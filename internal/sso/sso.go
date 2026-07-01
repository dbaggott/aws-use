// Package sso handles AWS IAM Identity Center: reusing/writing the CLI-compatible
// token cache, performing a device-authorization login, and discovering the
// accounts and roles a session can assume.
package sso

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	oidctypes "github.com/aws/aws-sdk-go-v2/service/ssooidc/types"
)

const scope = "sso:account:access"

// AccountRole is one assumable (account, role) pair surfaced by discovery.
type AccountRole struct {
	Session     string
	AccountID   string
	AccountName string
	RoleName    string
}

// cachedToken mirrors the JSON the AWS CLI writes to ~/.aws/sso/cache. Writing
// the same shape (keyed by sha1(sessionName)) means the CLI, the SDKs, and
// Terraform all reuse the token this tool obtains, and vice versa.
type cachedToken struct {
	StartURL              string `json:"startUrl"`
	Region                string `json:"region"`
	AccessToken           string `json:"accessToken"`
	ExpiresAt             string `json:"expiresAt"`
	ClientID              string `json:"clientId,omitempty"`
	ClientSecret          string `json:"clientSecret,omitempty"`
	RegistrationExpiresAt string `json:"registrationExpiresAt,omitempty"`
	RefreshToken          string `json:"refreshToken,omitempty"`
}

func cacheDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".aws", "sso", "cache")
	}
	return filepath.Join(home, ".aws", "sso", "cache")
}

// cachePath is ~/.aws/sso/cache/<sha1hex(sessionName)>.json — the exact path the
// AWS CLI uses for sso-session based config.
func cachePath(sessionName string) string {
	sum := sha1.Sum([]byte(sessionName))
	return filepath.Join(cacheDir(), hex.EncodeToString(sum[:])+".json")
}

// ValidToken returns a non-expired cached access token for the session, if one
// exists (left by this tool, the AWS CLI, or anything else).
func ValidToken(sessionName string) (string, bool) {
	b, err := os.ReadFile(cachePath(sessionName))
	if err != nil {
		return "", false
	}
	var t cachedToken
	if err := json.Unmarshal(b, &t); err != nil || t.AccessToken == "" {
		return "", false
	}
	exp, err := time.Parse(time.RFC3339, t.ExpiresAt)
	if err != nil {
		return "", false
	}
	// Small buffer so we don't hand back a token about to expire mid-operation.
	if time.Now().Add(1 * time.Minute).After(exp) {
		return "", false
	}
	return t.AccessToken, true
}

// TokenExpiry returns the cached token's expiry for a session and whether a
// parseable token cache file exists (regardless of whether it's still valid).
func TokenExpiry(sessionName string) (time.Time, bool) {
	b, err := os.ReadFile(cachePath(sessionName))
	if err != nil {
		return time.Time{}, false
	}
	var t cachedToken
	if err := json.Unmarshal(b, &t); err != nil || t.ExpiresAt == "" {
		return time.Time{}, false
	}
	exp, err := time.Parse(time.RFC3339, t.ExpiresAt)
	if err != nil {
		return time.Time{}, false
	}
	return exp, true
}

func writeToken(sessionName string, t cachedToken) error {
	dir := cacheDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(cachePath(sessionName), b, 0o600)
}

// Login runs the device-authorization flow against the session's start URL,
// opens the browser for the user to approve, and writes the token cache. It
// returns the fresh access token.
func Login(ctx context.Context, sessionName, startURL, region string) (string, error) {
	cfg := aws.Config{Region: region, Credentials: aws.AnonymousCredentials{}}
	oidc := ssooidc.NewFromConfig(cfg)

	reg, err := oidc.RegisterClient(ctx, &ssooidc.RegisterClientInput{
		ClientName: aws.String("aws-use"),
		ClientType: aws.String("public"),
		Scopes:     []string{scope},
		GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"},
	})
	if err != nil {
		return "", fmt.Errorf("registering oidc client: %w", err)
	}

	auth, err := oidc.StartDeviceAuthorization(ctx, &ssooidc.StartDeviceAuthorizationInput{
		ClientId:     reg.ClientId,
		ClientSecret: reg.ClientSecret,
		StartUrl:     aws.String(startURL),
	})
	if err != nil {
		return "", fmt.Errorf("starting device authorization: %w", err)
	}

	url := aws.ToString(auth.VerificationUriComplete)
	fmt.Fprintf(os.Stderr, "Opening %s\n", url)
	fmt.Fprintf(os.Stderr, "If the browser does not open, visit it manually. Verification code: %s\n",
		aws.ToString(auth.UserCode))
	_ = openBrowser(url)

	interval := time.Duration(auth.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	deadline := time.Now().Add(time.Duration(auth.ExpiresIn) * time.Second)

	for {
		if time.Now().After(deadline) {
			return "", errors.New("device authorization expired before approval")
		}
		tok, err := oidc.CreateToken(ctx, &ssooidc.CreateTokenInput{
			ClientId:     reg.ClientId,
			ClientSecret: reg.ClientSecret,
			GrantType:    aws.String("urn:ietf:params:oauth:grant-type:device_code"),
			DeviceCode:   auth.DeviceCode,
		})
		if err == nil {
			ct := cachedToken{
				StartURL:     startURL,
				Region:       region,
				AccessToken:  aws.ToString(tok.AccessToken),
				ExpiresAt:    time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second).UTC().Format(time.RFC3339),
				ClientID:     aws.ToString(reg.ClientId),
				ClientSecret: aws.ToString(reg.ClientSecret),
				RefreshToken: aws.ToString(tok.RefreshToken),
			}
			if reg.ClientSecretExpiresAt != 0 {
				ct.RegistrationExpiresAt = time.Unix(reg.ClientSecretExpiresAt, 0).UTC().Format(time.RFC3339)
			}
			if err := writeToken(sessionName, ct); err != nil {
				return "", fmt.Errorf("writing token cache: %w", err)
			}
			return ct.AccessToken, nil
		}

		var pending *oidctypes.AuthorizationPendingException
		var slow *oidctypes.SlowDownException
		switch {
		case errors.As(err, &pending):
			time.Sleep(interval)
		case errors.As(err, &slow):
			interval += 5 * time.Second
			time.Sleep(interval)
		default:
			return "", fmt.Errorf("creating token: %w", err)
		}
	}
}

// AccountName resolves an account's display name via sso:ListAccounts. It's much
// cheaper than Discover (no per-account role listing) — used to label the active
// account in `current`.
func AccountName(ctx context.Context, region, accessToken, accountID string) (string, error) {
	cfg := aws.Config{Region: region, Credentials: aws.AnonymousCredentials{}}
	client := sso.NewFromConfig(cfg)
	p := sso.NewListAccountsPaginator(client, &sso.ListAccountsInput{AccessToken: aws.String(accessToken)})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return "", err
		}
		for _, a := range page.AccountList {
			if aws.ToString(a.AccountId) == accountID {
				return aws.ToString(a.AccountName), nil
			}
		}
	}
	return "", nil
}

// Discover lists every (account, role) the access token can assume in a session.
func Discover(ctx context.Context, sessionName, region, accessToken string) ([]AccountRole, error) {
	cfg := aws.Config{Region: region, Credentials: aws.AnonymousCredentials{}}
	client := sso.NewFromConfig(cfg)

	var out []AccountRole
	accts := sso.NewListAccountsPaginator(client, &sso.ListAccountsInput{AccessToken: aws.String(accessToken)})
	for accts.HasMorePages() {
		page, err := accts.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing accounts: %w", err)
		}
		for _, a := range page.AccountList {
			roles := sso.NewListAccountRolesPaginator(client, &sso.ListAccountRolesInput{
				AccessToken: aws.String(accessToken),
				AccountId:   a.AccountId,
			})
			for roles.HasMorePages() {
				rp, err := roles.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("listing roles for %s: %w", aws.ToString(a.AccountId), err)
				}
				for _, r := range rp.RoleList {
					out = append(out, AccountRole{
						Session:     sessionName,
						AccountID:   aws.ToString(a.AccountId),
						AccountName: aws.ToString(a.AccountName),
						RoleName:    aws.ToString(r.RoleName),
					})
				}
			}
		}
	}
	return out, nil
}

func openBrowser(url string) error {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
	case "windows":
		cmd, args = "rundll32", []string{"url.dll,FileProtocolHandler"}
	default:
		cmd = "xdg-open"
	}
	return exec.Command(cmd, append(args, url)...).Start()
}
