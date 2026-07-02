// Package sso handles AWS IAM Identity Center: reusing/writing the CLI-compatible
// token cache, logging in (authorization-code + PKCE, with a device-code
// fallback), refreshing tokens, and discovering the accounts and roles a session
// can assume.
package sso

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
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
func loadToken(sessionName string) (cachedToken, bool) {
	b, err := os.ReadFile(cachePath(sessionName))
	if err != nil {
		return cachedToken{}, false
	}
	var t cachedToken
	if err := json.Unmarshal(b, &t); err != nil {
		return cachedToken{}, false
	}
	return t, true
}

func ValidToken(sessionName string) (string, bool) {
	t, ok := loadToken(sessionName)
	if !ok || t.AccessToken == "" {
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
	t, ok := loadToken(sessionName)
	if !ok || t.ExpiresAt == "" {
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
// AcquireToken returns a usable access token for a session: a still-valid cached
// token, else a silent refresh with the cached refresh token, else an
// interactive login.
func AcquireToken(ctx context.Context, sessionName, startURL, region string) (string, error) {
	if tok, ok := ValidToken(sessionName); ok {
		return tok, nil
	}
	if tok, err := Refresh(ctx, sessionName, region); err == nil && tok != "" {
		return tok, nil
	}
	return Login(ctx, sessionName, startURL, region)
}

// Login signs in interactively. It uses the authorization-code + PKCE flow (a
// local browser + 127.0.0.1 callback) by default; set AWS_USE_DEVICE_AUTH to use
// the device-authorization flow instead, which suits headless/remote shells.
func Login(ctx context.Context, sessionName, startURL, region string) (string, error) {
	if os.Getenv("AWS_USE_DEVICE_AUTH") != "" {
		return loginDeviceCode(ctx, sessionName, startURL, region)
	}
	return loginPKCE(ctx, sessionName, startURL, region)
}

func loginDeviceCode(ctx context.Context, sessionName, startURL, region string) (string, error) {
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

// loginPKCE runs the OAuth 2.0 authorization-code flow with PKCE: register a
// client with a loopback redirect, open the browser to the SSO /authorize page,
// receive the code on a local 127.0.0.1 callback, and exchange it (with the PKCE
// verifier) for an access + refresh token. Mirrors `aws sso login`, and the
// refresh token is what enables silent renewal.
func loginPKCE(ctx context.Context, sessionName, startURL, region string) (string, error) {
	// Bind the loopback callback first so we know the redirect URI to register.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("opening callback listener: %w", err)
	}
	defer func() { _ = ln.Close() }()
	redirect := fmt.Sprintf("http://127.0.0.1:%d/oauth/callback", ln.Addr().(*net.TCPAddr).Port)

	cfg := aws.Config{Region: region, Credentials: aws.AnonymousCredentials{}}
	oidc := ssooidc.NewFromConfig(cfg)

	reg, err := oidc.RegisterClient(ctx, &ssooidc.RegisterClientInput{
		ClientName:   aws.String("aws-use"),
		ClientType:   aws.String("public"),
		Scopes:       []string{scope},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		RedirectUris: []string{redirect},
		// Required for the authorization-code flow (unlike device-code): the SSO
		// instance's issuer URL, which is the session's start URL.
		IssuerUrl: aws.String(startURL),
	})
	if err != nil {
		return "", fmt.Errorf("registering oidc client: %w", err)
	}

	verifier, err := randURLToken(32)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	state, err := randURLToken(16)
	if err != nil {
		return "", err
	}

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", aws.ToString(reg.ClientId))
	q.Set("redirect_uri", redirect)
	q.Set("state", state)
	q.Set("scopes", scope)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	authURL := fmt.Sprintf("https://oidc.%s.amazonaws.com/authorize?%s", region, q.Encode())

	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/callback", func(w http.ResponseWriter, r *http.Request) {
		qs := r.URL.Query()
		switch {
		case qs.Get("error") != "":
			http.Error(w, "aws-use: sign-in failed: "+qs.Get("error"), http.StatusBadRequest)
			errCh <- fmt.Errorf("authorization failed: %s", qs.Get("error"))
		case qs.Get("state") != state:
			http.Error(w, "aws-use: state mismatch", http.StatusBadRequest)
			errCh <- errors.New("state mismatch in callback")
		case qs.Get("code") == "":
			http.Error(w, "aws-use: no authorization code", http.StatusBadRequest)
			errCh <- errors.New("no authorization code in callback")
		default:
			_, _ = fmt.Fprintln(w, "aws-use: sign-in complete — you can close this window.")
			codeCh <- qs.Get("code")
		}
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Shutdown(context.Background()) }()

	fmt.Fprintf(os.Stderr, "Opening %s\n", authURL)
	fmt.Fprintln(os.Stderr, "Complete the sign-in in your browser…")
	_ = openBrowser(authURL)

	var code string
	select {
	case code = <-codeCh:
	case err = <-errCh:
		return "", err
	case <-ctx.Done():
		return "", ctx.Err()
	case <-time.After(5 * time.Minute):
		return "", errors.New("timed out waiting for browser sign-in")
	}

	tok, err := oidc.CreateToken(ctx, &ssooidc.CreateTokenInput{
		ClientId:     reg.ClientId,
		ClientSecret: reg.ClientSecret,
		GrantType:    aws.String("authorization_code"),
		Code:         aws.String(code),
		RedirectUri:  aws.String(redirect),
		CodeVerifier: aws.String(verifier),
	})
	if err != nil {
		return "", fmt.Errorf("exchanging code for token: %w", err)
	}

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

// Refresh mints a new access token from the cached refresh token (no browser)
// and updates the cache. Errors if there's no usable refresh token.
func Refresh(ctx context.Context, sessionName, region string) (string, error) {
	ct, ok := loadToken(sessionName)
	if !ok || ct.RefreshToken == "" || ct.ClientID == "" || ct.ClientSecret == "" {
		return "", errors.New("no refresh token")
	}
	cfg := aws.Config{Region: region, Credentials: aws.AnonymousCredentials{}}
	oidc := ssooidc.NewFromConfig(cfg)
	tok, err := oidc.CreateToken(ctx, &ssooidc.CreateTokenInput{
		ClientId:     aws.String(ct.ClientID),
		ClientSecret: aws.String(ct.ClientSecret),
		GrantType:    aws.String("refresh_token"),
		RefreshToken: aws.String(ct.RefreshToken),
	})
	if err != nil {
		return "", err
	}
	ct.AccessToken = aws.ToString(tok.AccessToken)
	ct.ExpiresAt = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second).UTC().Format(time.RFC3339)
	if rt := aws.ToString(tok.RefreshToken); rt != "" {
		ct.RefreshToken = rt
	}
	if err := writeToken(sessionName, ct); err != nil {
		return "", fmt.Errorf("writing token cache: %w", err)
	}
	return ct.AccessToken, nil
}

// randURLToken returns n random bytes as an unpadded base64url string — the PKCE
// verifier and the CSRF state.
func randURLToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
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
