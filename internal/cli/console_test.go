package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dbaggott/aws-use/internal/awsconfig"
)

// writeConfig points AWS_CONFIG_FILE at a temp file with the given body.
func writeConfig(t *testing.T, body string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", path)
}

const configWithProfiles = `
[sso-session dnbg]
sso_start_url = https://dnbg.awsapps.com/start
sso_region = us-east-1

[profile dnbg-ops-Admin]
sso_session = dnbg
sso_account_id = 224850139999
sso_role_name = AdministratorAccess
region = us-east-1

[profile orphaned]
sso_session = gone
sso_account_id = 111111111111
sso_role_name = AdministratorAccess

[profile static-keys]
region = us-east-1
`

func TestActiveTarget(t *testing.T) {
	writeConfig(t, configWithProfiles)
	sessions, err := awsconfig.SSOSessions()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("sso profile resolves without network", func(t *testing.T) {
		t.Setenv("AWS_PROFILE", "dnbg-ops-Admin")
		session, ar, why := activeTarget(sessions)
		if why != "" {
			t.Fatalf("unexpected fallback: %s", why)
		}
		if session.StartURL != "https://dnbg.awsapps.com/start" {
			t.Errorf("start url = %q", session.StartURL)
		}
		if ar.AccountID != "224850139999" || ar.RoleName != "AdministratorAccess" {
			t.Errorf("account/role = %q / %q", ar.AccountID, ar.RoleName)
		}
		// Naming the account needs a live sso:ListAccounts call, which is the
		// whole cost this path exists to avoid.
		if ar.AccountName != "" {
			t.Errorf("account name should be left blank, got %q", ar.AccountName)
		}
	})

	// Each of these is a cue to fall back to the picker, so the reason has to
	// name the profile — an unexplained picker looks like AWS_PROFILE was ignored.
	fallbacks := map[string]string{
		"unset":            "",
		"static-keys":      "static-keys",
		"orphaned session": "orphaned",
	}
	for name, profile := range fallbacks {
		t.Run("falls back: "+name, func(t *testing.T) {
			t.Setenv("AWS_PROFILE", profile)
			if _, _, why := activeTarget(sessions); why == "" {
				t.Fatal("want a fallback reason, got none")
			} else if profile != "" && !strings.Contains(why, profile) {
				t.Errorf("reason %q should name the profile %q", why, profile)
			}
		})
	}
}
