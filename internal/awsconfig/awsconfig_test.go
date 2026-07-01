package awsconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sample = `[default]
region = us-west-2

[sso-session dnbg]
sso_start_url = https://d-9267c4ecb7.awsapps.com/start
sso_region = us-west-2
sso_registration_scopes = sso:account:access

[sso-session qhcorp]
sso_start_url = https://d-9267da40f8.awsapps.com/start
sso_region = us-west-2

[profile existing]
sso_session = dnbg
sso_account_id = 111111111111
sso_role_name = AdministratorAccess
region = us-west-2
`

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", path)
	return path
}

func TestSSOSessions(t *testing.T) {
	writeConfig(t, sample)
	got, err := SSOSessions()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 sessions, got %d: %+v", len(got), got)
	}
	// Sorted by name: dnbg before qhcorp.
	if got[0].Name != "dnbg" || got[0].StartURL != "https://d-9267c4ecb7.awsapps.com/start" || got[0].Region != "us-west-2" {
		t.Errorf("dnbg parsed wrong: %+v", got[0])
	}
	if got[1].Name != "qhcorp" {
		t.Errorf("want qhcorp second, got %q", got[1].Name)
	}
}

func TestEnsureProfileCreatesAndIsIdempotent(t *testing.T) {
	path := writeConfig(t, sample)

	p := Profile{Name: "dnbg-management-AdministratorAccess", SSOSession: "dnbg", AccountID: "626716204703", RoleName: "AdministratorAccess", Region: "us-west-2"}
	if err := EnsureProfile(p); err != nil {
		t.Fatal(err)
	}

	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(before), "[profile dnbg-management-AdministratorAccess]") {
		t.Fatalf("profile section not written:\n%s", before)
	}
	if !strings.Contains(string(before), "sso_account_id = 626716204703") {
		t.Errorf("account id not written:\n%s", before)
	}

	// Second call with identical values must not rewrite the file.
	infoBefore, _ := os.Stat(path)
	if err := EnsureProfile(p); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	infoAfter, _ := os.Stat(path)
	if string(before) != string(after) {
		t.Errorf("idempotent EnsureProfile changed the file")
	}
	if infoBefore.ModTime() != infoAfter.ModTime() {
		t.Errorf("idempotent EnsureProfile rewrote the file (mtime changed)")
	}
}
