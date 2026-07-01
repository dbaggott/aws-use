package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dbaggott/aws-use/internal/awsconfig"
	"github.com/dbaggott/aws-use/internal/sso"
)

func TestHumanDuration(t *testing.T) {
	cases := map[time.Duration]string{
		3*time.Hour + 42*time.Minute: "3h42m",
		42 * time.Minute:             "42m",
		2 * time.Minute:              "2m",
		time.Hour:                    "1h0m",
		10 * time.Second:             "<1m",
	}
	for d, want := range cases {
		if got := humanDuration(d); got != want {
			t.Errorf("humanDuration(%s) = %q, want %q", d, got, want)
		}
	}
}

func TestCompleteFilter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	body := "[sso-session dnbg]\nsso_start_url = https://d.example/start\n\n[sso-session qhcorp]\nsso_start_url = https://q.example/start\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", path)

	all, _ := completeFilter(nil, nil, "")
	if len(all) != 2 {
		t.Fatalf("want 2 completions, got %v", all)
	}
	pref, _ := completeFilter(nil, nil, "dn")
	if len(pref) != 1 || pref[0] != "dnbg" {
		t.Errorf("prefix 'dn': got %v", pref)
	}
	// Once a word names a session, the switch targets it — no more session
	// completions (you can't filter across two sessions).
	after, _ := completeFilter(nil, []string{"dnbg"}, "")
	if len(after) != 0 {
		t.Errorf("session already chosen should yield no completions, got %v", after)
	}
}

func TestSlug(t *testing.T) {
	cases := map[string]string{
		"AdministratorAccess": "AdministratorAccess",
		"dnbg-management":     "dnbg-management",
		"a b/c":               "a-b-c",
		"  trim--me  ":        "trim--me",
		"weird@#name":         "weird-name",
	}
	for in, want := range cases {
		if got := slug(in); got != want {
			t.Errorf("slug(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestProfileName(t *testing.T) {
	s := awsconfig.SSOSession{Name: "dnbg"}
	ar := sso.AccountRole{AccountName: "dnbg-management", RoleName: "AdministratorAccess"}

	if got := profileName(s, ar); got != "dnbg-management-AdministratorAccess" {
		t.Errorf("default template: got %q", got)
	}

	t.Setenv("AWS_USE_PROFILE_TEMPLATE", "{session}-{account}-{role}")
	if got := profileName(s, ar); got != "dnbg-dnbg-management-AdministratorAccess" {
		t.Errorf("custom template: got %q", got)
	}
}

func TestResolveSession(t *testing.T) {
	two := []awsconfig.SSOSession{{Name: "dnbg"}, {Name: "qhcorp"}}

	// A query term matching a session name selects it and is consumed.
	s, terms, err := resolveSession(two, []string{"qhcorp", "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if s.Name != "qhcorp" {
		t.Errorf("want session qhcorp, got %q", s.Name)
	}
	if len(terms) != 1 || terms[0] != "admin" {
		t.Errorf("want remaining terms [admin], got %v", terms)
	}

	// A single session is used regardless, with the query passed through intact.
	one := []awsconfig.SSOSession{{Name: "only"}}
	s2, terms2, err := resolveSession(one, []string{"foo", "bar"})
	if err != nil {
		t.Fatal(err)
	}
	if s2.Name != "only" || len(terms2) != 2 {
		t.Errorf("single session: got %q terms=%v", s2.Name, terms2)
	}
}

func TestFilter(t *testing.T) {
	roles := []sso.AccountRole{
		{AccountName: "dnbg-management", AccountID: "1", RoleName: "AdministratorAccess"},
		{AccountName: "dnbg-management", AccountID: "1", RoleName: "ReadOnlyAccess"},
		{AccountName: "dnbg-operations", AccountID: "2", RoleName: "AdministratorAccess"},
	}
	if got := filter(roles, []string{"oper"}); len(got) != 1 || got[0].AccountName != "dnbg-operations" {
		t.Errorf("filter oper: %+v", got)
	}
	if got := filter(roles, []string{"management", "readonly"}); len(got) != 1 || got[0].RoleName != "ReadOnlyAccess" {
		t.Errorf("filter management readonly: %+v", got)
	}
	if got := filter(roles, nil); len(got) != 3 {
		t.Errorf("empty filter should return all, got %d", len(got))
	}
}
