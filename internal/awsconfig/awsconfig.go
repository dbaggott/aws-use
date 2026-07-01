// Package awsconfig reads SSO sessions from and writes profiles to the shared
// AWS config file (~/.aws/config), the same file the AWS CLI and SDKs use.
package awsconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/ini.v1"
)

// SSOSession is an [sso-session NAME] block from the AWS config file.
type SSOSession struct {
	Name     string
	StartURL string
	Region   string
}

// Profile is a [profile NAME] block backed by an SSO session.
type Profile struct {
	Name       string
	SSOSession string
	AccountID  string
	RoleName   string
	Region     string
}

// Path returns the AWS config file path, honoring AWS_CONFIG_FILE.
func Path() string {
	if p := os.Getenv("AWS_CONFIG_FILE"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".aws", "config")
	}
	return filepath.Join(home, ".aws", "config")
}

func load() (*ini.File, error) {
	path := Path()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return ini.Empty(), nil
	}
	f, err := ini.Load(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return f, nil
}

// SSOSessions returns every [sso-session NAME] block, sorted by name.
func SSOSessions() ([]SSOSession, error) {
	f, err := load()
	if err != nil {
		return nil, err
	}
	var out []SSOSession
	for _, sec := range f.Sections() {
		name, ok := strings.CutPrefix(sec.Name(), "sso-session ")
		if !ok {
			continue
		}
		out = append(out, SSOSession{
			Name:     strings.TrimSpace(name),
			StartURL: sec.Key("sso_start_url").String(),
			Region:   sec.Key("sso_region").String(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// EnsureProfile creates or updates the [profile p.Name] block so it points at
// the given SSO session/account/role. It is idempotent: an unchanged profile is
// left untouched (and the file is not rewritten).
func EnsureProfile(p Profile) error {
	path := Path()
	f, err := load()
	if err != nil {
		return err
	}

	secName := "profile " + p.Name
	sec, err := f.GetSection(secName)
	if err != nil {
		sec, err = f.NewSection(secName)
		if err != nil {
			return err
		}
	}

	want := map[string]string{
		"sso_session":    p.SSOSession,
		"sso_account_id": p.AccountID,
		"sso_role_name":  p.RoleName,
		"region":         p.Region,
	}
	changed := false
	for k, v := range want {
		if sec.Key(k).String() != v {
			sec.Key(k).SetValue(v)
			changed = true
		}
	}
	if !changed {
		return nil
	}

	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return f.SaveTo(path)
}
