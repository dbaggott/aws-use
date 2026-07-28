package console

import (
	"net/url"
	"strings"
	"testing"
)

func TestURL(t *testing.T) {
	// Every documented access portal form is extended the same way, so the
	// builder must not special-case the classic `<alias>.awsapps.com/start` one.
	cases := []struct {
		name     string
		startURL string
		want     string
	}{
		{
			name:     "classic portal",
			startURL: "https://example.awsapps.com/start",
			want:     "https://example.awsapps.com/start/#/console?account_id=123456789012&role_name=S3FullAccess",
		},
		{
			name:     "trailing slash trimmed",
			startURL: "https://example.awsapps.com/start/",
			want:     "https://example.awsapps.com/start/#/console?account_id=123456789012&role_name=S3FullAccess",
		},
		{
			name:     "dual-stack portal",
			startURL: "https://ssoins-1234567890abcdef.portal.us-east-1.app.aws",
			want:     "https://ssoins-1234567890abcdef.portal.us-east-1.app.aws/#/console?account_id=123456789012&role_name=S3FullAccess",
		},
		{
			name:     "govcloud portal",
			startURL: "https://start.us-gov-west-1.us-gov-home.awsapps.com/directory/example",
			want:     "https://start.us-gov-west-1.us-gov-home.awsapps.com/directory/example/#/console?account_id=123456789012&role_name=S3FullAccess",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := URL(c.startURL, "123456789012", "S3FullAccess", "")
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Errorf("URL() =\n %q\nwant\n %q", got, c.want)
			}
		})
	}
}

func TestURLEncodesDestination(t *testing.T) {
	dest := "https://console.aws.amazon.com/s3/home?region=us-west-2"
	got, err := URL("https://example.awsapps.com/start", "123456789012", "Admin+Access", dest)
	if err != nil {
		t.Fatal(err)
	}
	// AWS requires every parameter value URL-encoded — an unescaped destination
	// would terminate the parameter at its own "?"/"&".
	if strings.Contains(got, dest) {
		t.Errorf("destination left unencoded in %q", got)
	}
	frag := got[strings.Index(got, "?")+1:]
	q, err := url.ParseQuery(frag)
	if err != nil {
		t.Fatal(err)
	}
	if q.Get("destination") != dest {
		t.Errorf("destination round-trip = %q, want %q", q.Get("destination"), dest)
	}
	if q.Get("role_name") != "Admin+Access" {
		t.Errorf("role_name round-trip = %q", q.Get("role_name"))
	}
}

func TestURLRejectsUnusableInputs(t *testing.T) {
	cases := []struct {
		name                                       string
		startURL, accountID, roleName, destination string
	}{
		{"no start url", "", "123456789012", "Admin", ""},
		{"not https", "http://example.awsapps.com/start", "123456789012", "Admin", ""},
		{"not a portal root", "https://example.awsapps.com/start?foo=1", "123456789012", "Admin", ""},
		{"already a deep link", "https://example.awsapps.com/start/#/console", "123456789012", "Admin", ""},
		{"no account", "https://example.awsapps.com/start", "", "Admin", ""},
		{"no role", "https://example.awsapps.com/start", "123456789012", "", ""},
		{"relative destination", "https://example.awsapps.com/start", "123456789012", "Admin", "/s3/home"},
		{"non-https destination", "https://example.awsapps.com/start", "123456789012", "Admin", "http://console.aws.amazon.com/"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got, err := URL(c.startURL, c.accountID, c.roleName, c.destination); err == nil {
				t.Errorf("want an error, got %q", got)
			}
		})
	}
}

func TestRegionHome(t *testing.T) {
	want := "https://us-west-2.console.aws.amazon.com/console/home?region=us-west-2"
	got, err := RegionHome("us-west-2")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("RegionHome() = %q, want %q", got, want)
	}
	for _, r := range []string{"us-gov-west-1", "cn-north-1", "ap-southeast-3"} {
		if _, err := RegionHome(r); err != nil {
			t.Errorf("RegionHome(%q): %v", r, err)
		}
	}
}

// The region lands in the destination URL's host, where percent-escapes aren't
// valid syntax — so a bad region has to be rejected on shape, not escaped. Left
// to escaping, "evil.com/x?a=b#" produced an unreadable `invalid URL escape`
// error from url.Parse three layers down instead of a message naming the region.
func TestRegionHomeRejectsNonRegions(t *testing.T) {
	for _, r := range []string{"", "evil.com/x?a=b#", "US-EAST-1", "us east 1", "us_east_1", "us-east-1/"} {
		if got, err := RegionHome(r); err == nil {
			t.Errorf("RegionHome(%q) = %q, want an error", r, got)
		}
	}
}
