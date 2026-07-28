// Package console builds AWS access portal shortcut links — the URLs that sign
// you in to the AWS Management Console as a specific account/permission set.
//
// A shortcut link is just the session's `sso_start_url` with `/#/console?…`
// appended, so building one needs nothing but ~/.aws/config: no credentials, no
// API call, no valid SSO token. The portal resolves the account/role against the
// browser's own session (prompting for sign-in if there isn't one).
//
// Deliberately not the alternative: fetching credentials with
// sso:GetRoleCredentials and trading them for a signin token at
// signin.aws.amazon.com/federation. That works too, but it materializes real
// credentials and puts a signin token in a URL — a poor trade for a tool whose
// whole design is to select an account/role without ever assuming it.
package console

import (
	"fmt"
	"net/url"
	"strings"
)

// URL returns the access portal shortcut link that opens the console for the
// given account and permission set.
//
// startURL is the session's sso_start_url. destination is optional: an absolute
// console URL to land on. When it is empty the portal picks the destination
// itself — the permission set's admin-configured relay state if there is one,
// else the console home the browser last used.
func URL(startURL, accountID, roleName, destination string) (string, error) {
	portal, err := portalBase(startURL)
	if err != nil {
		return "", err
	}
	if accountID == "" || roleName == "" {
		return "", fmt.Errorf("need both an account id and a role name (got %q / %q)", accountID, roleName)
	}

	q := url.Values{
		"account_id": {accountID},
		"role_name":  {roleName},
	}
	if destination != "" {
		if err := validateDestination(destination); err != nil {
			return "", err
		}
		q.Set("destination", destination)
	}
	// The parameters live in the fragment, not the query string: the portal is a
	// single-page app that parses `#/console?…` client-side. Encode() still gives
	// the right escaping (AWS requires every value URL-encoded) and orders keys
	// deterministically, which keeps the URL stable enough to test and bookmark.
	return portal + "/#/console?" + q.Encode(), nil
}

// RegionHome is the console home page for a region — the destination used when
// the caller asks for a region but no specific page.
func RegionHome(region string) string {
	return fmt.Sprintf("https://%s.console.aws.amazon.com/console/home?region=%s",
		url.PathEscape(region), url.QueryEscape(region))
}

// portalBase validates that startURL is an access portal URL a shortcut link can
// extend, and returns it without a trailing slash.
//
// The check is deliberately shape-based rather than a host allowlist: the portal
// has several documented forms — `https://<alias>.awsapps.com/start`, the
// dual-stack `https://<instance>.portal.<region>.app.aws`, and the GovCloud
// `.../directory/<alias>` — and all of them are extended the same way. Anything
// carrying its own query or fragment isn't a portal root, and appending
// `/#/console?…` to it would silently produce a URL that goes nowhere useful.
func portalBase(startURL string) (string, error) {
	s := strings.TrimSpace(startURL)
	if s == "" {
		return "", fmt.Errorf("no sso_start_url configured")
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("sso_start_url %q is not a URL: %w", startURL, err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return "", fmt.Errorf("sso_start_url %q is not an https URL", startURL)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("sso_start_url %q has a query or fragment, so it is not an access portal URL", startURL)
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func validateDestination(destination string) error {
	u, err := url.Parse(destination)
	if err != nil {
		return fmt.Errorf("destination %q is not a URL: %w", destination, err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("destination %q must be an absolute https console URL", destination)
	}
	return nil
}
