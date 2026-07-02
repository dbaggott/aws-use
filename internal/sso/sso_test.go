package sso

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// PKCE verifiers must be 43–128 chars from the unreserved URL-safe set; 32 random
// bytes base64url-encode (unpadded) to 43 chars.
func TestRandURLToken(t *testing.T) {
	a, err := randURLToken(32)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 43 {
		t.Errorf("len = %d, want 43", len(a))
	}
	if strings.ContainsAny(a, "+/=") {
		t.Errorf("not url-safe / padded: %q", a)
	}
	if b, _ := randURLToken(32); a == b {
		t.Error("expected distinct tokens")
	}
}

// The token cache filename is sha1(sessionName) — this is the linchpin that
// makes the AWS CLI, the SDKs, and Terraform reuse the token we write. These
// expected hashes are the real files the AWS CLI produced for these sessions.
func TestCachePathMatchesAWSCLIScheme(t *testing.T) {
	cases := map[string]string{
		"dnbg":   "238e639be54a31b6c1da8ebc0cb100780e30dd9b.json",
		"qhcorp": "0d04fde4ec22b7ba0849223a8328ce76ae8372d5.json",
	}
	for session, want := range cases {
		if got := filepath.Base(cachePath(session)); got != want {
			t.Errorf("cachePath(%q) basename = %q, want %q", session, got, want)
		}
	}
}

func TestTokenExpiry(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if _, present := TokenExpiry("dnbg"); present {
		t.Fatal("no token file yet")
	}
	exp := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)
	if err := writeToken("dnbg", cachedToken{AccessToken: "x", ExpiresAt: exp.Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
	got, present := TokenExpiry("dnbg")
	if !present || !got.Equal(exp) {
		t.Errorf("TokenExpiry = %v, %v; want %v, true", got, present, exp)
	}
}

func TestValidTokenAndWriteRoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	if _, ok := ValidToken("dnbg"); ok {
		t.Fatal("expected no token before anything is written")
	}

	// A fresh token round-trips.
	if err := writeToken("dnbg", cachedToken{
		StartURL:    "https://example.awsapps.com/start",
		Region:      "us-west-2",
		AccessToken: "abc123",
		ExpiresAt:   time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}
	if tok, ok := ValidToken("dnbg"); !ok || tok != "abc123" {
		t.Fatalf("ValidToken = %q, %v; want abc123, true", tok, ok)
	}

	// An expired token is rejected.
	if err := writeToken("dnbg", cachedToken{
		AccessToken: "stale",
		ExpiresAt:   time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok := ValidToken("dnbg"); ok {
		t.Error("expired token should be invalid")
	}

	// A token expiring within the 1-minute buffer is treated as invalid.
	if err := writeToken("dnbg", cachedToken{
		AccessToken: "expiring",
		ExpiresAt:   time.Now().Add(30 * time.Second).UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok := ValidToken("dnbg"); ok {
		t.Error("token inside the expiry buffer should be invalid")
	}

	// Malformed JSON is rejected, not panicked on.
	if err := os.WriteFile(cachePath("dnbg"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := ValidToken("dnbg"); ok {
		t.Error("malformed token file should be invalid")
	}
}
