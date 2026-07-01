package sso

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

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
