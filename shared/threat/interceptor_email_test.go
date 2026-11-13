package threat

import (
	"encoding/base64"
	"testing"
)

// b64url is the RawURL (no-padding) encoder used for JWT segments.
func b64url(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

// TestExtractEmailFromJWT pins the metadata-extraction invariants of
// extractEmailFromJWT, which feeds meta.Username and thereby gates per-user
// lockout (the `if meta.Username != ""` step). The security-relevant property:
// a malformed/garbage token must yield "" (so per-user lockout is SKIPPED, never
// crashing the pre-auth pipeline), and a well-formed token with an `email` claim
// must yield that email. This is the "empty-email-spray-skip on malformed token"
// invariant, pinned directly at the pure function (no pool needed).
//
// NOTE: this function intentionally does NOT verify the signature — it is rate-
// limit metadata only, not an auth decision. The test therefore feeds unsigned,
// crafted segments; that is by design (documented at the function).
func TestExtractEmailFromJWT(t *testing.T) {
	header := b64url(`{"alg":"ES256","typ":"JWT"}`)

	tests := []struct {
		name  string
		token string
		want  string
	}{
		{"empty string", "", ""},
		{"no dot / single segment", "notajwt", ""},
		{"only header (one segment before dot)", header, ""},
		{"garbage base64 in payload", header + ".!!!not-base64!!!.sig", ""},
		{"valid payload without email claim", header + "." + b64url(`{"sub":"42"}`) + ".sig", ""},
		{"valid payload with empty email claim", header + "." + b64url(`{"email":""}`) + ".sig", ""},
		{"valid payload with email claim", header + "." + b64url(`{"email":"alice@example.com"}`) + ".sig", "alice@example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractEmailFromJWT(tt.token)
			if got != tt.want {
				t.Fatalf("extractEmailFromJWT(%q) = %q, want %q", tt.token, got, tt.want)
			}
		})
	}
}
