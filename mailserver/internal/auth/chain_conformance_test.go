package auth

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	sharedauth "setjoin.com/shared/auth"
)

// AUTH-V-002: the mailserver auth chain must satisfy the SAME conformance
// contract the shared/auth unit tests assert (shared/auth/conformance.go,
// hardened by AUTH-V-001 with the wrong-type / expired / tampered legs) — not
// only the authserver's implementation. These tests drive the PRODUCTION chain
// through Chain.Authenticate, the exact entry point shared middleware
// RequireAuth calls in main.go, so a future chain change that breaks the
// contract fails here regardless of what the shared fakes still accept.

// Compile-time proof the production chain implements the shared contract.
var _ sharedauth.Authenticator = (*Chain)(nil)

func bearerRequest(token string) func() *http.Request {
	return func() *http.Request {
		r, _ := http.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		return r
	}
}

// tamperedHS256 re-encodes the token payload with the email claim swapped for
// an attacker identity while keeping the ORIGINAL signature segment — the
// signature then no longer covers the claims, which is exactly the tamper leg
// of the conformance contract (a credential whose signature does not cover its
// claims must not authenticate).
func tamperedHS256(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("tamperedHS256: token %q is not a compact JWS", token)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("tamperedHS256: decode payload: %v", err)
	}
	tampered := bytes.Replace(payload,
		[]byte(`"email":"alice@example.com"`),
		[]byte(`"email":"attacker@evil.example"`), 1)
	if bytes.Equal(tampered, payload) {
		t.Fatal("tamperedHS256: email claim not found in payload; tamper leg would be vacuous")
	}
	parts[1] = base64.RawURLEncoding.EncodeToString(tampered)
	return strings.Join(parts, ".")
}

// TestChainAuthenticatorConformance runs the shared conformance harness against
// the production chain. NewChainWithJWT is the documented production-mirroring
// seam: it wires exactly the jwt_bearer method ReloadMethods always ensures is
// present, reached through the same Chain.Authenticate the shared middleware
// depends on. The fixtures cover every AUTH-V-001 leg: identity binding
// (WantEmail), plain rejection, refresh-presented-as-access, expired, and
// signature-tampered credentials.
func TestChainAuthenticatorConformance(t *testing.T) {
	valid := mintHS256(t, testSecret, testClaims(42, "alice@example.com", false, TypeAccess, time.Hour))
	sharedauth.AuthenticatorConformance(t,
		func() sharedauth.Authenticator {
			return NewChainWithJWT(NewJWTProvider(testSecret, nil, testIssuer))
		},
		sharedauth.ConformanceFixtures{
			ValidRequest:   bearerRequest(valid),
			WantEmail:      "alice@example.com",
			InvalidRequest: func() *http.Request { r, _ := http.NewRequest(http.MethodGet, "/", nil); return r },
			// Wrong token TYPE: a refresh token presented on the access surface.
			WrongTypeRequest: bearerRequest(mintHS256(t, testSecret,
				testClaims(42, "alice@example.com", false, TypeRefresh, time.Hour))),
			// Past its lifetime.
			ExpiredRequest: bearerRequest(mintHS256(t, testSecret,
				testClaims(42, "alice@example.com", false, TypeAccess, -time.Hour))),
			// Signature does not cover the presented claims.
			TamperedRequest: bearerRequest(tamperedHS256(t, valid)),
		})
}
