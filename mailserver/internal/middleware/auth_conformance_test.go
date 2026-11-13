package middleware

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"setjoin.com/mailserver/internal/auth"
	sharedauth "setjoin.com/shared/auth"
	"setjoin.com/shared/jwtutil"
)

// AUTH-V-002: the conformance contract must hold at the MIDDLEWARE layer, not
// only against the chain Authenticator in isolation. main.go wires the outermost
// authn as RequireAuth(chain, logger): the middleware maps chain outcomes onto
// HTTP (401 + challenge on rejection, claims-on-context on success), and a bug
// in that mapping (e.g. swallowing an error, or passing a non-access token
// through) would break the same shared contract. These tests drive the full
// production composition — RequireAuth wrapping the REAL auth.Chain (the
// NewChainWithJWT production-mirroring seam) — through the shared
// AuthenticatorConformance harness, plus explicit HTTP status assertions for
// every rejection leg.

// The authserver mint constants the gateway verifies against. auth.kidHMAC,
// auth.audience, and the config default JWT_ISSUER are unexported/test-internal,
// so they are pinned here; if they drift, the valid leg fails loudly — which is
// exactly the conformance signal wanted from this file.
const (
	conformanceKID      = "authserver-hmac-1"  // auth.kidHMAC
	conformanceIssuer   = "mailserver"         // config default JWT_ISSUER
	conformanceAudience = "mailserver-gateway" // auth.audience
	conformanceSecret   = "middleware-conformance-secret-32b!"
)

func mintConformanceHS256(t *testing.T, claims *jwtutil.Claims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tok.Header["kid"] = conformanceKID
	s, err := tok.SignedString([]byte(conformanceSecret))
	if err != nil {
		t.Fatalf("mint conformance token: %v", err)
	}
	return s
}

// conformanceClaims mirrors the authserver's mint shape (correct iss/aud/iat/nbf/
// exp) for an access token the gateway must accept; a negative ttl yields an
// already-expired token.
func conformanceClaims(ttl time.Duration) *jwtutil.Claims {
	now := time.Now()
	return &jwtutil.Claims{
		UserID: 42,
		Email:  "alice@example.com",
		Type:   jwtutil.TypeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    conformanceIssuer,
			Audience:  jwt.ClaimStrings{conformanceAudience},
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
}

func conformanceBearer(token string) func() *http.Request {
	return func() *http.Request {
		r, _ := http.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		return r
	}
}

// tamperedConformanceToken keeps the ORIGINAL signature segment but re-encodes
// the payload with the email claim swapped for an attacker identity, so the
// signature no longer covers the presented claims.
func tamperedConformanceToken(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("tamperedConformanceToken: token %q is not a compact JWS", token)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("tamperedConformanceToken: decode payload: %v", err)
	}
	tampered := bytes.Replace(payload,
		[]byte(`"email":"alice@example.com"`),
		[]byte(`"email":"attacker@evil.example"`), 1)
	if bytes.Equal(tampered, payload) {
		t.Fatal("tamperedConformanceToken: email claim not found; tamper leg would be vacuous")
	}
	parts[1] = base64.RawURLEncoding.EncodeToString(tampered)
	return strings.Join(parts, ".")
}

// requireAuthAdapter maps the production middleware stack's HTTP outcome back
// onto the shared Authenticator contract: the request is served through
// RequireAuth(realChain) composed with a terminal handler, a 200 yields the
// claims the middleware attached to the handler context, and any other status
// is a contract rejection.
type requireAuthAdapter struct {
	chain *auth.Chain
}

var _ sharedauth.Authenticator = requireAuthAdapter{}

func (a requireAuthAdapter) Authenticate(ctx context.Context, r *http.Request) (*jwtutil.Claims, error) {
	var got *jwtutil.Claims
	terminal := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		got = auth.UserFromContext(req.Context())
		w.WriteHeader(http.StatusOK)
	})
	rec := httptest.NewRecorder()
	RequireAuth(a.chain, gateLogger())(terminal).ServeHTTP(rec, r.WithContext(ctx))
	if rec.Code != http.StatusOK {
		return nil, fmt.Errorf("RequireAuth: status %d", rec.Code)
	}
	return got, nil
}

// TestRequireAuthMiddlewareConformance runs the shared conformance harness
// against the full production middleware composition, covering every AUTH-V-001
// leg: identity binding, plain rejection, wrong-type, expired, and tampered.
func TestRequireAuthMiddlewareConformance(t *testing.T) {
	valid := mintConformanceHS256(t, conformanceClaims(time.Hour))
	sharedauth.AuthenticatorConformance(t,
		func() sharedauth.Authenticator {
			chain := auth.NewChainWithJWT(auth.NewJWTProvider(conformanceSecret, nil, conformanceIssuer))
			return requireAuthAdapter{chain: chain}
		},
		sharedauth.ConformanceFixtures{
			ValidRequest:   conformanceBearer(valid),
			WantEmail:      "alice@example.com",
			InvalidRequest: func() *http.Request { r, _ := http.NewRequest(http.MethodGet, "/", nil); return r },
			// Refresh token presented on the access surface.
			WrongTypeRequest: conformanceBearer(
				mintConformanceHS256(t, refreshConformanceClaims())),
			// Past its lifetime.
			ExpiredRequest: conformanceBearer(
				mintConformanceHS256(t, conformanceClaims(-time.Hour))),
			// Signature does not cover the presented claims.
			TamperedRequest: conformanceBearer(tamperedConformanceToken(t, valid)),
		})
}

// refreshConformanceClaims mints refresh-type claims (same mint shape, wrong
// token type) for the wrong-type leg.
func refreshConformanceClaims() *jwtutil.Claims {
	claims := conformanceClaims(time.Hour)
	claims.Type = jwtutil.TypeRefresh
	return claims
}

// TestRequireAuthMiddlewareStatusContract pins the HTTP mapping the harness
// observes through the adapter: exactly the valid leg reaches the terminal
// handler with the expected identity on the context; every rejection leg is a
// 401 carrying the WWW-Authenticate challenge — never a pass-through, 500, or
// other status.
func TestRequireAuthMiddlewareStatusContract(t *testing.T) {
	chain := auth.NewChainWithJWT(auth.NewJWTProvider(conformanceSecret, nil, conformanceIssuer))
	valid := mintConformanceHS256(t, conformanceClaims(time.Hour))

	var (
		observedEmail string
		handlerRan    bool
	)
	handler := RequireAuth(chain, gateLogger())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerRan = true
		if claims := auth.UserFromContext(r.Context()); claims != nil {
			observedEmail = claims.Email
		}
		w.WriteHeader(http.StatusOK)
	}))

	leg := func(name, token string) *httptest.ResponseRecorder {
		t.Helper()
		handlerRan = false
		observedEmail = ""
		req, _ := http.NewRequest(http.MethodGet, "/", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		t.Logf("%s: status=%d", name, rec.Code)
		return rec
	}

	// Valid leg: 200 + identity binding on the handler context.
	if rec := leg("valid", valid); rec.Code != http.StatusOK {
		t.Fatalf("valid access token: expected 200, got %d", rec.Code)
	}
	if !handlerRan || observedEmail != "alice@example.com" {
		t.Fatalf("valid access token: handler ran=%v, identity email=%q, want alice@example.com on context", handlerRan, observedEmail)
	}

	rejections := []struct {
		name  string
		token string
	}{
		{"no credentials", ""},
		{"garbage token", "not-a-jwt"},
		{"wrong-type (refresh as access)", mintConformanceHS256(t, refreshConformanceClaims())},
		{"expired", mintConformanceHS256(t, conformanceClaims(-time.Hour))},
		{"tampered", tamperedConformanceToken(t, valid)},
	}
	for _, tc := range rejections {
		rec := leg(tc.name, tc.token)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s: expected 401, got %d", tc.name, rec.Code)
		}
		if rec.Header().Get("WWW-Authenticate") == "" {
			t.Fatalf("%s: 401 must carry the WWW-Authenticate challenge", tc.name)
		}
		if handlerRan {
			t.Fatalf("%s: terminal handler must not run on a rejected credential", tc.name)
		}
	}
}
