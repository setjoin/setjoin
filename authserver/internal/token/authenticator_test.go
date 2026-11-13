package token_test

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"setjoin.com/authserver/internal/token"
	sharedauth "setjoin.com/shared/auth"
	"setjoin.com/shared/cryptokey"
)

func newProvider(t *testing.T) *token.JWTProvider {
	t.Helper()
	return token.NewJWTProvider(
		"test-secret-32-bytes-long-ok-now!!",
		nil,
		cryptokey.ProfileStandard,
		time.Hour,
		720*time.Hour,
		"test-issuer",
	)
}

func mintAccessToken(t *testing.T, p *token.JWTProvider, email string) string {
	t.Helper()
	tok, err := p.IssueAccess(1, email, false)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	return tok
}

func mintRefreshToken(t *testing.T, p *token.JWTProvider, email string) string {
	t.Helper()
	tok, err := p.IssueRefresh(1, email)
	if err != nil {
		t.Fatalf("IssueRefresh: %v", err)
	}
	return tok
}

func TestBearerAuthenticator_Conformance(t *testing.T) {
	p := newProvider(t)
	access := mintAccessToken(t, p, "alice@x")
	sharedauth.AuthenticatorConformance(t,
		func() sharedauth.Authenticator { return token.NewBearerAuthenticator(p) },
		sharedauth.ConformanceFixtures{
			ValidRequest: func() *http.Request {
				r, _ := http.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("Authorization", "Bearer "+access)
				return r
			},
			WantEmail:      "alice@x",
			InvalidRequest: func() *http.Request { r, _ := http.NewRequest(http.MethodGet, "/", nil); return r },
		})
}

func TestBearerAuthenticator_RejectsNonAccessToken(t *testing.T) {
	p := newProvider(t)
	refresh := mintRefreshToken(t, p, "alice@x")
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+refresh)
	_, err := token.NewBearerAuthenticator(p).Authenticate(r.Context(), r)
	if err == nil {
		t.Fatal("invariant: non-access token type must be rejected (parity with old middleware claims.Type check)")
	}
	if !errors.Is(err, token.ErrWrongTokenType) {
		t.Fatalf("invariant: non-access token must yield ErrWrongTokenType (403 parity); got %v", err)
	}
}

func TestBearerAuthenticator_RejectsMissingBearer(t *testing.T) {
	p := newProvider(t)
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	_, err := token.NewBearerAuthenticator(p).Authenticate(r.Context(), r)
	if !errors.Is(err, token.ErrNoBearer) {
		t.Fatalf("missing Bearer AND missing cookie must yield ErrNoBearer (401 parity); got %v", err)
	}
}

// The webmail SPA is cookie-based (credentials:'include', no Authorization
// header), so the authenticator must accept the HttpOnly access_token cookie as
// a fallback when no Bearer header is present — mirroring the gateway's Chain
// (mailserver/internal/auth/chain.go). Mutating routes are CSRF-protected, so
// this adds no CSRF surface.
func TestBearerAuthenticator_CookieFallback(t *testing.T) {
	p := newProvider(t)
	access := mintAccessToken(t, p, "alice@x")
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "access_token", Value: access})
	claims, err := token.NewBearerAuthenticator(p).Authenticate(r.Context(), r)
	if err != nil {
		t.Fatalf("access_token cookie must authenticate when no Bearer header is present; got %v", err)
	}
	if claims == nil {
		t.Fatal("cookie fallback returned nil claims")
	}
}

func TestBearerAuthenticator_BearerBeatsCookie(t *testing.T) {
	p := newProvider(t)
	access := mintAccessToken(t, p, "alice@x")
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+access)
	r.AddCookie(&http.Cookie{Name: "access_token", Value: "not-a-jwt"})
	if _, err := token.NewBearerAuthenticator(p).Authenticate(r.Context(), r); err != nil {
		t.Fatalf("Bearer header must take precedence over the access_token cookie; got %v", err)
	}
}

// A non-access token in the cookie must still be rejected (parity with Bearer).
func TestBearerAuthenticator_CookieRejectsNonAccessToken(t *testing.T) {
	p := newProvider(t)
	refresh := mintRefreshToken(t, p, "alice@x")
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "access_token", Value: refresh})
	_, err := token.NewBearerAuthenticator(p).Authenticate(r.Context(), r)
	if !errors.Is(err, token.ErrWrongTokenType) {
		t.Fatalf("a refresh token in the cookie must yield ErrWrongTokenType; got %v", err)
	}
}
