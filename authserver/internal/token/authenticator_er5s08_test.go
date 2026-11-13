package token

// ER5 er5-s08 occurrence tests: the authserver bearer acceptance path must
// enforce session revocation (CA-3a denylist positive match → ErrRevoked) and
// DPoP proof-of-possession for cnf-bound access tokens (fail-closed via the
// in-process replay cache + shared/threat.VerifyDPoPForToken).

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/sha256"
	cryptoTLS "crypto/tls"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/threat"
)

func newER5S08TestProvider() *JWTProvider {
	return NewJWTProvider("test-secret-key-at-least-32-chars-long!!", nil, "", time.Hour, 30*24*time.Hour, "test")
}

// mintDPoPProof builds a signed RFC 9449 proof JWT for the given key, binding
// htm/htu/jti (and ath over accessToken when non-empty).
func mintDPoPProof(t *testing.T, key *ecdsa.PrivateKey, htm, htu, jti string, iat time.Time, accessToken string) (string, string) {
	t.Helper()
	jwk := map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(key.PublicKey.X.Bytes()),
		"y": base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.Bytes()),
	}
	jkt, err := threat.JKTFromJWK(jwk)
	if err != nil {
		t.Fatal(err)
	}
	claims := jwt.MapClaims{"htm": htm, "htu": htu, "jti": jti, "iat": iat.Unix()}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	proof := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	proof.Header["typ"] = "dpop+jwt"
	proof.Header["jwk"] = jwk
	signed, err := proof.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return signed, jkt
}

func authRequest(token string) *http.Request {
	return tlsRequest(token, "https://auth.example/auth/me", nil)
}

// tlsRequest builds a request over a TLS connection (r.TLS set), matching a
// direct HTTPS deployment; httptest.NewRequest alone leaves TLS nil.
func tlsRequest(token, target string, body io.Reader) *http.Request {
	r := httptest.NewRequest(http.MethodPost, target, body)
	r.TLS = &cryptoTLS.ConnectionState{HandshakeComplete: true}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

// TestBearerAuthenticator_RevokedSessionRejected proves the acceptance path
// consults the shared CA-3a denylist: a positive IsRevoked match — jti, family,
// and all-scope watermarks, the exact authority the revoke_user_sessions
// reducer propagates — rejects with ErrRevoked; an unrevoked principal
// authenticates.
func TestBearerAuthenticator_RevokedSessionRejected(t *testing.T) {
	jwtP := newER5S08TestProvider()
	denylist := threat.NewSessionDenylist(nil, nil)
	a := NewBearerAuthenticator(jwtP).WithRevocations(denylist)

	clean, err := jwtP.IssueAccessFull(1, "clean@example.com", false, nil, nil, nil, nil, AuthContext{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Authenticate(context.Background(), authRequest(clean)); err != nil {
		t.Fatalf("unrevoked token rejected: %v", err)
	}

	// jti-scoped: read the token's minted jti back, then revoke exactly that
	// session the way revoke_user_sessions(scope='jti') does.
	revoked, err := jwtP.IssueAccessFull(2, "victim@example.com", false, nil, nil, nil, nil, AuthContext{})
	if err != nil {
		t.Fatal(err)
	}
	revokedClaims, err := jwtP.Validate(revoked)
	if err != nil {
		t.Fatal(err)
	}
	denylist.Apply(threat.RevocationRow{
		UserID: 2, Scope: threat.ScopeJTI, JTI: revokedClaims.JTI,
		NotBefore: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(31 * 24 * time.Hour),
	})
	if _, err := a.Authenticate(context.Background(), authRequest(revoked)); err != ErrRevoked {
		t.Fatalf("revoked token: err = %v, want ErrRevoked", err)
	}

	// Family-scoped revocation kills a token minted before the row's NotBefore.
	familyToken, err := jwtP.IssueAccessCAFamilySession(3, "fam@example.com", false, nil, nil, nil, nil, AuthContext{}, nil, nil, nil, "family-3", "")
	if err != nil {
		t.Fatal(err)
	}
	denylist.Apply(threat.RevocationRow{
		UserID: 3, Scope: threat.ScopeFamily, FamilyID: "family-3",
		NotBefore: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(31 * 24 * time.Hour),
	})
	if _, err := a.Authenticate(context.Background(), authRequest(familyToken)); err != ErrRevoked {
		t.Fatalf("family-revoked token: err = %v, want ErrRevoked", err)
	}

	// All-scope watermark: everything for user 4 issued before the flip dies.
	tok4, err := jwtP.IssueAccessFull(4, "all@example.com", false, nil, nil, nil, nil, AuthContext{})
	if err != nil {
		t.Fatal(err)
	}
	denylist.Apply(threat.RevocationRow{
		UserID: 4, Scope: threat.ScopeAll,
		NotBefore: time.Now().Add(time.Minute), // after iat → this token is covered
		ExpiresAt: time.Now().Add(31 * 24 * time.Hour),
	})
	if _, err := a.Authenticate(context.Background(), authRequest(tok4)); err != ErrRevoked {
		t.Fatalf("all-scope revoked token: err = %v, want ErrRevoked", err)
	}
}

// TestBearerAuthenticator_NilRevocations_NoCheck pins the unwired posture: with
// no denylist attached the authenticator makes no revocation claim (matching the
// gateway's positive-match-off posture while feature.cae_runtime is OFF), and a
// revocation that was never wired cannot fail closed on every request.
func TestBearerAuthenticator_NilRevocations_NoCheck(t *testing.T) {
	jwtP := newER5S08TestProvider()
	a := NewBearerAuthenticator(jwtP) // no WithRevocations
	tok, err := jwtP.IssueAccessFull(9, "u9@example.com", false, nil, nil, nil, nil, AuthContext{})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := a.Authenticate(context.Background(), authRequest(tok))
	if err != nil {
		t.Fatalf("unwired denylist must not affect authentication: %v", err)
	}
	if claims.UserID != 9 {
		t.Fatalf("claims.UserID = %d, want 9", claims.UserID)
	}
}

// TestBearerAuthenticator_BoundTokenRequiresDPoPProof proves the DPoP seam:
// a cnf-bound access token without a proof is refused fail-closed (no wiring,
// no toggle at the acceptance path — a bound token only exists when an operator
// enabled feature.token_binding), a valid proof bound to THIS request and token
// authenticates, and the proof is single-use (replay → ErrTokenBinding).
func TestBearerAuthenticator_BoundTokenRequiresDPoPProof(t *testing.T) {
	jwtP := newER5S08TestProvider()
	a := NewBearerAuthenticator(jwtP)

	key, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	bound, err := jwtP.IssueAccessCA(1, "bound@example.com", false, nil, nil, nil, nil, AuthContext{}, &jwtutil.ConfirmationClaim{JKT: "PLACEHOLDER"}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	// Mint the proof first to learn the real jkt, then re-mint the token bound
	// to it (the cnf carries the key's thumbprint).
	proof, jkt := mintDPoPProof(t, key, "POST", "https://auth.example/auth/me", "proof-1", time.Now(), "TOKEN")
	bound, err = jwtP.IssueAccessCA(1, "bound@example.com", false, nil, nil, nil, nil, AuthContext{}, &jwtutil.ConfirmationClaim{JKT: jkt}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	proof, _ = mintDPoPProof(t, key, "POST", "https://auth.example/auth/me", "proof-1", time.Now(), bound)

	// 1. Bound token, NO proof → fail-closed ErrTokenBinding.
	if _, err := a.Authenticate(context.Background(), authRequest(bound)); err != ErrTokenBinding {
		t.Fatalf("bound token without proof: err = %v, want ErrTokenBinding", err)
	}

	// 2. Bound token with a VALID proof → authenticates.
	r := tlsRequest(bound, "https://auth.example/auth/me", nil)
	r.Header.Set("DPoP", proof)
	claims, err := a.Authenticate(context.Background(), r)
	if err != nil {
		t.Fatalf("bound token with valid proof rejected: %v", err)
	}
	if claims.UserID != 1 {
		t.Fatalf("claims.UserID = %d, want 1", claims.UserID)
	}

	// 3. Proof replay (same jti) → refused.
	r = tlsRequest(bound, "https://auth.example/auth/me", nil)
	r.Header.Set("DPoP", proof)
	if _, err := a.Authenticate(context.Background(), r); err != ErrTokenBinding {
		t.Fatalf("replayed proof: err = %v, want ErrTokenBinding", err)
	}

	// 4. Proof signed by a DIFFERENT key (jkt mismatch) → refused.
	wrongKeyProof, _ := mintDPoPProof(t, otherKey, "POST", "https://auth.example/auth/me", "proof-2", time.Now(), bound)
	r = tlsRequest(bound, "https://auth.example/auth/me", nil)
	r.Header.Set("DPoP", wrongKeyProof)
	if _, err := a.Authenticate(context.Background(), r); err != ErrTokenBinding {
		t.Fatalf("wrong-key proof: err = %v, want ErrTokenBinding", err)
	}

	// 5. Proof minted for a different htu (the off-device relay attack) → refused.
	wrongURIProof, _ := mintDPoPProof(t, key, "POST", "https://evil.example/relay", "proof-3", time.Now(), bound)
	r = tlsRequest(bound, "https://auth.example/auth/me", nil)
	r.Header.Set("DPoP", wrongURIProof)
	if _, err := a.Authenticate(context.Background(), r); err != ErrTokenBinding {
		t.Fatalf("wrong-htu proof: err = %v, want ErrTokenBinding", err)
	}

	// 6. Unbound tokens are unaffected (no cnf → no proof demanded).
	unbound, err := jwtP.IssueAccessFull(4, "plain@example.com", false, nil, nil, nil, nil, AuthContext{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Authenticate(context.Background(), authRequest(unbound)); err != nil {
		t.Fatalf("unbound token must not require a proof: %v", err)
	}
}

// TestBearerAuthenticator_ProxyHTUReconstruction pins the htu derivation behind
// the gateway's auth proxy: X-Forwarded-Host + X-Forwarded-Proto restore the
// client-facing URI the proof was minted against, while a garbage/multi-valued
// forwarded host cannot smuggle a host past the check (falls back to r.Host).
func TestBearerAuthenticator_ProxyHTUReconstruction(t *testing.T) {
	jwtP := newER5S08TestProvider()
	a := NewBearerAuthenticator(jwtP)

	key, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	mintBound := func() string {
		_, jkt := mintDPoPProof(t, key, "POST", "https://mail.example.com/auth/me", "seed", time.Now(), "SEED")
		tok, err := jwtP.IssueAccessCA(5, "proxied@example.com", false, nil, nil, nil, nil, AuthContext{}, &jwtutil.ConfirmationClaim{JKT: jkt}, nil, "")
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}

	// Proxied request: internal Host, client-facing forwarded headers.
	tok := mintBound()
	proof, _ := mintDPoPProof(t, key, "POST", "https://mail.example.com/auth/me", "proxy-1", time.Now(), tok)
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8443/auth/me", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	r.Header.Set("DPoP", proof)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "mail.example.com")
	if _, err := a.Authenticate(context.Background(), r); err != nil {
		t.Fatalf("proxied request with client-facing proof rejected: %v", err)
	}

	// Direct request: r.Host + connection TLS fallback still verifies.
	tok = mintBound()
	proof, _ = mintDPoPProof(t, key, "POST", "https://auth.example/auth/me", "direct-1", time.Now(), tok)
	r = tlsRequest(tok, "https://auth.example/auth/me", nil)
	r.Header.Set("DPoP", proof)
	if _, err := a.Authenticate(context.Background(), r); err != nil {
		t.Fatalf("direct request with direct proof rejected: %v", err)
	}

	// A multi-valued/garbage X-Forwarded-Host cannot smuggle a host: the
	// verifier falls back to r.Host, so a proof signed for the smuggled host
	// does not verify.
	tok = mintBound()
	proof, _ = mintDPoPProof(t, key, "POST", "https://evil.example/auth/me", "smuggle-1", time.Now(), tok)
	r = httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8443/auth/me", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	r.Header.Set("DPoP", proof)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "evil.example http://attacker")
	if _, err := a.Authenticate(context.Background(), r); err != ErrTokenBinding {
		t.Fatalf("smuggled forwarded host: err = %v, want ErrTokenBinding", err)
	}
}

// TestIssueRefreshWithFamilySession_UniquePerMint pins the refresh-token
// uniqueness fix: every claim in a refresh token is second-resolution and
// deterministic per family state, so two mints in the same second under HS256
// were byte-identical (the "new" bearer secret preserved the old one). Each
// mint must now carry a fresh random jti, making the credential strings — and
// therefore the oauth_tokens token_hash anchors — distinct.
func TestIssueRefreshWithFamilySession_UniquePerMint(t *testing.T) {
	p := newER5S08TestProvider()
	const family = "11111111-2222-4333-8444-555555555555"

	first, err := p.IssueRefreshWithFamilySession(7, "u7@example.com", family, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := p.IssueRefreshWithFamilySession(7, "u7@example.com", family, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("two same-second refresh mints produced byte-identical tokens — rotation preserved the old bearer secret")
	}

	// Both still validate as refresh tokens of the same family (the jti is
	// additive; nothing downstream keys on refresh jti equality).
	c1, err := p.Validate(first)
	if err != nil {
		t.Fatalf("first token invalid: %v", err)
	}
	c2, err := p.Validate(second)
	if err != nil {
		t.Fatalf("second token invalid: %v", err)
	}
	if c1.FamilyID != family || c2.FamilyID != family {
		t.Fatalf("family inheritance broken: %q / %q", c1.FamilyID, c2.FamilyID)
	}
	if c1.JTI == "" || c1.JTI == c2.JTI {
		t.Fatalf("refresh jtis empty or colliding: %q vs %q", c1.JTI, c2.JTI)
	}
}

// TestBearerAuthenticator_ForwardedHeaderHTUUnits pins the htu derivation and
// forwarded-header sanitization contract edge-by-edge: only a single valid
// host[:port] or bracketed IPv6 literal may set the htu host, and only a single
// http/https token may set the scheme.
func TestBearerAuthenticator_ForwardedHeaderHTUUnits(t *testing.T) {
	r := func(headers map[string]string, target string, tlsConn bool) *http.Request {
		req := httptest.NewRequest(http.MethodPost, target, nil)
		if tlsConn {
			req.TLS = &cryptoTLS.ConnectionState{HandshakeComplete: true}
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		return req
	}
	cases := []struct {
		name    string
		req     *http.Request
		wantHTU string
	}{
		{"direct TLS", r(nil, "https://auth.example/auth/me", true), "https://auth.example/auth/me"},
		{"plain http direct", r(nil, "http://auth.example/auth/me", false), "http://auth.example/auth/me"},
		{"proxied https", r(map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-Host": "mail.example.com"}, "http://int:8443/auth/me", false), "https://mail.example.com/auth/me"},
		{"proxied explicit http scheme", r(map[string]string{"X-Forwarded-Proto": "http", "X-Forwarded-Host": "mail.example.com"}, "http://int:8443/auth/me", true), "http://mail.example.com/auth/me"},
		{"garbage forwarded proto falls back to TLS", r(map[string]string{"X-Forwarded-Proto": "ftp, https"}, "https://auth.example/auth/me", true), "https://auth.example/auth/me"},
		{"forwarded host with port", r(map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-Host": "mail.example.com:8443"}, "http://int:8443/auth/me", false), "https://mail.example.com:8443/auth/me"},
		{"bracketed ipv6 host", r(map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-Host": "[2001:db8::1]:8443"}, "http://int/auth/me", false), "https://[2001:db8::1]:8443/auth/me"},
		{"bracketed ipv6 without port", r(map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-Host": "[2001:db8::1]"}, "http://int/auth/me", false), "https://[2001:db8::1]/auth/me"},
		{"list-syntax host rejected", r(map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-Host": "a.example, b.example"}, "http://int/auth/me", false), "https://int/auth/me"},
		{"userinfo host rejected", r(map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-Host": "evil@example.com"}, "http://int/auth/me", false), "https://int/auth/me"},
		{"bad port rejected", r(map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-Host": "mail.example.com:word"}, "http://int/auth/me", false), "https://int/auth/me"},
		{"unbracketed colon host rejected", r(map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-Host": "a:b:c"}, "http://int/auth/me", false), "https://int/auth/me"},
		{"empty host keeps r.Host", r(map[string]string{"X-Forwarded-Proto": "https"}, "https://auth.example/auth/me", true), "https://auth.example/auth/me"},
		{"empty path falls back to root", r(nil, "https://auth.example", true), "https://auth.example/"},
	}
	for _, tc := range cases {
		if got := dpopClientFacingURI(tc.req); got != tc.wantHTU {
			t.Errorf("%s: htu = %q, want %q", tc.name, got, tc.wantHTU)
		}
	}

	// Direct sanitizer units for the shapes the URI cases above don't isolate.
	for bad := range map[string]bool{
		"": true, "a.example/path": true,
		"a..example": true, "a\\example": true, "a@example.com": true, "a?query": true,
		"[::1": true, "[bad]": true, "[::1]:notaport": true, "a:b:c": true,
		"mail.example.com:notaport": true, "[::1]:99999x": true,
		":8080": true,
	} {
		if got := sanitizedForwardedHost(bad); got != "" {
			t.Errorf("sanitizedForwardedHost(%q) = %q, want \"\"", bad, got)
		}
	}
	for good := range map[string]bool{
		"mail.example.com": true, "mail.example.com:8443": true,
		"[2001:db8::1]": true, "[2001:db8::1]:8443": true, "192.168.1.10": true,
	} {
		if got := sanitizedForwardedHost(good); got == "" {
			t.Errorf("sanitizedForwardedHost(%q) = \"\", want accepted", good)
		}
	}
}

// TestBearerAuthenticator_LoggerAttachedDenials exercises the structured denial
// logging legs (revocation + binding) with a logger attached.
func TestBearerAuthenticator_LoggerAttachedDenials(t *testing.T) {
	jwtP := newER5S08TestProvider()
	denylist := threat.NewSessionDenylist(nil, nil)
	a := NewBearerAuthenticator(jwtP).
		WithRevocations(denylist).
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if a.logger == nil {
		t.Fatal("WithLogger must attach the logger")
	}

	revoked, err := jwtP.IssueAccessFull(2, "victim@example.com", false, nil, nil, nil, nil, AuthContext{})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := jwtP.Validate(revoked)
	if err != nil {
		t.Fatal(err)
	}
	denylist.Apply(threat.RevocationRow{
		UserID: 2, Scope: threat.ScopeJTI, JTI: claims.JTI,
		NotBefore: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour),
	})
	if _, err := a.Authenticate(context.Background(), authRequest(revoked)); err != ErrRevoked {
		t.Fatalf("revoked token: %v, want ErrRevoked", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := jwtP.IssueAccessCA(1, "b@example.com", false, nil, nil, nil, nil, AuthContext{}, &jwtutil.ConfirmationClaim{JKT: "somejkt"}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	// Bound token without proof → binding denial through the logged path.
	if _, err := a.Authenticate(context.Background(), authRequest(bound)); err != ErrTokenBinding {
		t.Fatalf("bound token without proof: %v, want ErrTokenBinding", err)
	}
	_ = key
}
