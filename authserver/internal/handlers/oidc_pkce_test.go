package handlers

// OIDC RP PKCE (FEDERATION-003, RFC 7636) handler-path tests.
//
// Two layers are covered here:
//
//  1. The first-party flow-state gates in OIDCLogin/OIDCCallback -- the
//     verifier cookie must exist and be a syntactically valid RFC 7636
//     code_verifier before any provider resolution or token exchange (the
//     missing/malformed-cookie tests below; same pattern as
//     oidc_saml_negative_test.go).
//  2. The persistence/consumption round trip (Astra FEDERATION-003 r2): a
//     real OIDCLogin call must bind state + nonce + code_verifier flow
//     cookies to the authorization redirect, the callback must carry that
//     verifier to the token endpoint (S256 §4.6-checked by the stub IdP
//     against the challenge advertised in the redirect), the verifier must be
//     deleted on use, and a replayed callback must not mint anything.
//     state/nonce mismatch rejection at the handler boundary is asserted on
//     the same harness.
//
// The round-trip layer needs a *signing* stub IdP (discovery + JWKS + token
// on one httptest server). Unlike the sibling scope notes, signing is
// unavoidable here -- not to re-verify zitadel's signature checking, but
// because the handler's nonce gate only runs after a fully verified exchange,
// and production providers are OIDC-mode (oauth2Only=false), whose
// CodeExchange populates IDTokenClaims only through that verified path. The
// production SSRF guard intentionally refuses loopback IdPs at dial time, so
// the registry is seeded via federation.NewOIDCRPProviderForTest with a
// test-built relying party; the S256 challenge-binding primitives themselves
// remain pinned by internal/federation's oidc_rp_pkce_test.go.

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client/rp"

	"setjoin.com/authserver/internal/federation"
	"setjoin.com/authserver/internal/federation/pkce"
)

// validTestVerifier is a syntactically valid RFC 7636 §4.1 code_verifier (43
// unreserved characters) for tests that must pass the handler's PKCE
// flow-state gate to reach the check under test.
func validTestVerifier() string { return strings.Repeat("a", 43) }

func TestOIDCCallback_MissingVerifierCookie(t *testing.T) {
	h := &loginHandler{&deps{logger: discardLogger(), oidcRP: &federation.OIDCRPProvider{}}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?state=s1&code=c1", nil)
	r.AddCookie(&http.Cookie{Name: "oidc_state", Value: "s1"})
	// state matches, but no oidc_verifier cookie (FEDERATION-003 fail-closed)

	h.OIDCCallback(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing verifier cookie: got %d, want 400", w.Code)
	}
	if got := decodeProblem(t, w)["detail"]; got != "missing code verifier" {
		t.Errorf("detail = %v, want %q", got, "missing code verifier")
	}
}

func TestOIDCCallback_MalformedVerifierCookie(t *testing.T) {
	cases := []struct {
		name     string
		verifier string
	}{
		{"too short", "short-verifier"},
		{"too long", strings.Repeat("a", 129)},
		{"base64 charset violation", strings.Repeat("a", 42) + "+"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &loginHandler{&deps{logger: discardLogger(), oidcRP: &federation.OIDCRPProvider{}}}
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?state=s1&code=c1", nil)
			r.AddCookie(&http.Cookie{Name: "oidc_state", Value: "s1"})
			r.AddCookie(&http.Cookie{Name: "oidc_verifier", Value: tc.verifier})

			h.OIDCCallback(w, r)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("malformed verifier: got %d, want 400", w.Code)
			}
			if got := decodeProblem(t, w)["detail"]; got != "invalid code verifier" {
				t.Errorf("detail = %v, want %q", got, "invalid code verifier")
			}
		})
	}
}

// ── PKCE round trip: login persistence → callback consumption ─────────────

// oidcRPTestKey is one RSA key shared by every stub-IdP test (key generation
// dominates the stub's cost).
var oidcRPTestKey = sync.OnceValue(func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
})

const (
	oidcTestClientID = "setjoin-client"
	oidcTestKeyID    = "rp-pkce-test-key"
)

// tokenRequest is one captured POST /token presentation.
type tokenRequest struct {
	form   url.Values
	pkceOK bool // §4.6 verdict against the armed challenge; true when none armed
}

// fakeOIDCIdP is a minimal discovery + JWKS + token OIDC IdP on one httptest
// server. The token endpoint enforces authorization-code single-use and, once
// armed, the RFC 7636 §4.6 comparison the way a conforming IdP does; the
// minted id_token carries the flow's armed nonce.
type fakeOIDCIdP struct {
	t   *testing.T
	URL string

	srv          *httptest.Server
	mu           sync.Mutex
	challenge    string // armed expected code_challenge; "" disables §4.6 enforcement
	idTokenNonce string // nonce embedded in the minted id_token

	presentations []tokenRequest
	redeemed      map[string]int // presentations per code (single-use enforcement)
	granted       map[string]int // successful redemptions per code
}

func newFakeOIDCIdP(t *testing.T) *fakeOIDCIdP {
	t.Helper()
	idp := &fakeOIDCIdP{t: t, redeemed: map[string]int{}, granted: map[string]int{}}
	key := oidcRPTestKey()

	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(v); err != nil {
			t.Errorf("stub write: %v", err)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                idp.URL,
			"authorization_endpoint":                idp.URL + "/authorize",
			"token_endpoint":                        idp.URL + "/token",
			"jwks_uri":                              idp.URL + "/keys",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"code_challenge_methods_supported":      []string{"S256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": oidcTestKeyID,
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		idp.mu.Lock()
		defer idp.mu.Unlock()
		rec := tokenRequest{form: r.PostForm}
		rec.pkceOK = idp.challenge == "" || pkce.Verify(r.PostForm.Get("code_verifier"), idp.challenge) == nil
		idp.presentations = append(idp.presentations, rec)
		code := r.PostForm.Get("code")
		idp.redeemed[code]++
		// Conforming IdP order: an unknown or already-redeemed code and a
		// verifier that does not derive the authorize-time challenge are both
		// invalid_grant (RFC 6749 §4.1.2, RFC 7636 §4.6). Note oauth2's
		// AuthStyleAutoDetect re-presents the request with credentials in the
		// form body after a 400, so presentations can exceed requests.
		if idp.redeemed[code] > 1 || !rec.pkceOK {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"code or PKCE verification failed"}`))
			return
		}
		idp.granted[code]++
		writeJSON(w, map[string]any{
			"access_token": "at-1",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     idp.signIDToken(key, idp.idTokenNonce, time.Now()),
		})
	})

	idp.srv = httptest.NewServer(mux)
	idp.URL = idp.srv.URL
	t.Cleanup(idp.srv.Close)
	return idp
}

// arm pins the stub to one login flow: only a token request presenting a
// verifier that derives challenge passes §4.6, and only an id_token minted
// with nonce passes the handler's request-bound comparison.
func (idp *fakeOIDCIdP) arm(challenge, nonce string) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.challenge, idp.idTokenNonce = challenge, nonce
}

func (idp *fakeOIDCIdP) overrideNonce(nonce string) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.idTokenNonce = nonce
}

func (idp *fakeOIDCIdP) presentationsSnapshot() []tokenRequest {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	return append([]tokenRequest(nil), idp.presentations...)
}

func (idp *fakeOIDCIdP) redeemCount(code string) int {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	return idp.redeemed[code]
}

func (idp *fakeOIDCIdP) grantCount(code string) int {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	return idp.granted[code]
}

// signIDToken mints an RS256 id_token with the flow nonce for the stub's
// current settings (at_hash is deliberately omitted: zitadel skips the check
// when absent). Caller must hold idp.mu.
func (idp *fakeOIDCIdP) signIDToken(key *rsa.PrivateKey, nonce string, now time.Time) string {
	idp.t.Helper()
	claims := map[string]any{
		"iss":            idp.URL,
		"sub":            "subject-1",
		"aud":            oidcTestClientID,
		"exp":            now.Add(5 * time.Minute).Unix(),
		"iat":            now.Unix(),
		"nonce":          nonce,
		"email":          "ada@example.test",
		"email_verified": true,
	}
	b64 := base64.RawURLEncoding.EncodeToString
	head, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": oidcTestKeyID})
	if err != nil {
		idp.t.Errorf("marshal JWT header: %v", err)
		return ""
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		idp.t.Errorf("marshal JWT claims: %v", err)
		return ""
	}
	signingInput := b64(head) + "." + b64(payload)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		idp.t.Errorf("sign id_token: %v", err)
		return ""
	}
	return signingInput + "." + b64(sig)
}

// addressGateIdentityResolver stops the callback at the identity-resolution
// boundary without a database: resolveAddress answers 409 "explicit account
// linking is required", the first response after every PKCE/nonce/email gate
// has already passed. Production would continue into SP-mode resolution.
type addressGateIdentityResolver struct{}

func (addressGateIdentityResolver) ResolveExisting(context.Context, identityKeys) (*userRow, resolveSource, error) {
	return nil, resolveAddress, nil
}

const addressGateDetail = "explicit account linking is required"

// rpHarness wires the stub IdP, a test-seeded provider registry, and a deps
// bag hermetic to the identity-resolution boundary.
type rpHarness struct {
	t   *testing.T
	idp *fakeOIDCIdP
	h   *loginHandler
}

func newRPHarness(t *testing.T) *rpHarness {
	t.Helper()
	idp := newFakeOIDCIdP(t)
	party, err := rp.NewRelyingPartyOIDC(context.Background(),
		idp.URL, oidcTestClientID, "setjoin-secret",
		"https://auth.example.test/auth/oidc/callback",
		[]string{"openid", "email", "profile", "groups"},
		// Mirror production's verifier wiring (oidc_rp.go): the RP performs no
		// nonce validation of its own; the handler owns the request-bound
		// comparison against the oidc_nonce cookie.
		rp.WithVerifierOpts(rp.WithNonce(nil)))
	if err != nil {
		t.Fatalf("NewRelyingPartyOIDC: %v", err)
	}
	return &rpHarness{
		t:   t,
		idp: idp,
		h: &loginHandler{&deps{
			logger:           discardLogger(),
			oidcRP:           federation.NewOIDCRPProviderForTest("stub", party),
			identityResolver: addressGateIdentityResolver{},
		}},
	}
}

// login drives OIDCLogin for the stub provider and returns the flow cookies
// plus the authorization redirect's query.
func (x *rpHarness) login() ([]*http.Cookie, url.Values) {
	x.t.Helper()
	w := httptest.NewRecorder()
	x.h.OIDCLogin(w, httptest.NewRequest(http.MethodGet, "/auth/oidc/login?provider=stub", nil))
	if w.Code != http.StatusFound {
		x.t.Fatalf("OIDCLogin: got %d, want 302 (body=%s)", w.Code, w.Body.String())
	}
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		x.t.Fatalf("parse authorization redirect %q: %v", w.Header().Get("Location"), err)
	}
	return w.Result().Cookies(), u.Query()
}

// armFlow cross-checks that the redirect's challenge is the persisted
// verifier's S256 derivation and pins the stub IdP to this flow.
func (x *rpHarness) armFlow(cookies []*http.Cookie, q url.Values) {
	x.t.Helper()
	verifier := cookieValue(x.t, cookies, "oidc_verifier")
	if err := pkce.Verify(verifier, q.Get("code_challenge")); err != nil {
		x.t.Fatalf("redirect code_challenge not derived from the persisted verifier: %v", err)
	}
	x.idp.arm(q.Get("code_challenge"), cookieValue(x.t, cookies, "oidc_nonce"))
}

// callback replays the flow cookies into OIDCCallback with the given
// state/code.
func (x *rpHarness) callback(cookies []*http.Cookie, state, code string) *httptest.ResponseRecorder {
	x.t.Helper()
	r := httptest.NewRequest(http.MethodGet,
		"/auth/oidc/callback?state="+url.QueryEscape(state)+"&code="+url.QueryEscape(code), nil)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	x.h.OIDCCallback(w, r)
	return w
}

func cookieValue(t *testing.T, cookies []*http.Cookie, name string) string {
	t.Helper()
	return cookieByName(t, cookies, name).Value
}

func cookieByName(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no %q cookie in response", name)
	return nil
}

// wantProblem asserts the response status and problem detail exactly.
func wantProblem(t *testing.T, w *httptest.ResponseRecorder, status int, detail string) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("got %d, want %d (body=%s)", w.Code, status, w.Body.String())
	}
	if got := decodeProblem(t, w)["detail"]; got != detail {
		t.Errorf("detail = %v, want %q", got, detail)
	}
}

// assertCleared asserts every named flow cookie was deleted in the response
// (empty value, expired): the single-use posture of the flow-cookie set.
func assertCleared(t *testing.T, w *httptest.ResponseRecorder, names ...string) {
	t.Helper()
	got := w.Result().Cookies()
	for _, name := range names {
		var c *http.Cookie
		for _, g := range got {
			if g.Name == name {
				c = g
				break
			}
		}
		if c == nil {
			t.Errorf("response did not delete flow cookie %q (no Set-Cookie)", name)
			continue
		}
		if c.Value != "" || c.MaxAge >= 0 {
			t.Errorf("flow cookie %q not cleared: value=%q maxage=%d, want empty/expired", name, c.Value, c.MaxAge)
		}
	}
}

// assertNotCleared asserts none of the named flow cookies was deleted — the
// gate under test fired before the clear step.
func assertNotCleared(t *testing.T, w *httptest.ResponseRecorder, names ...string) {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		for _, name := range names {
			if c.Name == name && c.Value == "" && c.MaxAge < 0 {
				t.Errorf("flow cookie %q unexpectedly cleared", name)
			}
		}
	}
}

// (a) OIDCLogin persists the complete PKCE flow state and binds it to the
// redirect: oidc_verifier is a valid RFC 7636 verifier whose S256 derivation
// is exactly the code_challenge sent to the IdP, alongside the request-bound
// state/nonce pair.
func TestOIDCLoginPKCE_PersistsVerifierBoundToRedirect(t *testing.T) {
	x := newRPHarness(t)

	cookies, q := x.login()

	verifier := cookieValue(t, cookies, "oidc_verifier")
	if err := pkce.ValidateVerifier(verifier); err != nil {
		t.Fatalf("persisted oidc_verifier invalid: %v", err)
	}
	if err := pkce.Verify(verifier, q.Get("code_challenge")); err != nil {
		t.Fatalf("redirect code_challenge is not the S256 derivation of the persisted verifier: %v", err)
	}
	if q.Get("code_challenge_method") != pkce.MethodS256 {
		t.Fatalf("code_challenge_method = %q, want %q", q.Get("code_challenge_method"), pkce.MethodS256)
	}
	if state := cookieValue(t, cookies, "oidc_state"); state != q.Get("state") {
		t.Errorf("oidc_state cookie %q != redirect state %q", state, q.Get("state"))
	}
	if nonce := cookieValue(t, cookies, "oidc_nonce"); nonce != q.Get("nonce") {
		t.Errorf("oidc_nonce cookie %q != redirect nonce %q", nonce, q.Get("nonce"))
	}
	if provider := cookieValue(t, cookies, "oidc_provider"); provider != "stub" {
		t.Errorf("oidc_provider cookie = %q, want %q", provider, "stub")
	}
	// The flow cookies share the hardened shape (HttpOnly, SameSite=Strict,
	// 10-min TTL).
	for _, name := range []string{"oidc_state", "oidc_nonce", "oidc_provider", "oidc_verifier"} {
		c := cookieByName(t, cookies, name)
		if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.MaxAge != oidcFlowTTL {
			t.Errorf("flow cookie %q: httponly=%t samesite=%v maxage=%d, want true/Strict/%d",
				name, c.HttpOnly, c.SameSite, c.MaxAge, oidcFlowTTL)
		}
	}
}

// (b)+(c) The callback consumes the flow verifier at a real token exchange —
// the outgoing request body carries code_verifier, and the IdP's §4.6 check
// against the redirect-time challenge passes — and every flow cookie is
// deleted by the response (state+verifier before the exchange, nonce+provider
// on nonce success). The 409 sentinel proves the flow reached identity
// resolution, i.e. crossed every gate past PKCE.
func TestOIDCCallbackPKCE_RoundTripConsumesAndClearsVerifier(t *testing.T) {
	x := newRPHarness(t)

	cookies, q := x.login()
	x.armFlow(cookies, q)

	w := x.callback(cookies, q.Get("state"), "auth-code-1")
	wantProblem(t, w, http.StatusConflict, addressGateDetail)

	presented := x.idp.presentationsSnapshot()
	if len(presented) != 1 {
		t.Fatalf("token endpoint saw %d presentations, want 1", len(presented))
	}
	verifier := cookieValue(t, cookies, "oidc_verifier")
	form := presented[0].form
	if v := form.Get("code_verifier"); v != verifier {
		t.Errorf("token request code_verifier = %q (len %d), want the persisted flow verifier (len %d)",
			v, len(v), len(verifier))
	}
	if form.Get("code") != "auth-code-1" {
		t.Errorf("token request code = %q, want %q", form.Get("code"), "auth-code-1")
	}
	if form.Get("grant_type") != "authorization_code" {
		t.Errorf("token request grant_type = %q, want %q", form.Get("grant_type"), "authorization_code")
	}
	if form.Has("code_challenge") {
		t.Error("token request must carry the code_verifier, not the code_challenge")
	}
	if !presented[0].pkceOK {
		t.Error("presented verifier failed the stub IdP's §4.6 check against the redirect challenge")
	}

	assertCleared(t, w, "oidc_state", "oidc_verifier", "oidc_nonce", "oidc_provider")
}

// (d) Replaying the identical captured callback is rejected: the first use
// already deleted the verifier cookies, and the IdP refuses a second
// redemption of the single-use authorization code, so no second login
// completes.
func TestOIDCCallbackPKCE_ReplayedCallbackRejected(t *testing.T) {
	x := newRPHarness(t)

	cookies, q := x.login()
	x.armFlow(cookies, q)

	first := x.callback(cookies, q.Get("state"), "auth-code-1")
	wantProblem(t, first, http.StatusConflict, addressGateDetail)
	assertCleared(t, first, "oidc_state", "oidc_verifier")

	replay := x.callback(cookies, q.Get("state"), "auth-code-1")
	wantProblem(t, replay, http.StatusUnauthorized, "token exchange failed")

	presented := x.idp.presentationsSnapshot()
	if len(presented) != 2 {
		t.Fatalf("token endpoint saw %d presentations, want 2", len(presented))
	}
	if !presented[0].pkceOK || !presented[1].pkceOK {
		t.Error("replay must present the still-correct verifier; rejection is code single-use, not PKCE")
	}
	if n := x.idp.grantCount("auth-code-1"); n != 1 {
		t.Errorf("successful redemptions = %d, want 1 (first use only)", n)
	}
}

// (e) state mismatch is rejected at the very first handler gate: no network,
// no cookie mutation.
func TestOIDCCallbackPKCE_StateMismatchRejectedBeforeExchange(t *testing.T) {
	x := newRPHarness(t)

	cookies, q := x.login()
	x.armFlow(cookies, q)

	w := x.callback(cookies, "state-from-an-attacker", "auth-code-1")
	wantProblem(t, w, http.StatusBadRequest, "invalid state")

	if got := x.idp.presentationsSnapshot(); len(got) != 0 {
		t.Errorf("state mismatch reached the token endpoint (%d presentations)", len(got))
	}
	if cleared := w.Result().Cookies(); len(cleared) != 0 {
		t.Errorf("state rejection mutated cookies: %+v", cleared)
	}
}

// (e) nonce mismatch is rejected at the request-bound comparison after a
// cryptographically successful exchange: the verifier was consumed, but the
// flow dies at the handler boundary and cannot resume into a login.
func TestOIDCCallbackPKCE_NonceMismatchRejected(t *testing.T) {
	x := newRPHarness(t)

	cookies, q := x.login()
	x.armFlow(cookies, q)
	x.idp.overrideNonce("nonce-from-another-flow")

	w := x.callback(cookies, q.Get("state"), "auth-code-1")
	wantProblem(t, w, http.StatusBadRequest, "invalid nonce")

	presented := x.idp.presentationsSnapshot()
	if len(presented) != 1 || !presented[0].pkceOK {
		t.Fatalf("token endpoint presentations = %+v, want one §4.6-passing exchange", presented)
	}
	// nonce/provider are only cleared after the nonce check succeeds.
	assertNotCleared(t, w, "oidc_nonce", "oidc_provider")
}

// A structurally valid verifier from a DIFFERENT PKCE pair passes the
// handler's syntax gate but is rejected by the IdP's §4.6 derivation check —
// an intercepted verifier is not interchangeable across flows.
func TestOIDCCallbackPKCE_SwappedVerifierRejectedByIdP(t *testing.T) {
	x := newRPHarness(t)

	cookies, q := x.login()
	x.armFlow(cookies, q)

	other, err := pkce.NewVerifier()
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	swapped := make([]*http.Cookie, len(cookies))
	for i, c := range cookies {
		if c.Name == "oidc_verifier" {
			c = &http.Cookie{Name: c.Name, Value: other}
		}
		swapped[i] = c
	}

	w := x.callback(swapped, q.Get("state"), "auth-code-1")
	wantProblem(t, w, http.StatusUnauthorized, "token exchange failed")

	// oauth2's AuthStyleAutoDetect re-presents a 400 with credentials in the
	// form body, so the stub can legitimately see more than one presentation;
	// every one of them must fail §4.6 and the code must never be granted.
	presented := x.idp.presentationsSnapshot()
	if len(presented) == 0 {
		t.Fatal("token endpoint was never reached")
	}
	for i, p := range presented {
		if p.pkceOK {
			t.Errorf("presentation %d passed §4.6 with a verifier from a different PKCE pair", i)
		}
	}
	if n := x.idp.grantCount("auth-code-1"); n != 0 {
		t.Errorf("swapped verifier must never redeem the code, granted = %d", n)
	}
}
