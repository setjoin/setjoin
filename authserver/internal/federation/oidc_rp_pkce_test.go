package federation

// PKCE (FEDERATION-003, RFC 7636) binding tests for the OIDC RP flow.
//
// AuthCodeURL must carry an S256 code_challenge derived from the verifier it
// returns, and Exchange must present that verifier to the token endpoint and
// fail closed without a valid one. The token endpoint here is an httptest
// stub enforcing the RFC 7636 §4.6 comparison the way a conforming IdP does;
// rp.NewRelyingPartyOAuth (oauth2-only, no discovery/JWKS) provides the
// relyingParty so the SAML/OIDC negative-test scope note stands: no signing
// IdP is stood up to re-verify zitadel's token verification.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"golang.org/x/oauth2"

	"setjoin.com/authserver/internal/federation/pkce"
)

func newPKCETestRP(t *testing.T, tokenURL string) rp.RelyingParty {
	t.Helper()
	rp, err := rp.NewRelyingPartyOAuth(&oauth2.Config{
		ClientID:     "setjoin-client",
		ClientSecret: "setjoin-secret",
		RedirectURL:  "https://auth.example.test/auth/oidc/callback",
		Scopes:       []string{"openid", "email", "profile", "groups"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://idp.example.test/authorize",
			TokenURL: tokenURL,
		},
	})
	if err != nil {
		t.Fatalf("NewRelyingPartyOAuth: %v", err)
	}
	return rp
}

// TestAuthCodeURLBindsPKCEChallengeToReturnedVerifier proves the redirect URL
// and the returned verifier are one PKCE pair: the URL carries
// code_challenge_method=S256 and a code_challenge that is exactly the S256
// derivation of the verifier the caller must store for the callback.
func TestAuthCodeURLBindsPKCEChallengeToReturnedVerifier(t *testing.T) {
	cfg := &oidcProviderConfig{relyingParty: newPKCETestRP(t, "https://idp.example.test/token")}

	authURL, verifier, err := cfg.AuthCodeURL("flow-state", "flow-nonce")
	if err != nil {
		t.Fatalf("AuthCodeURL: %v", err)
	}
	if err := pkce.ValidateVerifier(verifier); err != nil {
		t.Fatalf("returned verifier invalid: %v", err)
	}

	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse auth URL: %v", err)
	}
	q := u.Query()
	if got := q.Get("code_challenge_method"); got != pkce.MethodS256 {
		t.Fatalf("code_challenge_method = %q, want %q", got, pkce.MethodS256)
	}
	challenge := q.Get("code_challenge")
	if challenge == "" {
		t.Fatal("authorization URL carries no code_challenge")
	}
	if err := pkce.Verify(verifier, challenge); err != nil {
		t.Fatalf("URL code_challenge not derived from returned verifier: %v", err)
	}
	// Pre-existing parameters are preserved alongside PKCE.
	if q.Get("state") != "flow-state" || q.Get("nonce") != "flow-nonce" {
		t.Fatalf("state/nonce missing from auth URL: state=%q nonce=%q", q.Get("state"), q.Get("nonce"))
	}
	// Two redirects must mint independent pairs (no verifier reuse).
	_, verifier2, err := cfg.AuthCodeURL("flow-state", "flow-nonce")
	if err != nil {
		t.Fatalf("second AuthCodeURL: %v", err)
	}
	if verifier2 == verifier {
		t.Fatal("two redirects returned the same code_verifier")
	}
}

// TestExchangePresentsCodeVerifier proves the token request carries the flow's
// code_verifier as the RFC 7636 §4.5 form parameter.
func TestExchangePresentsCodeVerifier(t *testing.T) {
	var gotVerifier string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotVerifier = r.PostFormValue("code_verifier")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer","expires_in":3600}`))
	}))
	defer ts.Close()

	cfg := &oidcProviderConfig{relyingParty: newPKCETestRP(t, ts.URL)}
	_, verifier, err := cfg.AuthCodeURL("flow-state", "flow-nonce")
	if err != nil {
		t.Fatalf("AuthCodeURL: %v", err)
	}

	tokens, err := cfg.Exchange(context.Background(), "the-code", verifier)
	if err != nil {
		t.Fatalf("Exchange with the flow verifier: %v", err)
	}
	if tokens == nil || tokens.Token == nil || tokens.Token.AccessToken != "at" {
		t.Fatalf("Exchange returned unexpected tokens: %+v", tokens)
	}
	if gotVerifier != verifier {
		t.Fatalf("token endpoint received code_verifier %q, want the stored flow verifier (len %d)", gotVerifier, len(verifier))
	}
}

// TestExchangeMismatchedVerifierRejectedByIdP proves the RFC 7636 §4.6
// contract end to end at our seam: a verifier from a *different* PKCE pair
// (structurally valid, so the handler's syntax gate passes it) is rejected by
// the IdP because it does not derive the challenge sent at authorize time.
func TestExchangeMismatchedVerifierRejectedByIdP(t *testing.T) {
	correctVerifier, err := pkce.NewVerifier()
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	expectedChallenge, err := pkce.ChallengeS256(correctVerifier)
	if err != nil {
		t.Fatalf("ChallengeS256: %v", err)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if pkce.Verify(r.PostFormValue("code_verifier"), expectedChallenge) != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"PKCE verification failed"}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer","expires_in":3600}`))
	}))
	defer ts.Close()

	cfg := &oidcProviderConfig{relyingParty: newPKCETestRP(t, ts.URL)}

	// Matching pair succeeds.
	if _, err := cfg.Exchange(context.Background(), "the-code", correctVerifier); err != nil {
		t.Fatalf("Exchange with matching verifier: %v", err)
	}

	// Mismatched (but well-formed) verifier is rejected by the IdP.
	otherVerifier, err := pkce.NewVerifier()
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, err := cfg.Exchange(context.Background(), "the-code", otherVerifier); err == nil {
		t.Fatal("Exchange with mismatched verifier must fail (IdP invalid_grant)")
	}
}

// TestExchangeFailsClosedOnMissingOrMalformedVerifier proves Exchange refuses
// to reach the network without a syntactically valid verifier (FEDERATION-003
// fail-closed contract at the federation layer).
func TestExchangeFailsClosedOnMissingOrMalformedVerifier(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("token endpoint reached without a valid code_verifier")
	}))
	defer ts.Close()

	cfg := &oidcProviderConfig{relyingParty: newPKCETestRP(t, ts.URL)}

	for _, v := range []string{"", "short-verifier", strings.Repeat("a", 129), strings.Repeat("a", 42) + "+"} {
		if _, err := cfg.Exchange(context.Background(), "the-code", v); err == nil {
			t.Fatalf("Exchange with verifier %q (len %d) must fail closed", v, len(v))
		}
	}
}
