package handlers

// OIDC RP + SAML SP negative-path regression tests.
//
// Scope note (read the code first, don't invent validations): the id_token
// signature check, issuer/audience check (OIDC), and the assertion signature/
// expiry/audience/recipient checks (SAML) are NOT reimplemented in this
// codebase -- they're delegated whole to zitadel/oidc's rp.CodeExchange and
// crewjam/saml's samlsp.Middleware respectively (both invoked before our own
// code ever inspects a claim). Exercising those specific rejections here would
// mean standing up a fake IdP/OP with real JWS/xmldsig signing just to
// re-verify a well-tested third-party library, not our handler code -- out of
// scope for a focused regression test. What IS first-party, own-code logic in
// internal/handlers/auth.go and is covered below:
//
//   - OIDCCallback: state-cookie mismatch/missing, missing provider cookie,
//     unknown provider -- all checked by our code BEFORE any token exchange.
//   - SAMLACS / SAMLLogin: feature-disabled and unknown-IdP guards.
//   - SAML assertion replay detection: the exact atomic
//     "INSERT ... ON CONFLICT (assertion_id) DO NOTHING RETURNING" SQL used by
//     SAMLACS (auth.go), proven against a live DB to reject a repeat
//     assertion_id -- this is setjoin's own replay defense (OASIS Core §2.5.1),
//     not vendored.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5"

	"setjoin.com/authserver/internal/federation"
)

func decodeProblem(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if w.Body.Len() == 0 {
		return body
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode problem body: %v (body=%s)", err, w.Body.String())
	}
	return body
}

// ── OIDC RP callback ─────────────────────────────────────────────────────

func TestOIDCCallback_ProviderDisabled(t *testing.T) {
	h := &loginHandler{&deps{logger: discardLogger()}} // oidcRP nil
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback", nil)

	h.OIDCCallback(w, r)

	if w.Code != http.StatusNotFound {
		t.Fatalf("OIDC disabled: got %d, want 404", w.Code)
	}
}

func TestOIDCCallback_StateCookieMissing(t *testing.T) {
	h := &loginHandler{&deps{logger: discardLogger(), oidcRP: &federation.OIDCRPProvider{}}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?state=abc", nil)
	// no oidc_state cookie set at all

	h.OIDCCallback(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing state cookie: got %d, want 400", w.Code)
	}
	if got := decodeProblem(t, w)["detail"]; got != "invalid state" {
		t.Errorf("detail = %v, want %q", got, "invalid state")
	}
}

func TestOIDCCallback_StateMismatch(t *testing.T) {
	h := &loginHandler{&deps{logger: discardLogger(), oidcRP: &federation.OIDCRPProvider{}}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?state=attacker-supplied", nil)
	r.AddCookie(&http.Cookie{Name: "oidc_state", Value: "server-issued-state"})

	h.OIDCCallback(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("state mismatch: got %d, want 400", w.Code)
	}
	if got := decodeProblem(t, w)["detail"]; got != "invalid state" {
		t.Errorf("detail = %v, want %q", got, "invalid state")
	}
}

func TestOIDCCallback_MissingProviderCookie(t *testing.T) {
	h := &loginHandler{&deps{logger: discardLogger(), oidcRP: &federation.OIDCRPProvider{}}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?state=s1", nil)
	r.AddCookie(&http.Cookie{Name: "oidc_state", Value: "s1"})
	r.AddCookie(&http.Cookie{Name: "oidc_verifier", Value: validTestVerifier()})
	// state and PKCE verifier match, but no oidc_provider cookie

	h.OIDCCallback(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing provider cookie: got %d, want 400", w.Code)
	}
	if got := decodeProblem(t, w)["detail"]; got != "missing provider" {
		t.Errorf("detail = %v, want %q", got, "missing provider")
	}
}

func TestOIDCCallback_UnknownProvider(t *testing.T) {
	// oidcRP has no providers loaded, so any provider name resolves to nil --
	// covers the misconfiguration/tampering case where the provider cookie
	// names a provider that isn't (or is no longer) registered.
	h := &loginHandler{&deps{logger: discardLogger(), oidcRP: &federation.OIDCRPProvider{}}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?state=s1", nil)
	r.AddCookie(&http.Cookie{Name: "oidc_state", Value: "s1"})
	r.AddCookie(&http.Cookie{Name: "oidc_verifier", Value: validTestVerifier()})
	r.AddCookie(&http.Cookie{Name: "oidc_provider", Value: "does-not-exist"})

	h.OIDCCallback(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown provider: got %d, want 400", w.Code)
	}
	if got := decodeProblem(t, w)["detail"]; got != "unknown OIDC provider" {
		t.Errorf("detail = %v, want %q", got, "unknown OIDC provider")
	}
}

// ── SAML SP ACS ──────────────────────────────────────────────────────────

func TestSAMLACS_FeatureDisabled(t *testing.T) {
	h := &loginHandler{&deps{logger: discardLogger()}} // samlSP nil
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/saml/corp/acs", nil)
	r.SetPathValue("idp", "corp")

	h.SAMLACS(w, r)

	if w.Code != http.StatusNotFound {
		t.Fatalf("SAML disabled: got %d, want 404", w.Code)
	}
}

func TestSAMLACS_UnknownIdP(t *testing.T) {
	h := &loginHandler{&deps{logger: discardLogger(), samlSP: &federation.SAMLSPRegistry{}}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/saml/no-such-idp/acs", nil)
	r.SetPathValue("idp", "no-such-idp")

	h.SAMLACS(w, r)

	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown IdP: got %d, want 404", w.Code)
	}
}

func TestSAMLLogin_UnknownIdP(t *testing.T) {
	h := &loginHandler{&deps{logger: discardLogger(), samlSP: &federation.SAMLSPRegistry{}}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/saml/no-such-idp/login", nil)
	r.SetPathValue("idp", "no-such-idp")

	h.SAMLLogin(w, r)

	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown IdP: got %d, want 404", w.Code)
	}
}

// ── SAML assertion replay detection (OASIS Core §2.5.1) ─────────────────
//
// SAMLACS's replay guard is exactly:
//
//	INSERT INTO used_saml_assertions (assertion_id) VALUES ($1)
//	ON CONFLICT (assertion_id) DO NOTHING RETURNING assertion_id
//
// with a Scan error (no row returned) treated as "already used" -> 400. This
// proves that exact primitive rejects a repeat assertion_id against a live DB,
// independent of the SAML crypto stack.
func TestSAMLAssertionReplay_SecondInsertRejected(t *testing.T) {
	pool := openHandlerPool(t)
	ctx := context.Background()
	assertionID := "regression-test-assertion-id-do-not-reuse"

	// Clean slate in case a prior failed run left the row behind.
	_, _ = pool.Exec(ctx, `DELETE FROM used_saml_assertions WHERE assertion_id = $1`, assertionID)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM used_saml_assertions WHERE assertion_id = $1`, assertionID)
	})

	var got string
	err := pool.QueryRow(ctx,
		`INSERT INTO used_saml_assertions (assertion_id) VALUES ($1)
		 ON CONFLICT (assertion_id) DO NOTHING
		 RETURNING assertion_id`,
		assertionID,
	).Scan(&got)
	if err != nil {
		t.Fatalf("first use of a fresh assertion_id must succeed: %v", err)
	}
	if got != assertionID {
		t.Fatalf("returned assertion_id = %q, want %q", got, assertionID)
	}

	// Replay: same assertion_id again -- must find no row (ON CONFLICT DO
	// NOTHING skipped the insert), which is exactly the condition SAMLACS
	// treats as "SAML assertion already used".
	err = pool.QueryRow(ctx,
		`INSERT INTO used_saml_assertions (assertion_id) VALUES ($1)
		 ON CONFLICT (assertion_id) DO NOTHING
		 RETURNING assertion_id`,
		assertionID,
	).Scan(&got)
	if err == nil {
		t.Fatal("replayed assertion_id must not insert a second row (replay not rejected)")
	}
	if err != pgx.ErrNoRows {
		t.Fatalf("replay error = %v, want pgx.ErrNoRows", err)
	}
}
