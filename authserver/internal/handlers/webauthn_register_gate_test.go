package handlers

// webauthn_register_gate_test.go — the gated WebAuthn registration finish
// (r1 receipt defect 1; scheme v7 §1.6/§2.2): the finish is ONE transaction
// whose refused outcomes leave credentials, users.factor_generation and the
// success audit UNCHANGED, and whose reauth_token is decoded from the
// BUFFERED body (the ordinary UI transport — a second body read yields
// nothing). Cryptographic fixtures come from the software authenticator
// (webauthn_software_authenticator_test.go).

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"setjoin.com/authserver/internal/token"
)

// newRegisterHarness is the possession harness with the cookie cipher keyed
// (the registration arms encrypt the wa_reg_sess transport cookie).
func newRegisterHarness(t *testing.T) *AuthHandler {
	t.Helper()
	h := newPossessionHarness(t)
	h.cookieKey = []byte("register-gate-test-cookie-key-32")
	return h
}

// registerChallenge drives WebAuthnRegisterBegin with a live
// webauthn.register grant and returns the creation challenge, the session
// cookie, the raw grant token, and the user handle bytes the creation
// options presented (what a real browser's authenticator stores).
func registerChallenge(t *testing.T, h *AuthHandler, userID int64, claimsJTI string, email string) (challenge, sessionCookie, token string, registeredHandle []byte) {
	t.Helper()
	claims := removalClaims(userID, claimsJTI)
	claims.Email = email
	tok := seedSessionGrant(t, h, userID, claims.JTI, "webauthn.register", nil, "password", nil)

	req := httptest.NewRequest(http.MethodGet, "/auth/webauthn/register/begin", nil)
	req.Header.Set(ReauthTokenHeader, tok)
	req = req.WithContext(ContextWithUser(req.Context(), claims))
	rr := httptest.NewRecorder()
	h.WebAuthnRegisterBegin(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("register begin: status = %d body %s, want 200", rr.Code, rr.Body.String())
	}
	var options struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			User      struct {
				ID string `json:"id"`
			} `json:"user"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &options); err != nil || options.PublicKey.Challenge == "" {
		t.Fatalf("register begin options %s: challenge=%q (%v)", rr.Body.String(), options.PublicKey.Challenge, err)
	}
	handle, err := base64.RawURLEncoding.DecodeString(options.PublicKey.User.ID)
	if err != nil || len(handle) == 0 {
		t.Fatalf("register begin options user.id %q: %v", options.PublicKey.User.ID, err)
	}
	var cookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == "wa_reg_sess" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("register begin set no wa_reg_sess cookie")
	}
	return options.PublicKey.Challenge, cookie.Value, tok, handle
}

// postRegisterFinish drives WebAuthnRegisterFinish: bearer claims ride the
// context (the requireAuth shape), the session cookie and the optional
// reauth_token travel the wire (header when headerTok is set, body member
// otherwise — the ordinary UI's transport). family binds the bearer's
// refresh-family claim ("" = a family-less session).
func postRegisterFinish(h *AuthHandler, userID int64, claimsJTI, email, family, sessionCookie string, attestation []byte, headerTok string, bodyTok string) *httptest.ResponseRecorder {
	claims := removalClaims(userID, claimsJTI)
	claims.Email = email
	claims.FamilyID = family

	body := attestation
	if headerTok == "" && bodyTok != "" {
		// Stitch the token member into the response body the way the SPA does:
		// the finish arm tolerates extra top-level JSON members.
		body = []byte(strings.TrimSuffix(string(attestation), "}") +
			`,"reauth_token":"` + bodyTok + `"}`)
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/webauthn/register/finish", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	if headerTok != "" {
		req.Header.Set(ReauthTokenHeader, headerTok)
	}
	req.AddCookie(&http.Cookie{Name: "wa_reg_sess", Value: sessionCookie})
	req = req.WithContext(ContextWithUser(req.Context(), claims))
	rr := httptest.NewRecorder()
	h.WebAuthnRegisterFinish(rr, req)
	return rr
}

func countRegisteredCredentials(t *testing.T, h *AuthHandler, userID int64) int {
	t.Helper()
	var n int
	if err := h.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM passkey_credentials WHERE user_id = $1`, userID,
	).Scan(&n); err != nil {
		t.Fatalf("count credentials: %v", err)
	}
	return n
}

func countRegistrationAudits(t *testing.T, h *AuthHandler, userID int64) int {
	t.Helper()
	var n int
	if err := h.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM admin_audit_log WHERE user_id = $1 AND action = 'passkey_registered'`, userID,
	).Scan(&n); err != nil {
		t.Fatalf("count audits: %v", err)
	}
	return n
}

func readFactorGeneration(t *testing.T, h *AuthHandler, userID int64) int64 {
	t.Helper()
	var gen int64
	if err := h.pool.QueryRow(context.Background(),
		`SELECT factor_generation FROM users WHERE id = $1`, userID,
	).Scan(&gen); err != nil {
		t.Fatalf("read generation: %v", err)
	}
	return gen
}

// TestWebAuthnRegisterFinishRefusalLeavesNothingPersisted is the r1 defect 1
// reproduction: a finish whose authorization is REFUSED — missing proof or
// proof bound to another ceremony — must answer 403 with credentials,
// factor_generation and the success audit untouched, even though the
// attestation itself verifies.
func TestWebAuthnRegisterFinishRefusalLeavesNothingPersisted(t *testing.T) {
	h := newRegisterHarness(t)
	auth, err := newSoftwareAuthenticator("localhost", "http://localhost:8080")
	if err != nil {
		t.Fatalf("software authenticator: %v", err)
	}

	t.Run("missing proof: refused finish persists nothing", func(t *testing.T) {
		userID, claims := newPossessionUser(t, h, "reg-nogrant", true)
		challenge, sessCookie, _, _ := registerChallenge(t, h, userID, claims.JTI, claims.Email)
		att, err := auth.AttestationResponse(challenge)
		if err != nil {
			t.Fatalf("attestation: %v", err)
		}
		credsBefore := countRegisteredCredentials(t, h, userID)
		rr := postRegisterFinish(h, userID, claims.JTI, claims.Email, "", sessCookie, att, "", "")
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status = %d body %s, want 403 reauth_required", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), ReauthRequiredCode) {
			t.Fatalf("body %s missing %q", rr.Body.String(), ReauthRequiredCode)
		}
		if n := countRegisteredCredentials(t, h, userID); n != credsBefore {
			t.Fatalf("REFUSED finish left %d credential row(s) behind (had %d) — the passkey committed on refusal", n, credsBefore)
		}
		if gen := readFactorGeneration(t, h, userID); gen != 0 {
			t.Fatalf("REFUSED finish bumped factor_generation to %d", gen)
		}
		if n := countRegistrationAudits(t, h, userID); n != 0 {
			t.Fatalf("REFUSED finish wrote %d success audit row(s)", n)
		}
	})

	t.Run("replaced proof: mismatch refusal persists nothing", func(t *testing.T) {
		userID, claims := newPossessionUser(t, h, "reg-mismatch", true)
		challenge, sessCookie, _, _ := registerChallenge(t, h, userID, claims.JTI, claims.Email)
		att, err := auth.AttestationResponse(challenge)
		if err != nil {
			t.Fatalf("attestation: %v", err)
		}
		// A grant whose tuple does not match the presented ceremony (wrong
		// operation): the §1.7 mismatch refusal — the credential must not ride
		// its commit.
		other := seedSessionGrant(t, h, userID, claims.JTI, "recovery.regenerate", nil, "totp", nil)
		credsBefore := countRegisteredCredentials(t, h, userID)
		rr := postRegisterFinish(h, userID, claims.JTI, claims.Email, "", sessCookie, att, other, "")
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status = %d body %s, want 403", rr.Code, rr.Body.String())
		}
		if n := countRegisteredCredentials(t, h, userID); n != credsBefore {
			t.Fatalf("REFUSED finish left %d credential row(s) behind (had %d) — the passkey committed on refusal", n, credsBefore)
		}
		if gen := readFactorGeneration(t, h, userID); gen != 0 {
			t.Fatalf("REFUSED finish bumped factor_generation to %d", gen)
		}
		if n := countRegistrationAudits(t, h, userID); n != 0 {
			t.Fatalf("REFUSED finish wrote %d success audit row(s)", n)
		}
	})
}

// TestWebAuthnRegisterFinishBodyTokenDecoded pins the transport half of r1
// defect 1: the finish decodes reauth_token from the BUFFERED body — the
// ordinary UI never sends the X-MFA-Reauth header on this POST — so a valid
// ceremony + valid grant completes 201 with credential, generation bump,
// audit and consumed grant.
func TestWebAuthnRegisterFinishBodyTokenDecoded(t *testing.T) {
	h := newRegisterHarness(t)
	auth, err := newSoftwareAuthenticator("localhost", "http://localhost:8080")
	if err != nil {
		t.Fatalf("software authenticator: %v", err)
	}
	userID, claims := newPossessionUser(t, h, "reg-body", false)
	challenge, sessCookie, tok, _ := registerChallenge(t, h, userID, claims.JTI, claims.Email)
	att, err := auth.AttestationResponse(challenge)
	if err != nil {
		t.Fatalf("attestation: %v", err)
	}
	rr := postRegisterFinish(h, userID, claims.JTI, claims.Email, "", sessCookie, att, "", tok)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d body %s, want 201 (the body reauth_token must decode)", rr.Code, rr.Body.String())
	}
	if n := countRegisteredCredentials(t, h, userID); n != 1 {
		t.Fatalf("credentials = %d, want the registered one", n)
	}
	if gen := readFactorGeneration(t, h, userID); gen != 1 {
		t.Fatalf("factor_generation = %d, want 1 (the §1.8 bump)", gen)
	}
	if n := countRegistrationAudits(t, h, userID); n != 1 {
		t.Fatalf("success audit rows = %d, want 1", n)
	}
	// The presented grant is consumed — a replay refuses.
	if n := countGrantsFor(t, h, userID); n != 0 {
		t.Fatalf("grant rows = %d after consumption, want 0", n)
	}
}

func countGrantsFor(t *testing.T, h *AuthHandler, userID int64) int {
	t.Helper()
	var n int
	if err := h.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM mfa_reauth_step_ups WHERE user_id = $1`, userID,
	).Scan(&n); err != nil {
		t.Fatalf("count grants: %v", err)
	}
	return n
}

// newPossessionUserWithEmail is newPossessionUser whose claims carry the
// SEEDED email (login arms resolve the account by email — the claims-shaped
// email must match the row for real email-addressed flows).
func newPossessionUserWithEmail(t *testing.T, h *AuthHandler, label string, uvPasskey bool) (int64, *token.Claims) {
	t.Helper()
	email := fmt.Sprintf("poss-%s-%d@example.test", label, time.Now().UnixNano())
	userID := seedLocalUser(t, h.pool, email)
	if uvPasskey {
		seedUVPasskey(t, h, userID, "", true)
	}
	claims := removalClaims(userID, "poss-jti-"+fmt.Sprint(userID))
	claims.Email = email
	return userID, claims
}
