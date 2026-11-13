package handlers

// webauthn_register_login_test.go — registration-to-login coverage with a
// real signed attestation/assertion (r1 receipt defect 5 / fix plan 3;
// scheme v7 §4 "registration-to-login coverage"): the WebAuthn user handle
// minted inside the gated registration begin is STABLE — persisted in the
// registration transaction before the options are produced — so a real
// browser authenticator that stores the handle at registration presents a
// userHandle the login path accepts.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestWebAuthnRegistrationToLoginStableHandle drives the REAL registration
// pair (begin + finish with a signed "none" attestation) and then the REAL
// login pair (begin + finish with a signed UV assertion) for the SAME
// credential. The software authenticator stores the user handle from the
// registration options — exactly what a browser does — and presents it in
// the login assertion.
func TestWebAuthnRegistrationToLoginStableHandle(t *testing.T) {
	h := newRegisterHarness(t)
	auth, err := newSoftwareAuthenticator("localhost", "http://localhost:8080")
	if err != nil {
		t.Fatalf("software authenticator: %v", err)
	}
	userID, claims := newPossessionUserWithEmail(t, h, "reg-login", false)

	// Registration begin: the options present a user handle, and the SAME
	// handle is already PERSISTED (minted inside the registration transaction
	// before the options were produced).
	challenge, sessCookie, tok, handle := registerChallenge(t, h, userID, claims.JTI, claims.Email)
	var dbHandle []byte
	if err := h.pool.QueryRow(context.Background(),
		`SELECT webauthn_user_handle FROM users WHERE id = $1`, userID,
	).Scan(&dbHandle); err != nil {
		t.Fatalf("read handle after begin: %v", err)
	}
	if len(dbHandle) == 0 {
		t.Fatal("registration begin persisted NO webauthn_user_handle — the options present an unstable ID")
	}
	if string(dbHandle) != string(handle) {
		t.Fatalf("persisted handle %x != options handle %x", dbHandle, handle)
	}

	// Registration finish: verify → consume → persist, one commit.
	att, err := auth.AttestationResponse(challenge)
	if err != nil {
		t.Fatalf("attestation: %v", err)
	}
	rr := postRegisterFinish(h, userID, claims.JTI, claims.Email, "", sessCookie, att, tok, "")
	if rr.Code != http.StatusCreated {
		t.Fatalf("register finish: status = %d body %s, want 201", rr.Code, rr.Body.String())
	}

	// Login begin for the SAME account.
	email := claims.Email
	lb := httptest.NewRequest(http.MethodGet, "/auth/webauthn/login/begin?email="+email, nil)
	lrr := httptest.NewRecorder()
	h.WebAuthnLoginBegin(lrr, lb)
	if lrr.Code != http.StatusOK {
		t.Fatalf("login begin: status = %d body %s, want 200", lrr.Code, lrr.Body.String())
	}
	var loginOptions struct {
		PublicKey struct {
			Challenge        string `json:"challenge"`
			AllowCredentials []struct {
				ID string `json:"id"`
			} `json:"allowCredentials"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(lrr.Body.Bytes(), &loginOptions); err != nil || loginOptions.PublicKey.Challenge == "" {
		t.Fatalf("login begin options %s (%v)", lrr.Body.String(), err)
	}
	if len(loginOptions.PublicKey.AllowCredentials) == 0 {
		t.Fatal("login begin allowed no credentials — the registered credential is missing")
	}
	if got := loginOptions.PublicKey.AllowCredentials[0].ID; got != base64.RawURLEncoding.EncodeToString(auth.credID) {
		t.Fatalf("allowCredentials id %q, want the registered credential %q", got, base64.RawURLEncoding.EncodeToString(auth.credID))
	}
	var sessCookieV, uidCookieV string
	for _, c := range lrr.Result().Cookies() {
		switch c.Name {
		case "wa_login_sess":
			sessCookieV = c.Value
		case "wa_login_uid":
			uidCookieV = c.Value
		}
	}
	if sessCookieV == "" || uidCookieV == "" {
		t.Fatal("login begin set no session/uid cookies")
	}

	// The browser authenticator signs the login assertion presenting the
	// handle it stored at REGISTRATION — the real-browser behavior the
	// unstable-handle defect broke.
	assertion, err := auth.AssertionResponse(loginOptions.PublicKey.Challenge, handle)
	if err != nil {
		t.Fatalf("assertion: %v", err)
	}
	lf := httptest.NewRequest(http.MethodPost, "/auth/webauthn/login/finish", strings.NewReader(string(assertion)))
	lf.Header.Set("Content-Type", "application/json")
	lf.AddCookie(&http.Cookie{Name: "wa_login_sess", Value: sessCookieV})
	lf.AddCookie(&http.Cookie{Name: "wa_login_uid", Value: uidCookieV})
	lfrr := httptest.NewRecorder()
	h.WebAuthnLoginFinish(lfrr, lf)
	if lfrr.Code != http.StatusOK {
		t.Fatalf("login finish: status = %d body %s, want 200 — the registered handle must survive to login", lfrr.Code, lfrr.Body.String())
	}
	var tokens struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(lfrr.Body.Bytes(), &tokens); err != nil || tokens.AccessToken == "" {
		t.Fatalf("login finish body %s: no access_token (%v)", lfrr.Body.String(), err)
	}
	if _, err := h.jwt.Validate(tokens.AccessToken); err != nil {
		t.Fatalf("minted access token invalid: %v", err)
	}
}
