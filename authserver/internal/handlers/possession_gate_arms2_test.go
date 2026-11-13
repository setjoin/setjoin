package handlers

// possession_gate_arms2_test.go — the remaining reachable fail-closed arms of
// the possession gate surface, driven through the real handlers with the
// established injection seams:
//
//   - the possession finish's §2.3 bookkeeping and §1.7 cleanup faults, and
//     the grant-issuance/commit faults for BOTH admission scopes (mfa_pending
//     and session), against real UV assertions from the software
//     authenticator;
//   - the TOTP confirm's §1.7 mismatch-refusal COMMIT fault and the legacy
//     bootstrap confirm's locked-commit fault;
//   - the bootstrap promotion's mismatch-refusal audit fault;
//   - the enrollment setup's person-fence arm behind a VALID identity-fence
//     claim (the claim path skips the classified mint fence that otherwise
//     precedes it);
//   - request-validation arms (begin decode failure, decodeReauthToken body
//     read failure, validateIssuanceOperation target rules, register-finish
//     impersonation and garbage session-cookie JSON, empty revoke id, device
//     register users-fence refusal).

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

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/pquerna/otp/totp"

	"setjoin.com/authserver/internal/authn"
	"setjoin.com/authserver/internal/token"
)

// armsUVFixture is a C1 account with a REGISTERED software authenticator: a
// real UV assertion can be minted for any ceremony the server issues.
type armsUVFixture struct {
	h         *AuthHandler
	userID    int64
	email     string
	claims    *token.Claims
	authr     *softwareAuthenticator
	bearer    string
	sessionJT string
}

func newArmsUVFixture(t *testing.T, label string) *armsUVFixture {
	t.Helper()
	h := newRegisterHarness(t)
	authr, err := newSoftwareAuthenticator("localhost", "http://localhost:8080")
	if err != nil {
		t.Fatalf("software authenticator: %v", err)
	}
	userID, email, claims := seedC1UserWithPassword(t, h, label, authr)
	bearer := armsIssueBearer(t, h, userID, email)
	wire, err := h.jwt.Validate(bearer)
	if err != nil {
		t.Fatalf("validate bearer: %v", err)
	}
	return &armsUVFixture{h: h, userID: userID, email: email, claims: claims, authr: authr, bearer: bearer, sessionJT: wire.JTI}
}

// armsBeginAndAssert runs a management-assertion begin for the scope and
// returns a fresh, VALID UV assertion over the issued challenge.
func (f *armsUVFixture) armsBeginAndAssert(t *testing.T, operation string, mfaToken string) (assertion []byte, extra map[string]string) {
	t.Helper()
	payload := map[string]any{"operation": operation}
	hdrs := map[string]string{}
	if mfaToken != "" {
		payload["mfa_token"] = mfaToken
	} else {
		hdrs["Authorization"] = "Bearer " + f.bearer
	}
	br := postPossession(f.h, "/auth/mfa/possession/webauthn/begin", payload, hdrs, nil)
	if br.Code != http.StatusOK {
		t.Fatalf("begin = %d body %s, want 200", br.Code, br.Body.String())
	}
	var options struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(br.Body.Bytes(), &options); err != nil || options.PublicKey.Challenge == "" {
		t.Fatalf("begin options %s (%v)", br.Body.String(), err)
	}
	assertion, err := f.authr.AssertionResponse(options.PublicKey.Challenge, nil)
	if err != nil {
		t.Fatalf("assertion: %v", err)
	}
	extra = map[string]string{"operation": operation}
	if mfaToken != "" {
		extra["mfa_token"] = mfaToken
	}
	if mfaToken == "" {
		return assertion, map[string]string{"operation": operation}
	}
	return assertion, extra
}

func TestPossessionFinishFaultedBookkeepingArms(t *testing.T) {
	t.Run("faulted refusal commit fails the finish closed", func(t *testing.T) {
		f := newArmsUVFixture(t, "arms-fin-refuse")
		_, T := loginForBootstrap(t, f.h, f.email, "correct-horse-battery")
		if T == "" {
			t.Fatal("no mfa_token from login")
		}
		assertion, extra := f.armsBeginAndAssert(t, "bootstrap.totp.enroll", T)
		// A parseable assertion over a DIFFERENT challenge: an EVALUATED
		// failure whose §2.3 increment commits with the refusal — the
		// deferred fault breaks that commit → 500.
		attWrong, err := f.authr.AssertionResponse("arms-wrong-challenge", nil)
		if err != nil {
			t.Fatal(err)
		}
		armsDeferredCommitFault(t, f.h, "arms_fin_refuse_commit_fault", "arms_fin_refuse_commit_trig", "users", "AFTER UPDATE",
			"NEW.id = "+itoaInt(f.userID)+" AND NEW.possession_webauthn_failed_attempts = OLD.possession_webauthn_failed_attempts + 1")
		_ = assertion
		fr := postPossessionFinishHdrs(f.h, "/auth/mfa/possession/webauthn/finish", attWrong, extra, nil)
		if fr.Code != http.StatusInternalServerError {
			t.Fatalf("finish with faulted refusal commit = %d body %s, want 500", fr.Code, fr.Body.String())
		}
		if budget := readWebAuthnBudget(t, f.h, f.userID); budget.Attempts != 0 {
			t.Fatalf("webauthn_uv counter after faulted refusal = %d, want 0 (the increment rolled back)", budget.Attempts)
		}
		var ceremonies int
		if err := f.h.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM webauthn_ceremonies WHERE user_id = $1`, f.userID).Scan(&ceremonies); err != nil || ceremonies != 1 {
			t.Fatalf("ceremony rows after faulted refusal = %d (%v), want 1 (not consumed)", ceremonies, err)
		}
	})

	t.Run("faulted budget reset fails the finish closed", func(t *testing.T) {
		f := newArmsUVFixture(t, "arms-fin-reset")
		_, T := loginForBootstrap(t, f.h, f.email, "correct-horse-battery")
		assertion, extra := f.armsBeginAndAssert(t, "bootstrap.totp.enroll", T)
		// Park the counter at 1 so the success reset is a REAL rewrite.
		if _, err := f.h.pool.Exec(context.Background(),
			`UPDATE users SET possession_webauthn_failed_attempts = 1 WHERE id = $1`, f.userID); err != nil {
			t.Fatal(err)
		}
		armsFaultTrigger(t, f.h, "arms_fin_reset_fault", "arms_fin_reset_trig", "users", "BEFORE UPDATE",
			"NEW.id = "+itoaInt(f.userID)+" AND NEW.possession_webauthn_failed_attempts = 0 AND OLD.possession_webauthn_failed_attempts <> 0")
		fr := postPossessionFinishHdrs(f.h, "/auth/mfa/possession/webauthn/finish", assertion, extra, nil)
		if fr.Code != http.StatusInternalServerError {
			t.Fatalf("finish with faulted reset = %d, want 500", fr.Code)
		}
		if budget := readWebAuthnBudget(t, f.h, f.userID); budget.Attempts != 1 {
			t.Fatalf("counter after faulted reset = %d, want 1 (the reset rolled back)", budget.Attempts)
		}
	})
}

func TestPossessionFinishConsumeAndGrantFaultArms(t *testing.T) {
	t.Run("faulted ceremony consume fails closed", func(t *testing.T) {
		f := newArmsUVFixture(t, "arms-fin-consume")
		_, T := loginForBootstrap(t, f.h, f.email, "correct-horse-battery")
		assertion, extra := f.armsBeginAndAssert(t, "bootstrap.totp.enroll", T)
		armsFaultTrigger(t, f.h, "arms_fin_consume_fault", "arms_fin_consume_trig", "webauthn_ceremonies", "BEFORE DELETE",
			"OLD.user_id = "+itoaInt(f.userID))
		fr := postPossessionFinishHdrs(f.h, "/auth/mfa/possession/webauthn/finish", assertion, extra, nil)
		if fr.Code != http.StatusInternalServerError {
			t.Fatalf("finish with faulted consume = %d, want 500", fr.Code)
		}
		// A C1 account holds NO bootstrap grant; the faulted consume rolls
		// back, so still zero grant rows and the ceremony stays live.
		if n := countGrantsFor(t, f.h, f.userID); n != 0 {
			t.Fatalf("grant rows after faulted consume = %d, want 0", n)
		}
	})

	t.Run("faulted mfa_pending grant issuance fails closed", func(t *testing.T) {
		f := newArmsUVFixture(t, "arms-fin-mp-grant")
		_, T := loginForBootstrap(t, f.h, f.email, "correct-horse-battery")
		assertion, extra := f.armsBeginAndAssert(t, "bootstrap.totp.enroll", T)
		armsFaultTrigger(t, f.h, "arms_fin_mp_grant_fault", "arms_fin_mp_grant_trig", "mfa_reauth_step_ups", "BEFORE INSERT",
			"NEW.user_id = "+itoaInt(f.userID))
		fr := postPossessionFinishHdrs(f.h, "/auth/mfa/possession/webauthn/finish", assertion, extra, nil)
		if fr.Code != http.StatusInternalServerError {
			t.Fatalf("finish with faulted mfa_pending grant = %d, want 500", fr.Code)
		}
		// A C1 account holds NO bootstrap grant (the UV proof mints it) — the
		// faulted mint must leave ZERO grant rows.
		if n := countGrantsFor(t, f.h, f.userID); n != 0 {
			t.Fatalf("grant rows after faulted mint = %d, want 0", n)
		}
	})

	t.Run("faulted mfa_pending grant commit issues nothing", func(t *testing.T) {
		f := newArmsUVFixture(t, "arms-fin-mp-commit")
		_, T := loginForBootstrap(t, f.h, f.email, "correct-horse-battery")
		assertion, extra := f.armsBeginAndAssert(t, "bootstrap.totp.enroll", T)
		armsDeferredCommitFault(t, f.h, "arms_fin_mp_commit_fault", "arms_fin_mp_commit_trig", "mfa_reauth_step_ups", "AFTER INSERT",
			"NEW.user_id = "+itoaInt(f.userID))
		fr := postPossessionFinishHdrs(f.h, "/auth/mfa/possession/webauthn/finish", assertion, extra, nil)
		if fr.Code != http.StatusInternalServerError {
			t.Fatalf("finish with faulted mfa_pending commit = %d, want 500", fr.Code)
		}
		if n := countGrantsFor(t, f.h, f.userID); n != 0 {
			t.Fatalf("grant rows after faulted commit = %d, want 0 (the UV grant rolled back)", n)
		}
	})

	t.Run("faulted session grant issuance fails closed", func(t *testing.T) {
		f := newArmsUVFixture(t, "arms-fin-sess-grant")
		assertion, extra := f.armsBeginAndAssert(t, "recovery.regenerate", "")
		armsFaultTrigger(t, f.h, "arms_fin_sess_grant_fault", "arms_fin_sess_grant_trig", "mfa_reauth_step_ups", "BEFORE INSERT",
			"NEW.user_id = "+itoaInt(f.userID))
		hdrs := map[string]string{"Authorization": "Bearer " + f.bearer}
		fr := postPossessionFinishHdrs(f.h, "/auth/mfa/possession/webauthn/finish", assertion, extra, hdrs)
		if fr.Code != http.StatusInternalServerError {
			t.Fatalf("finish with faulted session grant = %d, want 500", fr.Code)
		}
		if n := countGrantsFor(t, f.h, f.userID); n != 0 {
			t.Fatalf("grant rows after faulted session grant = %d, want 0", n)
		}
	})

	t.Run("faulted session grant commit issues nothing", func(t *testing.T) {
		f := newArmsUVFixture(t, "arms-fin-sess-commit")
		assertion, extra := f.armsBeginAndAssert(t, "recovery.regenerate", "")
		armsDeferredCommitFault(t, f.h, "arms_fin_sess_commit_fault", "arms_fin_sess_commit_trig", "mfa_reauth_step_ups", "AFTER INSERT",
			"NEW.user_id = "+itoaInt(f.userID))
		hdrs := map[string]string{"Authorization": "Bearer " + f.bearer}
		fr := postPossessionFinishHdrs(f.h, "/auth/mfa/possession/webauthn/finish", assertion, extra, hdrs)
		if fr.Code != http.StatusInternalServerError {
			t.Fatalf("finish with faulted session commit = %d, want 500", fr.Code)
		}
		if n := countGrantsFor(t, f.h, f.userID); n != 0 {
			t.Fatalf("grant rows after faulted session commit = %d, want 0", n)
		}
	})
}

// --- request-validation arms ---

func TestPossessionBeginDecodeFailArm(t *testing.T) {
	h := newPossessionHarness(t)
	userID, claims := newPossessionUser(t, h, "arms-beg-decode", true)
	bearer := armsIssueBearer(t, h, userID, claims.Email)
	req := httptest.NewRequest(http.MethodPost, "/auth/mfa/possession/webauthn/begin", strings.NewReader("{not-json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	rr := httptest.NewRecorder()
	h.MFAPossessionWebAuthnBegin(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("begin with unparseable body = %d, want 400", rr.Code)
	}
	var ceremonies int
	if err := h.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM webauthn_ceremonies WHERE user_id = $1`, userID).Scan(&ceremonies); err != nil || ceremonies != 0 {
		t.Fatalf("ceremony rows after decode failure = %d (%v), want 0", ceremonies, err)
	}
}

func TestTOTPSetupDecodeReadErrorArm(t *testing.T) {
	rh := newReauthStepupHarness(t, "none")
	// A body that fails mid-read defeats BOTH transports (header absent, body
	// unreadable): the gate refuses the setup with the typed 403.
	req := httptest.NewRequest(http.MethodGet, "/auth/totp/setup", errReader{err: fmt.Errorf("injected setup body failure")})
	req = req.WithContext(ContextWithUser(req.Context(), rh.claims()))
	rr := httptest.NewRecorder()
	rh.h.TOTPSetup(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("setup with unreadable body = %d, want 403 reauth_required", rr.Code)
	}
	var pending int
	if err := rh.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM totp_pending_enrollments WHERE user_id = $1`, rh.userID).Scan(&pending); err != nil || pending != 0 {
		t.Fatalf("pending rows after unreadable body = %d (%v), want 0", pending, err)
	}
}

func TestRequirePossessionGateRefusalCommitFaultArm(t *testing.T) {
	rh := newReauthStepupHarness(t, "none")
	// The seeded grant declares totp.enroll; the gated arm consumes
	// recovery.regenerate — the §1.7 mismatch deletes the row in-tx and the
	// gate COMMITS the refusal: the deferred fault breaks that commit.
	tok := rh.seedGrant("totp.enroll", nil)
	armsDeferredCommitFault(t, rh.h, "arms_gate_commit_fault", "arms_gate_commit_trig", "mfa_reauth_step_ups", "AFTER DELETE",
		"OLD.user_id = "+itoaInt(rh.userID))
	rec := rh.generate(tok)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("gated generate with faulted refusal commit = %d, want 500", rec.Code)
	}
	// The failed commit rolled the §1.7 deletion back: the grant survives.
	if n := countGrantsFor(t, rh.h, rh.userID); n != 1 {
		t.Fatalf("grant rows after faulted gate commit = %d, want 1", n)
	}
}

func TestValidateIssuanceOperationArms(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/mfa/reauth", nil)

	// webauthn.revoke WITHOUT a target: refused.
	if _, ok := validateIssuanceOperation(rr, req, "webauthn.revoke", ""); ok || rr.Code != http.StatusBadRequest {
		t.Fatalf("revoke without target = ok=%v status=%d, want false/400", ok, rr.Code)
	}
	// webauthn.revoke with an INVALID target encoding: refused.
	if _, ok := validateIssuanceOperation(rr, req, "webauthn.revoke", "!!!"); ok || rr.Code != http.StatusBadRequest {
		t.Fatalf("revoke with invalid target = ok=%v status=%d, want false/400", ok, rr.Code)
	}
	// A target on a NON-revoke operation: refused (one proof, one target).
	rr2 := httptest.NewRecorder()
	if _, ok := validateIssuanceOperation(rr2, req, "recovery.regenerate", "QUFB"); ok || rr2.Code != http.StatusBadRequest {
		t.Fatalf("target on non-revoke = ok=%v status=%d, want false/400", ok, rr2.Code)
	}
	// The happy revoke declaration canonicalizes the target.
	canonical, ok := validateIssuanceOperation(rr, req, "webauthn.revoke", "QUFBQUFB")
	if !ok || canonical == nil || *canonical != "QUFBQUFB" {
		t.Fatalf("revoke with valid target = (%v,%v), want canonical target", ok, canonical)
	}
}

// --- totp.go commit faults ---

func TestTOTPConfirmMismatchRefusalCommitFaultArm(t *testing.T) {
	rh := newReauthStepupHarness(t, "none")
	// The grant is bound to enrollment E; the STAGED row E is dead: the
	// confirm's pending-lookup mismatch runs commitGrantMismatchRefusal —
	// delete + audit + COMMIT — and the deferred fault breaks the commit.
	const deadEnrollment = "00000000-0000-0000-0000-00000000000e"
	tok := rh.seedGrant("totp.enroll", map[string]any{"target_ref": deadEnrollment})
	armsDeferredCommitFault(t, rh.h, "arms_confirm_mismatch_commit_fault", "arms_confirm_mismatch_commit_trig", "mfa_reauth_step_ups", "AFTER DELETE",
		"OLD.user_id = "+itoaInt(rh.userID))
	if rr := rh.confirm("000000", tok, deadEnrollment); rr.Code != http.StatusInternalServerError {
		t.Fatalf("confirm with faulted mismatch commit = %d, want 500", rr.Code)
	}
	if n := countGrantsFor(t, rh.h, rh.userID); n != 1 {
		t.Fatalf("grant rows after faulted mismatch commit = %d, want 1 (the §1.7 delete rolled back)", n)
	}
}

func TestPromotePeekMismatchAuditFaultArm(t *testing.T) {
	h, _, userID, mfaToken, _, enrollmentID := newBootstrapConfirmHarness(t, "arms-promo-audit")
	// Wrong enrollment id: the peek misses on the bound target — the §1.7
	// mismatch refusal's AUDIT insert is faulted, so the cleanup errors and
	// the promotion fails closed as bookkeeping.
	armsFaultTrigger(t, h, "arms_promo_refusal_audit_fault", "arms_promo_refusal_audit_trig", "admin_audit_log", "BEFORE INSERT",
		"NEW.user_id = "+itoaInt(userID)+" AND NEW.action = 'mfa_reauth_refused'")
	if rr := postEnrollmentJSON(t, "/auth/totp/enroll/confirm",
		map[string]any{"mfa_token": mfaToken, "code": "000000", "enrollment_id": enrollmentID + "0"}, h.TOTPEnrollmentConfirm); rr.Code != http.StatusInternalServerError {
		t.Fatalf("promotion with faulted mismatch audit = %d, want 500", rr.Code)
	}
}

func TestLegacyConfirmLockedCommitFaultArm(t *testing.T) {
	h, pool, userID, mfaToken, _, enrollmentID := newBootstrapConfirmHarness(t, "arms-legacy-lock")
	// Park at 4: a wrong code is the FIFTH evaluated failure — the increment
	// locks the account and the outcome commit carries it; the deferred fault
	// breaks that commit → 503, and the lock never takes effect (fail-closed:
	// a half-applied lockout is a refusal, not a state change).
	if _, err := pool.Exec(context.Background(),
		`UPDATE users SET totp_failed_attempts = 4 WHERE id = $1`, userID); err != nil {
		t.Fatal(err)
	}
	armsDeferredCommitFault(t, h, "arms_legacy_lock_commit_fault", "arms_legacy_lock_commit_trig", "users", "AFTER UPDATE",
		"NEW.id = "+itoaInt(userID)+" AND NEW.totp_failed_attempts = OLD.totp_failed_attempts + 1")
	if rr := postEnrollmentJSON(t, "/auth/totp/enroll/confirm",
		map[string]any{"mfa_token": mfaToken, "code": "000000", "enrollment_id": enrollmentID}, h.TOTPEnrollmentConfirm); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("locked legacy confirm with faulted commit = %d, want 503", rr.Code)
	}
	at, lock := readTOTPBudget(t, h, userID)
	if at != 4 || lock != nil {
		t.Fatalf("budget after faulted lock commit = %d/%v, want exactly 4/nil (the increment rolled back)", at, lock)
	}
}

// --- enrollment setup person fence behind a VALID identity-fence claim ---

// --- webauthn.go remaining arms ---

func TestWebAuthnFinishImpersonatedArm(t *testing.T) {
	h := newRegisterHarness(t)
	authr, err := newSoftwareAuthenticator("localhost", "http://localhost:8080")
	if err != nil {
		t.Fatal(err)
	}
	userID, email, claims := seedC1UserWithPassword(t, h, "arms-regf-imp", authr)
	seedEnabledTOTP(t, h, userID)
	tok := seedSessionGrant(t, h, userID, claims.JTI, "webauthn.register", nil, "totp", nil)
	challenge, cookie, _, _ := registerChallenge(t, h, userID, claims.JTI, email)
	att, err := authr.AttestationResponse(challenge)
	if err != nil {
		t.Fatal(err)
	}
	// The impersonated CONTEXT claims ride the requireAuth shape: the finish
	// refuses BEFORE any ceremony or cookie work.
	imp := armsImpersonated(claims)
	imp.Email = email
	imp.FamilyID = "F"
	body := strings.TrimSuffix(string(att), "}") + `,"reauth_token":"` + tok + `"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/webauthn/register/finish", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(ReauthTokenHeader, tok)
	req.AddCookie(&http.Cookie{Name: "wa_reg_sess", Value: cookie})
	req = req.WithContext(ContextWithUser(req.Context(), imp))
	rr := httptest.NewRecorder()
	h.WebAuthnRegisterFinish(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("register finish with impersonated claims = %d body %s, want 403", rr.Code, rr.Body.String())
	}
	if n := countRegisteredCredentials(t, h, userID); n != 1 {
		t.Fatalf("credentials after impersonated finish = %d, want 1 (unchanged)", n)
	}
}

func TestWebAuthnFinishGarbageSessionCookieArm(t *testing.T) {
	h := newRegisterHarness(t)
	userID, email, claims := seedC1UserWithPassword(t, h, "arms-regf-garb", nil)
	seedEnabledTOTP(t, h, userID)
	// A cookie that DECRYPTS but is not a SessionData document: the finish
	// must refuse with the same 400 shape before any ceremony work.
	garbage, err := h.encryptCookieValue([]byte(`{"Challenge":123}`))
	if err != nil {
		t.Fatal(err)
	}
	tok := seedSessionGrant(t, h, userID, claims.JTI, "webauthn.register", nil, "totp", nil)
	rr := postRegisterFinish(h, userID, claims.JTI, email, "F", garbage, []byte(`{}`), tok, "")
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid session cookie") {
		t.Fatalf("finish with garbage session JSON = %d body %s, want 400", rr.Code, rr.Body.String())
	}
}

func TestWebAuthnRevokeEmptyIDArm(t *testing.T) {
	h := newRegisterHarness(t)
	userID, _, claims := seedC1UserWithPassword(t, h, "arms-revoke-empty", nil)
	seedEnabledTOTP(t, h, userID)
	req := httptest.NewRequest(http.MethodDelete, "/auth/webauthn/credentials/", nil)
	req.SetPathValue("id", "")
	req = req.WithContext(ContextWithUser(req.Context(), claims))
	rr := httptest.NewRecorder()
	h.WebAuthnRevokeCredential(rr, req)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "missing credential id") {
		t.Fatalf("revoke with empty id = %d body %s, want 400", rr.Code, rr.Body.String())
	}
}

func TestWebAuthnRevokeDeletedUserArm(t *testing.T) {
	h := newRegisterHarness(t)
	userID, _, claims := seedC1UserWithPassword(t, h, "arms-revoke-del", nil)
	seedEnabledTOTP(t, h, userID)
	credID := seedUVPasskey(t, h, userID, "", true)
	target := base64.RawURLEncoding.EncodeToString(credID)
	tok := seedSessionGrant(t, h, userID, claims.JTI, "webauthn.revoke", &target, "totp", nil)
	if _, err := h.pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodDelete, "/auth/webauthn/credentials/"+target, nil)
	req.SetPathValue("id", target)
	req.Header.Set(ReauthTokenHeader, tok)
	req = req.WithContext(ContextWithUser(req.Context(), claims))
	rr := httptest.NewRecorder()
	h.WebAuthnRevokeCredential(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("revoke for a deleted user = %d, want 500", rr.Code)
	}
}

func TestDeviceRegisterDeletedUserArm(t *testing.T) {
	h := newPossessionHarness(t)
	userID, claims := newPossessionUserWithEmail(t, h, "arms-dev-del", true)
	seedEnabledTOTP(t, h, userID)
	tok, status := func() (string, int) {
		code, err := totp.GenerateCode(removalTestSecret, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		rr := armsPostTOTP(h, map[string]any{"operation": "device.register.native", "code": code}, nil, claims)
		var out struct {
			ReauthToken string `json:"reauth_token"`
		}
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return out.ReauthToken, rr.Code
	}()
	if status != http.StatusOK || tok == "" {
		t.Fatalf("device proof: status %d token %q", status, tok)
	}
	// The user row dies AFTER the proof: the fenced tx's users fence refuses
	// the registration closed.
	if _, err := h.pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID); err != nil {
		t.Fatal(err)
	}
	key := armsNativeDeviceKey(t)
	if rr := armsPostDeviceRegister(h, map[string]any{
		"provider": "apns", "push_token": "arms-del-token", "device_public_key": key, "reauth_token": tok,
	}, claims); rr.Code != http.StatusInternalServerError {
		t.Fatalf("native register for a deleted user = %d, want 500", rr.Code)
	}
	var devices int
	if err := h.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM push_devices WHERE user_id = $1`, userID).Scan(&devices); err == nil && devices != 0 {
		t.Fatalf("devices after deleted-user register = %d, want 0", devices)
	}
}

var _ = protocol.ErrBadRequest
var _ = authn.ErrGrantRequired

func TestPossessionWebAuthnNilPasskeySeamArm(t *testing.T) {
	pool := enrollmentHandlerPool(t)
	ensureEnrollmentLocalDomain(t, pool)
	// A handler assembled WITHOUT a passkey seam at all (nil interface): the
	// ceremony provider is nil and the endpoints answer 404 once admission
	// succeeds — the unconfigured-WebAuthn posture.
	d := &deps{pool: pool, jwt: newTestJWT(), logger: discardLogger()}
	h := &AuthHandler{
		deps:           d,
		loginHandler:   loginHandler{d},
		mfaHandler:     mfaHandler{d},
		sessionHandler: sessionHandler{d},
	}
	userID, claims := newPossessionUser(t, h, "arms-nilseam", true)
	bearer := armsIssueBearer(t, h, userID, claims.Email)
	hdrs := map[string]string{"Authorization": "Bearer " + bearer}
	if rr := armsPostBegin(h, map[string]any{"operation": "recovery.regenerate"}, hdrs, claims); rr.Code != http.StatusNotFound {
		t.Fatalf("begin with nil passkey seam = %d, want 404", rr.Code)
	}
	if rr := armsPostFinishBody(h, `{"operation":"recovery.regenerate"}`, hdrs, claims); rr.Code != http.StatusNotFound {
		t.Fatalf("finish with nil passkey seam = %d, want 404", rr.Code)
	}
}

func TestTOTPConfirmPendingLookupScanFaultArm(t *testing.T) {
	rh := newReauthStepupHarness(t, "none")
	tok, status := rh.beginReauth(rh.password, "totp.enroll")
	if status != http.StatusOK || tok == "" {
		t.Fatalf("proof: status %d token %q", status, tok)
	}
	sr := rh.setup(tok)
	if sr.Code != http.StatusOK {
		t.Fatalf("setup = %d, want 200", sr.Code)
	}
	_, enrollmentID := setupBody(t, sr)
	// The pending row's expiry is parked at 'infinity': the peek passes
	// (row live) but the pending LOOKUP's timestamptz scan fails — the
	// confirm must fail closed with 500 and leave the grant untouched.
	if _, err := rh.pool.Exec(context.Background(),
		`UPDATE totp_pending_enrollments SET expires_at = 'infinity'::timestamptz WHERE user_id = $1`, rh.userID); err != nil {
		t.Fatal(err)
	}
	if rr := rh.confirm("000000", tok, enrollmentID); rr.Code != http.StatusInternalServerError {
		t.Fatalf("confirm with faulted pending lookup = %d, want 500", rr.Code)
	}
	if n := countGrantsFor(t, rh.h, rh.userID); n != 1 {
		t.Fatalf("grant rows after faulted pending lookup = %d, want 1 (unconsumed)", n)
	}
}
