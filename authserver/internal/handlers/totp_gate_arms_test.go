package handlers

// totp_gate_arms_test.go — fail-closed arm coverage for the gated TOTP arms
// (totp.go), the password re-auth issuance (mfa_reauth.go), the gated
// backup-code regeneration (mfa.go), native device registration (device.go),
// the bootstrap grant mint (auth.go), the per-tab session token read
// (session.go) and the removal flow's impersonation guards (totp_removal.go).
// The happy paths and matrix scenarios live in possession_matrix_test.go,
// mfa_reauth_test.go, possession_bootstrap_promotion_test.go and
// totp_enrollment_handler_test.go; this file drives the arms those suites do
// not reach:
//
//   - §2.2 fence failures (person-fence function fault scoped to one fixture
//     user; deleted-user users-fence), impersonation guards, and the
//     durable-revocation refusals;
//   - statement faults for every gated write (pending-TOTP stage/delete,
//     one-time binding, promotion, generation bump, audit inserts) and
//     deferred constraint triggers for the COMMIT-failure arms;
//   - the §1.7 mismatch-refusal cleanup (its delete, audit and commit must
//     all fail closed);
//   - request-validation refusals and the §2.3 budget arms (locked → 429,
//     faulted read via the 'infinity' scan fault, increment/reset faults).
//
// Every test asserts the OBSERVABLE outcome — status contract, preserved
// counters, no half-bound grants, no consumed ceremonies — never merely line
// execution.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"

	"setjoin.com/authserver/internal/token"
	"setjoin.com/shared/jwtutil"
)

// --- fencedFactorTx + TOTPSetup guards (handlers/totp.go) ---

func TestTOTPSetupFenceAndGuardArms(t *testing.T) {
	rh := newReauthStepupHarness(t, "totp")

	t.Run("person fence fault fails the setup closed", func(t *testing.T) {
		var original string
		if err := rh.pool.QueryRow(context.Background(),
			`SELECT pg_get_functiondef('identity_auth_person_fence(bigint)'::regprocedure)`).Scan(&original); err != nil {
			t.Fatal(err)
		}
		if _, err := rh.pool.Exec(context.Background(), fmt.Sprintf(`CREATE OR REPLACE FUNCTION identity_auth_person_fence(p_user_id BIGINT) RETURNS void
			LANGUAGE plpgsql AS $fn$
			BEGIN
			  IF p_user_id = %d THEN
			    RAISE EXCEPTION 'injected setup fence failure';
			  END IF;
			  PERFORM pg_advisory_xact_lock(hashtextextended('identity-person:'||p_user_id::text, 0));
			END $fn$;`, rh.userID)); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = rh.pool.Exec(context.Background(), original)
		})
		if rr := rh.setup(""); rr.Code != http.StatusInternalServerError {
			t.Fatalf("setup under fence fault = %d body %s, want 500", rr.Code, rr.Body.String())
		}
		// Nothing staged under the faulted fence.
		var pending int
		if err := rh.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM totp_pending_enrollments WHERE user_id = $1`, rh.userID).Scan(&pending); err != nil || pending != 0 {
			t.Fatalf("pending rows under fence fault = %d (%v), want 0", pending, err)
		}
	})

	t.Run("deleted user fails the setup users fence", func(t *testing.T) {
		dh := newReauthStepupHarness(t, "none")
		if _, err := dh.pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, dh.userID); err != nil {
			t.Fatal(err)
		}
		if rr := dh.setup(""); rr.Code != http.StatusInternalServerError {
			t.Fatalf("setup for a deleted user = %d, want 500", rr.Code)
		}
	})

	t.Run("impersonated bearer refused at setup", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/totp/setup", nil)
		req = req.WithContext(ContextWithUser(req.Context(), armsImpersonated(rh.claims())))
		rr := httptest.NewRecorder()
		rh.h.TOTPSetup(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("setup with impersonated claims = %d, want 403", rr.Code)
		}
		var pending int
		if err := rh.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM totp_pending_enrollments WHERE user_id = $1`, rh.userID).Scan(&pending); err != nil || pending != 0 {
			t.Fatalf("pending rows after impersonated setup = %d (%v), want 0", pending, err)
		}
	})
}

func TestTOTPSetupFirstBindFaultArms(t *testing.T) {
	t.Run("faulted pending stage fails closed", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		tok, status := rh.beginReauth(rh.password, "totp.enroll")
		if status != http.StatusOK || tok == "" {
			t.Fatalf("proof: status %d token %q", status, tok)
		}
		armsFaultTrigger(t, rh.h, "arms_setup_stage_fault", "arms_setup_stage_trig", "totp_pending_enrollments", "BEFORE INSERT",
			"NEW.user_id = "+itoaInt(rh.userID))
		if rr := rh.setup(tok); rr.Code != http.StatusInternalServerError {
			t.Fatalf("setup with faulted stage = %d, want 500", rr.Code)
		}
		var pending int
		if err := rh.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM totp_pending_enrollments WHERE user_id = $1`, rh.userID).Scan(&pending); err != nil || pending != 0 {
			t.Fatalf("pending rows after faulted stage = %d (%v), want 0", pending, err)
		}
	})

	t.Run("faulted one-time binding fails closed", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		tok, status := rh.beginReauth(rh.password, "totp.enroll")
		if status != http.StatusOK || tok == "" {
			t.Fatalf("proof: status %d token %q", status, tok)
		}
		armsFaultTrigger(t, rh.h, "arms_setup_bind_fault", "arms_setup_bind_trig", "mfa_reauth_step_ups", "BEFORE UPDATE",
			"NEW.user_id = "+itoaInt(rh.userID)+" AND OLD.target_ref IS NULL")
		if rr := rh.setup(tok); rr.Code != http.StatusInternalServerError {
			t.Fatalf("setup with faulted binding = %d, want 500", rr.Code)
		}
		var target *string
		if err := rh.pool.QueryRow(context.Background(),
			`SELECT target_ref FROM mfa_reauth_step_ups WHERE user_id = $1`, rh.userID).Scan(&target); err != nil || target != nil {
			t.Fatalf("target_ref after faulted bind = %v (%v), want NULL (nothing half-bound)", target, err)
		}
	})

	t.Run("faulted setup commit leaves nothing staged or bound", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		tok, status := rh.beginReauth(rh.password, "totp.enroll")
		if status != http.StatusOK || tok == "" {
			t.Fatalf("proof: status %d token %q", status, tok)
		}
		armsDeferredCommitFault(t, rh.h, "arms_setup_commit_fault", "arms_setup_commit_trig", "totp_pending_enrollments", "AFTER INSERT",
			"NEW.user_id = "+itoaInt(rh.userID))
		if rr := rh.setup(tok); rr.Code != http.StatusInternalServerError {
			t.Fatalf("setup with faulted commit = %d, want 500", rr.Code)
		}
		var pending int
		var target *string
		if err := rh.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM totp_pending_enrollments WHERE user_id = $1`, rh.userID).Scan(&pending); err != nil || pending != 0 {
			t.Fatalf("pending rows after faulted commit = %d (%v), want 0", pending, err)
		}
		if err := rh.pool.QueryRow(context.Background(),
			`SELECT target_ref FROM mfa_reauth_step_ups WHERE user_id = $1`, rh.userID).Scan(&target); err != nil || target != nil {
			t.Fatalf("target_ref after faulted commit = %v (%v), want NULL (binding rolled back)", target, err)
		}
	})
}

// --- §1.7 mismatch-refusal cleanup arms (writeGrantGateRefusal /
// commitGrantMismatchRefusal) ---

func TestGrantGateRefusalFaultArms(t *testing.T) {
	// Shared driver: a C2 harness whose grant's operation does NOT match the
	// confirm arm's totp.enroll predicate — the §1.7 mismatch refusal deletes
	// the outstanding grant and COMMITS the refusal.
	confirmWithMismatchedGrant := func(t *testing.T, rh *reauthStepupHarness) *httptest.ResponseRecorder {
		t.Helper()
		// The seeded token differs from the confirm arm's declared totp.enroll
		// operation ONLY: the §1.7 mismatch (not a missing grant) is what
		// drives the refusal's in-tx cleanup DELETE.
		mismatchTok := rh.seedGrant("recovery.regenerate", nil)
		return rh.confirm("000000", mismatchTok, "00000000-0000-0000-0000-000000000000")
	}

	t.Run("faulted mismatch cleanup delete fails the confirm closed", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		armsFaultTrigger(t, rh.h, "arms_refusal_delete_fault", "arms_refusal_delete_trig", "mfa_reauth_step_ups", "BEFORE DELETE",
			"OLD.user_id = "+itoaInt(rh.userID))
		if rr := confirmWithMismatchedGrant(t, rh); rr.Code != http.StatusInternalServerError {
			t.Fatalf("confirm with faulted mismatch cleanup = %d, want 500", rr.Code)
		}
		// The mismatched grant SURVIVES: the faulted delete rolled back with
		// the whole refusal — cleanup is all-or-nothing.
		if n := countGrantsFor(t, rh.h, rh.userID); n != 1 {
			t.Fatalf("grant rows after faulted cleanup = %d, want 1 (the delete rolled back)", n)
		}
	})

	t.Run("faulted refusal audit fails the confirm closed", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		armsFaultTrigger(t, rh.h, "arms_refusal_audit_fault", "arms_refusal_audit_trig", "admin_audit_log", "BEFORE INSERT",
			"NEW.user_id = "+itoaInt(rh.userID)+" AND NEW.action = 'mfa_reauth_refused'")
		// The commitGrantMismatchRefusal path: the grant peek SUCCEEDS (bound
		// to enrollment E) but the STAGED row E is dead — the pending-lookup
		// mismatch's refusal audit is faulted, so nothing may commit.
		const deadEnrollment = "00000000-0000-0000-0000-00000000000e"
		tok := rh.seedGrant("totp.enroll", map[string]any{"target_ref": deadEnrollment})
		if rr := rh.confirm("000000", tok, deadEnrollment); rr.Code != http.StatusInternalServerError {
			t.Fatalf("confirm with faulted refusal audit = %d, want 500", rr.Code)
		}
		// The deletion never committed without its audit: the grant survives.
		if n := countGrantsFor(t, rh.h, rh.userID); n != 1 {
			t.Fatalf("grant rows after faulted refusal audit = %d, want 1", n)
		}
	})

	t.Run("faulted refusal commit fails the confirm closed", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		armsDeferredCommitFault(t, rh.h, "arms_refusal_commit_fault", "arms_refusal_commit_trig", "mfa_reauth_step_ups", "AFTER DELETE",
			"OLD.user_id = "+itoaInt(rh.userID))
		// Present the SEEDED grant's own token so the confirm's peek misses
		// ONLY on the operation member: the §1.7 mismatch really deletes the
		// outstanding grant before the faulted commit.
		mismatchTok := rh.seedGrant("recovery.regenerate", nil)
		rr := rh.confirm("000000", mismatchTok, "00000000-0000-0000-0000-000000000000")
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("confirm with faulted refusal commit = %d, want 500", rr.Code)
		}
		// The commit failed: the dead grant must NOT have been resurrected by
		// a partial rollback of the §1.7 deletion alone — the whole refusal
		// (delete + audit) rolled back.
		if n := countGrantsFor(t, rh.h, rh.userID); n != 1 {
			t.Fatalf("grant rows after faulted refusal commit = %d, want 1 (the whole refusal rolled back)", n)
		}
		if got := rh.reauthAuditCount("mfa_reauth_refused"); got != 0 {
			t.Fatalf("refusal audit rows after faulted commit = %d, want 0 (the audit rolled back)", got)
		}
	})
}

// --- TOTPConfirm guards + promotion arms ---

func TestTOTPConfirmGuardArms(t *testing.T) {
	rh := newReauthStepupHarness(t, "none")

	t.Run("unauthenticated confirm refused", func(t *testing.T) {
		if rr := rh.postJSON("/auth/totp/confirm", map[string]any{"code": "000000", "enrollment_id": "e"}, nil, rh.h.TOTPConfirm); rr.Code != http.StatusUnauthorized {
			t.Fatalf("confirm without claims = %d, want 401", rr.Code)
		}
	})
	t.Run("impersonated confirm refused", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/totp/confirm", strings.NewReader(`{"code":"000000","enrollment_id":"e"}`))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(ContextWithUser(req.Context(), armsImpersonated(rh.claims())))
		rr := httptest.NewRecorder()
		rh.h.TOTPConfirm(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("confirm with impersonated claims = %d, want 403", rr.Code)
		}
	})
	t.Run("malformed confirm body refused", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/totp/confirm", strings.NewReader("{not-json"))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(ContextWithUser(req.Context(), rh.claims()))
		rr := httptest.NewRecorder()
		rh.h.TOTPConfirm(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("confirm with malformed body = %d, want 400", rr.Code)
		}
	})
	t.Run("confirm without code or enrollment refused", func(t *testing.T) {
		if rr := rh.postJSON("/auth/totp/confirm", map[string]any{}, rh.claims(), rh.h.TOTPConfirm); rr.Code != http.StatusBadRequest {
			t.Fatalf("confirm without members = %d, want 400", rr.Code)
		}
	})
}

func TestTOTPConfirmProvingFactorNotLiveArm(t *testing.T) {
	// A totp-proof grant whose proving factor is ALREADY disabled: the confirm
	// consumes the grant and then the §1.1 full-tuple check refuses — the
	// staged row and the factor state stay untouched (tx rolls back).
	// Operation alignment: the account has NO totp factor, so proof, setup and
	// confirm all declare totp.enroll.
	rh := newReauthStepupHarness(t, "none")
	tok := rh.seedGrant("totp.enroll", map[string]any{"proof_method": "totp"})

	sr := rh.setup(tok)
	if sr.Code != http.StatusOK {
		t.Fatalf("setup = %d body %s, want 200", sr.Code, sr.Body.String())
	}
	_, enrollmentID := setupBody(t, sr)
	secret := provisioningSecret(t, sr)
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	cr := rh.confirm(code, tok, enrollmentID)
	if cr.Code != http.StatusForbidden {
		t.Fatalf("confirm with dead proving factor = %d body %s, want 403", cr.Code, cr.Body.String())
	}
	if totpEnabled(t, rh.h, rh.userID) {
		t.Fatal("confirm with a dead proving factor promoted the factor")
	}
	var pending int
	if err := rh.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM totp_pending_enrollments WHERE user_id = $1`, rh.userID).Scan(&pending); err != nil || pending != 1 {
		t.Fatalf("pending rows after refused confirm = %d (%v), want 1 (not consumed)", pending, err)
	}
	if n := countGrantsFor(t, rh.h, rh.userID); n != 1 {
		t.Fatalf("grant rows after refused confirm = %d, want 1 (the consumption rolled back)", n)
	}
}

func TestTOTPConfirmPromotionFaultArms(t *testing.T) {
	runConfirmToPromotion := func(t *testing.T) (*reauthStepupHarness, string, string, string) {
		t.Helper()
		rh := newReauthStepupHarness(t, "none")
		tok, status := rh.beginReauth(rh.password, "totp.enroll")
		if status != http.StatusOK || tok == "" {
			t.Fatalf("proof: status %d token %q", status, tok)
		}
		sr := rh.setup(tok)
		if sr.Code != http.StatusOK {
			t.Fatalf("setup = %d body %s, want 200", sr.Code, sr.Body.String())
		}
		_, enrollmentID := setupBody(t, sr)
		secret := provisioningSecret(t, sr)
		code, err := totp.GenerateCode(secret, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return rh, tok, enrollmentID, code
	}

	t.Run("faulted promotion update fails closed", func(t *testing.T) {
		rh, tok, enrollmentID, code := runConfirmToPromotion(t)
		armsFaultTrigger(t, rh.h, "arms_promote_fault", "arms_promote_trig", "users", "BEFORE UPDATE",
			"NEW.id = "+itoaInt(rh.userID)+" AND NEW.totp_enabled = TRUE AND COALESCE(OLD.totp_enabled, FALSE) = FALSE")
		if rr := rh.confirm(code, tok, enrollmentID); rr.Code != http.StatusInternalServerError {
			t.Fatalf("confirm with faulted promotion = %d, want 500", rr.Code)
		}
		if totpEnabled(t, rh.h, rh.userID) {
			t.Fatal("promotion activated under a faulted update")
		}
	})

	t.Run("faulted pending delete fails closed", func(t *testing.T) {
		rh, tok, enrollmentID, code := runConfirmToPromotion(t)
		armsFaultTrigger(t, rh.h, "arms_confirm_pending_fault", "arms_confirm_pending_trig", "totp_pending_enrollments", "BEFORE DELETE",
			"OLD.user_id = "+itoaInt(rh.userID))
		if rr := rh.confirm(code, tok, enrollmentID); rr.Code != http.StatusInternalServerError {
			t.Fatalf("confirm with faulted pending delete = %d, want 500", rr.Code)
		}
		var pending int
		if err := rh.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM totp_pending_enrollments WHERE user_id = $1`, rh.userID).Scan(&pending); err != nil || pending != 1 {
			t.Fatalf("pending rows after faulted delete = %d (%v), want 1 (rolled back)", pending, err)
		}
	})

	t.Run("faulted success audit fails closed", func(t *testing.T) {
		rh, tok, enrollmentID, code := runConfirmToPromotion(t)
		armsFaultTrigger(t, rh.h, "arms_confirm_audit_fault", "arms_confirm_audit_trig", "admin_audit_log", "BEFORE INSERT",
			"NEW.user_id = "+itoaInt(rh.userID)+" AND NEW.action = 'totp_confirmed'")
		if rr := rh.confirm(code, tok, enrollmentID); rr.Code != http.StatusInternalServerError {
			t.Fatalf("confirm with faulted audit = %d, want 500", rr.Code)
		}
		if totpEnabled(t, rh.h, rh.userID) {
			t.Fatal("promotion committed without its audit")
		}
	})

	t.Run("faulted confirm commit persists nothing", func(t *testing.T) {
		rh, tok, enrollmentID, code := runConfirmToPromotion(t)
		armsDeferredCommitFault(t, rh.h, "arms_confirm_commit_fault", "arms_confirm_commit_trig", "admin_audit_log", "AFTER INSERT",
			"NEW.user_id = "+itoaInt(rh.userID)+" AND NEW.action = 'totp_confirmed'")
		if rr := rh.confirm(code, tok, enrollmentID); rr.Code != http.StatusInternalServerError {
			t.Fatalf("confirm with faulted commit = %d, want 500", rr.Code)
		}
		if totpEnabled(t, rh.h, rh.userID) {
			t.Fatal("a faulted confirm commit activated the factor")
		}
		var pending int
		if err := rh.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM totp_pending_enrollments WHERE user_id = $1`, rh.userID).Scan(&pending); err != nil || pending != 1 {
			t.Fatalf("pending rows after faulted commit = %d (%v), want 1 (staged row intact)", pending, err)
		}
	})
}

// --- TOTPEnrollmentSetup arms (bootstrap grant) ---

func armsBootstrapFixture(t *testing.T, label string) (*AuthHandler, int64, string, *token.Claims) {
	t.Helper()
	pool := enrollmentHandlerPool(t)
	ensureEnrollmentLocalDomain(t, pool)
	email := fmt.Sprintf("arms-boot-%s-%d@example.test", label, time.Now().UnixNano())
	userID := seedLocalUser(t, pool, email)
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})
	mfaToken, err := h.jwt.IssueMFAPending(userID, email)
	if err != nil {
		t.Fatalf("issue mfa_token: %v", err)
	}
	seedBootstrapGrant(t, pool, h.jwt, mfaToken)
	claims, err := h.jwt.Validate(mfaToken)
	if err != nil {
		t.Fatalf("validate mfa_token: %v", err)
	}
	return h, userID, mfaToken, claims
}

func TestTOTPEnrollmentSetupGuardArms(t *testing.T) {
	t.Run("revoked pending jti answers the typed reauth_required", func(t *testing.T) {
		h, userID, mfaToken, claims := armsBootstrapFixture(t, "revoked")
		armsRevokeJTI(t, h, userID, claims.JTI)
		if rr := postEnrollmentJSON(t, "/auth/totp/enroll/setup", map[string]any{"mfa_token": mfaToken}, h.TOTPEnrollmentSetup); rr.Code != http.StatusForbidden {
			t.Fatalf("enrollment setup with revoked jti = %d body %s, want 403", rr.Code, rr.Body.String())
		}
	})

	t.Run("resume re-derives the SAME staged secret and enrollment", func(t *testing.T) {
		h, _, mfaToken, _ := armsBootstrapFixture(t, "resume")
		first := postEnrollmentJSON(t, "/auth/totp/enroll/setup", map[string]any{"mfa_token": mfaToken}, h.TOTPEnrollmentSetup)
		if first.Code != http.StatusOK {
			t.Fatalf("first setup = %d body %s, want 200", first.Code, first.Body.String())
		}
		second := postEnrollmentJSON(t, "/auth/totp/enroll/setup", map[string]any{"mfa_token": mfaToken}, h.TOTPEnrollmentSetup)
		if second.Code != http.StatusOK {
			t.Fatalf("resume setup = %d body %s, want 200", second.Code, second.Body.String())
		}
		_, firstID := setupBody(t, first)
		secondURI, secondID := setupBody(t, second)
		if secondID != firstID {
			t.Fatalf("resume staged a NEW enrollment %s, want the SAME %s", secondID, firstID)
		}
		if provisioningSecretFromURI(t, secondURI) != provisioningSecretFromURI(t, uriFromBody(t, first)) {
			t.Fatal("resume minted a second secret instead of re-deriving the SAME one")
		}
	})

	t.Run("bound grant with a dead staged row answers the 409", func(t *testing.T) {
		h, userID, mfaToken, _ := armsBootstrapFixture(t, "deadtgt")
		first := postEnrollmentJSON(t, "/auth/totp/enroll/setup", map[string]any{"mfa_token": mfaToken}, h.TOTPEnrollmentSetup)
		if first.Code != http.StatusOK {
			t.Fatalf("first setup = %d, want 200", first.Code)
		}
		if _, err := h.pool.Exec(context.Background(),
			`DELETE FROM totp_pending_enrollments WHERE user_id = $1`, userID); err != nil {
			t.Fatal(err)
		}
		second := postEnrollmentJSON(t, "/auth/totp/enroll/setup", map[string]any{"mfa_token": mfaToken}, h.TOTPEnrollmentSetup)
		if second.Code != http.StatusConflict || !strings.Contains(second.Body.String(), "proof_already_bound") {
			t.Fatalf("setup with dead staged row = %d body %s, want 409 proof_already_bound", second.Code, second.Body.String())
		}
	})

	t.Run("faulted bootstrap stage fails closed", func(t *testing.T) {
		h, userID, mfaToken, _ := armsBootstrapFixture(t, "stage")
		armsFaultTrigger(t, h, "arms_boot_stage_fault", "arms_boot_stage_trig", "totp_pending_enrollments", "BEFORE INSERT",
			"NEW.user_id = "+itoaInt(userID))
		if rr := postEnrollmentJSON(t, "/auth/totp/enroll/setup", map[string]any{"mfa_token": mfaToken}, h.TOTPEnrollmentSetup); rr.Code != http.StatusInternalServerError {
			t.Fatalf("bootstrap setup with faulted stage = %d, want 500", rr.Code)
		}
	})

	t.Run("faulted bootstrap binding fails closed", func(t *testing.T) {
		h, userID, mfaToken, _ := armsBootstrapFixture(t, "bind")
		armsFaultTrigger(t, h, "arms_boot_bind_fault", "arms_boot_bind_trig", "mfa_reauth_step_ups", "BEFORE UPDATE",
			"NEW.user_id = "+itoaInt(userID)+" AND OLD.target_ref IS NULL")
		if rr := postEnrollmentJSON(t, "/auth/totp/enroll/setup", map[string]any{"mfa_token": mfaToken}, h.TOTPEnrollmentSetup); rr.Code != http.StatusInternalServerError {
			t.Fatalf("bootstrap setup with faulted binding = %d, want 500", rr.Code)
		}
	})

	t.Run("faulted bootstrap setup commit stages nothing", func(t *testing.T) {
		h, userID, mfaToken, _ := armsBootstrapFixture(t, "commit")
		armsDeferredCommitFault(t, h, "arms_boot_commit_fault", "arms_boot_commit_trig", "totp_pending_enrollments", "AFTER INSERT",
			"NEW.user_id = "+itoaInt(userID))
		if rr := postEnrollmentJSON(t, "/auth/totp/enroll/setup", map[string]any{"mfa_token": mfaToken}, h.TOTPEnrollmentSetup); rr.Code != http.StatusInternalServerError {
			t.Fatalf("bootstrap setup with faulted commit = %d, want 500", rr.Code)
		}
		var pending int
		if err := h.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM totp_pending_enrollments WHERE user_id = $1`, userID).Scan(&pending); err != nil || pending != 0 {
			t.Fatalf("pending rows after faulted commit = %d (%v), want 0", pending, err)
		}
	})
}

func uriFromBody(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		ProvisioningURI string `json:"provisioning_uri"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.ProvisioningURI == "" {
		t.Fatalf("setup body %s (%v), want provisioning_uri", rec.Body.String(), err)
	}
	return body.ProvisioningURI
}

func provisioningSecretFromURI(t *testing.T, uri string) string {
	t.Helper()
	parsed := uri
	if i := strings.Index(uri, "secret="); i >= 0 {
		parsed = uri[i+7:]
		if j := strings.Index(parsed, "&"); j >= 0 {
			parsed = parsed[:j]
		}
		return parsed
	}
	t.Fatalf("uri %q carries no secret", uri)
	return ""
}

// --- TOTPEnrollmentConfirm arms (legacy + fenced paths) ---

func TestTOTPEnrollmentConfirmRequestArms(t *testing.T) {
	t.Run("missing code or enrollment refused", func(t *testing.T) {
		h, _, mfaToken, _ := armsBootstrapFixture(t, "req")
		if rr := postEnrollmentJSON(t, "/auth/totp/enroll/confirm", map[string]any{"mfa_token": mfaToken}, h.TOTPEnrollmentConfirm); rr.Code != http.StatusBadRequest {
			t.Fatalf("confirm without members = %d, want 400", rr.Code)
		}
		if rr := postEnrollmentJSON(t, "/auth/totp/enroll/confirm", map[string]any{"mfa_token": mfaToken, "code": "000000"}, h.TOTPEnrollmentConfirm); rr.Code != http.StatusBadRequest {
			t.Fatalf("confirm without enrollment = %d, want 400", rr.Code)
		}
	})

	t.Run("closed pool answers the 503 mint-fence posture", func(t *testing.T) {
		_, _, mfaToken, _ := armsBootstrapFixture(t, "closed")
		closed := enrollmentHandlerPool(t)
		ensureEnrollmentLocalDomain(t, closed)
		closed.Close()
		ch := NewAuthHandler(AuthHandlerConfig{Pool: closed, JWT: newTestJWT(), Logger: discardLogger()})
		rr := postEnrollmentJSON(t, "/auth/totp/enroll/confirm",
			map[string]any{"mfa_token": mfaToken, "code": "000000", "enrollment_id": "00000000-0000-0000-0000-000000000000"},
			ch.TOTPEnrollmentConfirm)
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("confirm with closed pool = %d, want 503", rr.Code)
		}
	})
}

func TestTOTPEnrollmentConfirmOutcomeArms(t *testing.T) {
	t.Run("wrong staged code answers 401 without promotion", func(t *testing.T) {
		h, pool, userID, mfaToken, _, enrollmentID := newBootstrapConfirmHarness(t, "arms-wrong")
		if rr := postEnrollmentJSON(t, "/auth/totp/enroll/confirm",
			map[string]any{"mfa_token": mfaToken, "code": "000000", "enrollment_id": enrollmentID}, h.TOTPEnrollmentConfirm); rr.Code != http.StatusUnauthorized {
			t.Fatalf("confirm with wrong code = %d body %s, want 401", rr.Code, rr.Body.String())
		}
		var enabled bool
		if err := pool.QueryRow(context.Background(),
			`SELECT COALESCE(totp_enabled, FALSE) FROM users WHERE id = $1`, userID).Scan(&enabled); err != nil || enabled {
			t.Fatalf("wrong code promoted the factor (%v)", err)
		}
	})

	t.Run("locked budget answers 429 without evaluation", func(t *testing.T) {
		h, pool, userID, mfaToken, _, enrollmentID := newBootstrapConfirmHarness(t, "arms-locked2")
		armsParkBudget(t, h, "totp_locked_until", "now() + interval '10 min'", userID)
		if rr := postEnrollmentJSON(t, "/auth/totp/enroll/confirm",
			map[string]any{"mfa_token": mfaToken, "code": "000000", "enrollment_id": enrollmentID}, h.TOTPEnrollmentConfirm); rr.Code != http.StatusTooManyRequests {
			t.Fatalf("locked confirm = %d body %s, want 429", rr.Code, rr.Body.String())
		}
		var enabled bool
		if err := pool.QueryRow(context.Background(),
			`SELECT COALESCE(totp_enabled, FALSE) FROM users WHERE id = $1`, userID).Scan(&enabled); err != nil || enabled {
			t.Fatalf("locked confirm promoted the factor (%v)", err)
		}
	})
}

func TestTOTPEnrollmentConfirmCommitFaultArm(t *testing.T) {
	h, pool, userID, mfaToken, stagedSecret, enrollmentID := newBootstrapConfirmHarness(t, "arms-commit")
	code, err := totp.GenerateCode(stagedSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// The legacy confirm path mints tokens INSIDE the confirm transaction: a
	// deferred fault on the token anchor INSERT fires at COMMIT — the answer
	// must be the 503 and NOTHING (factor, grant, anchor) may persist.
	armsDeferredCommitFault(t, h, "arms_enroll_commit_fault", "arms_enroll_commit_trig", "oauth_tokens", "AFTER INSERT",
		"NEW.user_id = "+itoaInt(userID))
	if rr := postEnrollmentJSON(t, "/auth/totp/enroll/confirm",
		map[string]any{"mfa_token": mfaToken, "code": code, "enrollment_id": enrollmentID}, h.TOTPEnrollmentConfirm); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("confirm with faulted commit = %d body %s, want 503", rr.Code, rr.Body.String())
	}
	var enabled bool
	var anchors int
	if err := pool.QueryRow(context.Background(),
		`SELECT COALESCE(totp_enabled, FALSE) FROM users WHERE id = $1`, userID).Scan(&enabled); err != nil || enabled {
		t.Fatalf("faulted commit promoted the factor (%v)", err)
	}
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM oauth_tokens WHERE user_id = $1`, userID).Scan(&anchors); err != nil || anchors != 0 {
		t.Fatalf("token anchors after faulted commit = %d (%v), want 0", anchors, err)
	}
	if n := countGrantsFor(t, h, userID); n != 1 {
		t.Fatalf("grant rows after faulted commit = %d, want 1 (the consumption rolled back)", n)
	}
}

// --- promoteBootstrapTOTPEnrollment internal arms ---

func TestPromoteBootstrapFailClosedArms(t *testing.T) {
	t.Run("person fence fault fails the promotion closed", func(t *testing.T) {
		h, _, userID, mfaToken, secret, enrollmentID := newBootstrapConfirmHarness(t, "arms-pf")
		code, err := totp.GenerateCode(secret, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		var original string
		if err := h.pool.QueryRow(context.Background(),
			`SELECT pg_get_functiondef('identity_auth_person_fence(bigint)'::regprocedure)`).Scan(&original); err != nil {
			t.Fatal(err)
		}
		if _, err := h.pool.Exec(context.Background(), fmt.Sprintf(`CREATE OR REPLACE FUNCTION identity_auth_person_fence(p_user_id BIGINT) RETURNS void
			LANGUAGE plpgsql AS $fn$
			BEGIN
			  IF p_user_id = %d THEN
			    RAISE EXCEPTION 'injected promotion fence failure';
			  END IF;
			  PERFORM pg_advisory_xact_lock(hashtextextended('identity-person:'||p_user_id::text, 0));
			END $fn$;`, userID)); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = h.pool.Exec(context.Background(), original)
		})
		if rr := postEnrollmentJSON(t, "/auth/totp/enroll/confirm",
			map[string]any{"mfa_token": mfaToken, "code": code, "enrollment_id": enrollmentID}, h.TOTPEnrollmentConfirm); rr.Code != http.StatusInternalServerError {
			t.Fatalf("promotion under fence fault = %d, want 500", rr.Code)
		}
		if n := countGrantsFor(t, h, userID); n != 1 {
			t.Fatalf("grant rows under fence fault = %d, want 1 (unconsumed)", n)
		}
	})

	t.Run("deleted user fails the promotion users fence", func(t *testing.T) {
		h, _, userID, mfaToken, _, enrollmentID := newBootstrapConfirmHarness(t, "arms-pdel")
		if _, err := h.pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID); err != nil {
			t.Fatal(err)
		}
		if rr := postEnrollmentJSON(t, "/auth/totp/enroll/confirm",
			map[string]any{"mfa_token": mfaToken, "code": "000000", "enrollment_id": enrollmentID}, h.TOTPEnrollmentConfirm); rr.Code != http.StatusInternalServerError {
			t.Fatalf("promotion for a deleted user = %d, want 500", rr.Code)
		}
	})

	t.Run("revoked pending jti refuses the promotion", func(t *testing.T) {
		h, _, userID, mfaToken, claims, enrollmentID := newBootstrapConfirmHarnessWithClaims(t, "arms-prev")
		armsRevokeJTI(t, h, userID, claims.JTI)
		if rr := postEnrollmentJSON(t, "/auth/totp/enroll/confirm",
			map[string]any{"mfa_token": mfaToken, "code": "000000", "enrollment_id": enrollmentID}, h.TOTPEnrollmentConfirm); rr.Code != http.StatusForbidden {
			t.Fatalf("promotion with revoked jti = %d body %s, want 403", rr.Code, rr.Body.String())
		}
	})

	t.Run("peek mismatch cleanup fault fails the promotion closed", func(t *testing.T) {
		h, _, userID, mfaToken, secret, _ := newBootstrapConfirmHarness(t, "arms-pmismatch")
		code, err := totp.GenerateCode(secret, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		armsFaultTrigger(t, h, "arms_promo_miss_fault", "arms_promo_miss_trig", "mfa_reauth_step_ups", "BEFORE DELETE",
			"OLD.user_id = "+itoaInt(userID))
		// A WRONG enrollment id mismatches the grant's bound target: the §1.7
		// cleanup DELETE is faulted — the promotion must answer 500.
		if rr := postEnrollmentJSON(t, "/auth/totp/enroll/confirm",
			map[string]any{"mfa_token": mfaToken, "code": code, "enrollment_id": "00000000-0000-0000-0000-000000000001"}, h.TOTPEnrollmentConfirm); rr.Code != http.StatusInternalServerError {
			t.Fatalf("promotion with faulted mismatch cleanup = %d, want 500", rr.Code)
		}
	})

	t.Run("binding mismatch cleanup fault fails the promotion closed", func(t *testing.T) {
		h, _, userID, mfaToken, secret, enrollmentID := newBootstrapConfirmHarness(t, "arms-pbind")
		code, err := totp.GenerateCode(secret, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		// The staged row dies after setup: the peek passes (bound target OK)
		// but the pending lookup misses — the §1.7 binding-mismatch cleanup
		// DELETE is faulted → 500.
		if _, err := h.pool.Exec(context.Background(),
			`DELETE FROM totp_pending_enrollments WHERE user_id = $1`, userID); err != nil {
			t.Fatal(err)
		}
		armsFaultTrigger(t, h, "arms_promo_bind_fault", "arms_promo_bind_trig", "mfa_reauth_step_ups", "BEFORE DELETE",
			"OLD.user_id = "+itoaInt(userID))
		if rr := postEnrollmentJSON(t, "/auth/totp/enroll/confirm",
			map[string]any{"mfa_token": mfaToken, "code": code, "enrollment_id": enrollmentID}, h.TOTPEnrollmentConfirm); rr.Code != http.StatusInternalServerError {
			t.Fatalf("promotion with faulted binding cleanup = %d, want 500", rr.Code)
		}
	})

	t.Run("faulted budget read fails the promotion closed", func(t *testing.T) {
		h, _, userID, mfaToken, secret, enrollmentID := newBootstrapConfirmHarness(t, "arms-pbudget")
		code, err := totp.GenerateCode(secret, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		armsParkBudget(t, h, "totp_locked_until", "'infinity'::timestamptz", userID)
		if rr := postEnrollmentJSON(t, "/auth/totp/enroll/confirm",
			map[string]any{"mfa_token": mfaToken, "code": code, "enrollment_id": enrollmentID}, h.TOTPEnrollmentConfirm); rr.Code != http.StatusInternalServerError {
			t.Fatalf("promotion with faulted budget read = %d, want 500", rr.Code)
		}
	})

	t.Run("faulted failure bookkeeping fails the promotion closed", func(t *testing.T) {
		h, _, userID, mfaToken, _, enrollmentID := newBootstrapConfirmHarness(t, "arms-pinc")
		armsFaultTrigger(t, h, "arms_promo_inc_fault", "arms_promo_inc_trig", "users", "BEFORE UPDATE",
			"NEW.id = "+itoaInt(userID)+" AND NEW.totp_failed_attempts = OLD.totp_failed_attempts + 1")
		if rr := postEnrollmentJSON(t, "/auth/totp/enroll/confirm",
			map[string]any{"mfa_token": mfaToken, "code": "000000", "enrollment_id": enrollmentID}, h.TOTPEnrollmentConfirm); rr.Code != http.StatusInternalServerError {
			t.Fatalf("promotion with faulted increment = %d, want 500", rr.Code)
		}
		at, lock := readTOTPBudget(t, h, userID)
		if at != 0 || lock != nil {
			t.Fatalf("budget after faulted increment = %d/%v, want exactly 0/nil", at, lock)
		}
	})

	t.Run("faulted grant consumption fails the promotion closed", func(t *testing.T) {
		h, _, userID, mfaToken, secret, enrollmentID := newBootstrapConfirmHarness(t, "arms-pconsume")
		code, err := totp.GenerateCode(secret, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		armsFaultTrigger(t, h, "arms_promo_consume_fault", "arms_promo_consume_trig", "mfa_reauth_step_ups", "BEFORE DELETE",
			"OLD.user_id = "+itoaInt(userID))
		if rr := postEnrollmentJSON(t, "/auth/totp/enroll/confirm",
			map[string]any{"mfa_token": mfaToken, "code": code, "enrollment_id": enrollmentID}, h.TOTPEnrollmentConfirm); rr.Code != http.StatusInternalServerError {
			t.Fatalf("promotion with faulted consume = %d, want 500", rr.Code)
		}
		if n := countGrantsFor(t, h, userID); n != 1 {
			t.Fatalf("grant rows after faulted consume = %d, want 1 (rolled back)", n)
		}
	})

	t.Run("dead proving credential refuses the promotion", func(t *testing.T) {
		// Seed the bootstrap grant with a webauthn_uv proof bound to a
		// credential id that does not exist: the §1.1 full-tuple consumption
		// refuses — the promotion never runs.
		h, pool, userID, mfaToken, secret, enrollmentID := newBootstrapConfirmHarness(t, "arms-pdead")
		if _, err := pool.Exec(context.Background(), `
			UPDATE mfa_reauth_step_ups
			   SET proof_method = 'webauthn_uv', proving_factor_id = $2
			 WHERE user_id = $1`, userID, []byte("arms-dead-credential")); err != nil {
			t.Fatal(err)
		}
		code, err := totp.GenerateCode(secret, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if rr := postEnrollmentJSON(t, "/auth/totp/enroll/confirm",
			map[string]any{"mfa_token": mfaToken, "code": code, "enrollment_id": enrollmentID}, h.TOTPEnrollmentConfirm); rr.Code != http.StatusForbidden {
			t.Fatalf("promotion with a dead proving credential = %d body %s, want 403", rr.Code, rr.Body.String())
		}
		var enabled bool
		if err := pool.QueryRow(context.Background(),
			`SELECT COALESCE(totp_enabled, FALSE) FROM users WHERE id = $1`, userID).Scan(&enabled); err != nil || enabled {
			t.Fatalf("dead-proof confirm promoted the factor (%v)", err)
		}
	})

	t.Run("faulted promotion update fails closed", func(t *testing.T) {
		h, _, userID, mfaToken, secret, enrollmentID := newBootstrapConfirmHarness(t, "arms-ppromo")
		code, err := totp.GenerateCode(secret, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		armsFaultTrigger(t, h, "arms_promo_upd_fault", "arms_promo_upd_trig", "users", "BEFORE UPDATE",
			"NEW.id = "+itoaInt(userID)+" AND NEW.totp_enabled = TRUE AND COALESCE(OLD.totp_enabled, FALSE) = FALSE")
		if rr := postEnrollmentJSON(t, "/auth/totp/enroll/confirm",
			map[string]any{"mfa_token": mfaToken, "code": code, "enrollment_id": enrollmentID}, h.TOTPEnrollmentConfirm); rr.Code != http.StatusInternalServerError {
			t.Fatalf("promotion with faulted update = %d, want 500", rr.Code)
		}
	})

	t.Run("faulted pending delete fails the promotion closed", func(t *testing.T) {
		h, _, userID, mfaToken, secret, enrollmentID := newBootstrapConfirmHarness(t, "arms-pdel2")
		code, err := totp.GenerateCode(secret, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		armsFaultTrigger(t, h, "arms_promo_pend_fault", "arms_promo_pend_trig", "totp_pending_enrollments", "BEFORE DELETE",
			"OLD.user_id = "+itoaInt(userID))
		if rr := postEnrollmentJSON(t, "/auth/totp/enroll/confirm",
			map[string]any{"mfa_token": mfaToken, "code": code, "enrollment_id": enrollmentID}, h.TOTPEnrollmentConfirm); rr.Code != http.StatusInternalServerError {
			t.Fatalf("promotion with faulted pending delete = %d, want 500", rr.Code)
		}
	})

	t.Run("faulted promotion audit fails closed", func(t *testing.T) {
		h, _, userID, mfaToken, secret, enrollmentID := newBootstrapConfirmHarness(t, "arms-paudit")
		code, err := totp.GenerateCode(secret, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		armsFaultTrigger(t, h, "arms_promo_audit_fault", "arms_promo_audit_trig", "admin_audit_log", "BEFORE INSERT",
			"NEW.user_id = "+itoaInt(userID)+" AND NEW.action = 'totp_confirmed'")
		if rr := postEnrollmentJSON(t, "/auth/totp/enroll/confirm",
			map[string]any{"mfa_token": mfaToken, "code": code, "enrollment_id": enrollmentID}, h.TOTPEnrollmentConfirm); rr.Code != http.StatusInternalServerError {
			t.Fatalf("promotion with faulted audit = %d, want 500", rr.Code)
		}
		if totpEnabled(t, h, userID) {
			t.Fatal("promotion committed without its audit")
		}
	})
}

// newBootstrapConfirmHarnessWithClaims is newBootstrapConfirmHarness plus the
// parsed mfa_token claims (the pending JTI the grant binds).
func newBootstrapConfirmHarnessWithClaims(t *testing.T, label string) (*AuthHandler, *pgxpool.Pool, int64, string, *token.Claims, string) {
	t.Helper()
	h, pool, userID, mfaToken, _, enrollmentID := newBootstrapConfirmHarness(t, label)
	claims, err := h.jwt.Validate(mfaToken)
	if err != nil {
		t.Fatalf("validate mfa_token: %v", err)
	}
	return h, pool, userID, mfaToken, claims, enrollmentID
}

// --- mfa_reauth.go arms ---

func TestMFAReauthFailClosedArms(t *testing.T) {
	t.Run("person fence fault fails the re-auth closed", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		var original string
		if err := rh.pool.QueryRow(context.Background(),
			`SELECT pg_get_functiondef('identity_auth_person_fence(bigint)'::regprocedure)`).Scan(&original); err != nil {
			t.Fatal(err)
		}
		if _, err := rh.pool.Exec(context.Background(), fmt.Sprintf(`CREATE OR REPLACE FUNCTION identity_auth_person_fence(p_user_id BIGINT) RETURNS void
			LANGUAGE plpgsql AS $fn$
			BEGIN
			  IF p_user_id = %d THEN
			    RAISE EXCEPTION 'injected reauth fence failure';
			  END IF;
			  PERFORM pg_advisory_xact_lock(hashtextextended('identity-person:'||p_user_id::text, 0));
			END $fn$;`, rh.userID)); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = rh.pool.Exec(context.Background(), original)
		})
		rec := rh.postJSON(MFAReauthChallengePath,
			map[string]any{"password": rh.password, "operation": "recovery.regenerate"}, rh.claims(), rh.h.MFAReauthBegin)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("re-auth under fence fault = %d, want 500", rec.Code)
		}
		if n := countGrantsFor(t, rh.h, rh.userID); n != 0 {
			t.Fatalf("grant rows under fence fault = %d, want 0", n)
		}
	})

	t.Run("deleted user fails the re-auth users fence", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		if _, err := rh.pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, rh.userID); err != nil {
			t.Fatal(err)
		}
		rec := rh.postJSON(MFAReauthChallengePath,
			map[string]any{"password": rh.password, "operation": "recovery.regenerate"}, rh.claims(), rh.h.MFAReauthBegin)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("re-auth for a deleted user = %d, want 500", rec.Code)
		}
	})

	t.Run("revoked jti answers the typed reauth_required", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		armsRevokeJTI(t, rh.h, rh.userID, rh.jti)
		rec := rh.postJSON(MFAReauthChallengePath,
			map[string]any{"password": rh.password, "operation": "recovery.regenerate"}, rh.claims(), rh.h.MFAReauthBegin)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), ReauthRequiredCode) {
			t.Fatalf("re-auth with revoked jti = %d body %s, want 403", rec.Code, rec.Body.String())
		}
		if n := countGrantsFor(t, rh.h, rh.userID); n != 0 {
			t.Fatalf("grant rows after revoked re-auth = %d, want 0", n)
		}
	})

	t.Run("faulted password budget read fails closed", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		armsParkBudget(t, rh.h, "possession_password_locked_until", "'infinity'::timestamptz", rh.userID)
		rec := rh.postJSON(MFAReauthChallengePath,
			map[string]any{"password": rh.password, "operation": "recovery.regenerate"}, rh.claims(), rh.h.MFAReauthBegin)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("re-auth with faulted budget read = %d, want 500", rec.Code)
		}
	})

	t.Run("locked password budget answers 429 without increment", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		armsParkBudget(t, rh.h, "possession_password_locked_until", "now() + interval '10 min'", rh.userID)
		rec := rh.postJSON(MFAReauthChallengePath,
			map[string]any{"password": "wrong-password", "operation": "recovery.regenerate"}, rh.claims(), rh.h.MFAReauthBegin)
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("re-auth under lock = %d, want 429", rec.Code)
		}
		var attempts int
		if err := rh.pool.QueryRow(context.Background(),
			`SELECT COALESCE(possession_password_failed_attempts, 0) FROM users WHERE id = $1`, rh.userID).Scan(&attempts); err != nil || attempts != 0 {
			t.Fatalf("locked refusal moved the counter to %d (%v), want 0", attempts, err)
		}
	})

	t.Run("faulted failure increment fails closed", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		armsFaultTrigger(t, rh.h, "arms_reauth_inc_fault", "arms_reauth_inc_trig", "users", "BEFORE UPDATE",
			"NEW.id = "+itoaInt(rh.userID)+" AND NEW.possession_password_failed_attempts = OLD.possession_password_failed_attempts + 1")
		rec := rh.postJSON(MFAReauthChallengePath,
			map[string]any{"password": "wrong-password", "operation": "recovery.regenerate"}, rh.claims(), rh.h.MFAReauthBegin)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("re-auth with faulted increment = %d, want 500", rec.Code)
		}
		var attempts int
		if err := rh.pool.QueryRow(context.Background(),
			`SELECT COALESCE(possession_password_failed_attempts, 0) FROM users WHERE id = $1`, rh.userID).Scan(&attempts); err != nil || attempts != 0 {
			t.Fatalf("counter after faulted increment = %d (%v), want 0 (rolled back)", attempts, err)
		}
	})

	t.Run("faulted refusal commit fails closed", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		armsDeferredCommitFault(t, rh.h, "arms_reauth_refusal_commit_fault", "arms_reauth_refusal_commit_trig", "users", "AFTER UPDATE",
			"NEW.id = "+itoaInt(rh.userID)+" AND NEW.possession_password_failed_attempts = OLD.possession_password_failed_attempts + 1")
		rec := rh.postJSON(MFAReauthChallengePath,
			map[string]any{"password": "wrong-password", "operation": "recovery.regenerate"}, rh.claims(), rh.h.MFAReauthBegin)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("re-auth with faulted refusal commit = %d, want 500", rec.Code)
		}
		var attempts int
		if err := rh.pool.QueryRow(context.Background(),
			`SELECT COALESCE(possession_password_failed_attempts, 0) FROM users WHERE id = $1`, rh.userID).Scan(&attempts); err != nil || attempts != 0 {
			t.Fatalf("counter after faulted refusal commit = %d (%v), want 0 (the increment rolled back)", attempts, err)
		}
		if got := rh.reauthAuditCount("mfa_reauth_refused"); got != 0 {
			t.Fatalf("refusal audits after faulted commit = %d, want 0", got)
		}
	})

	t.Run("faulted budget reset fails the issuance closed", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		if _, err := rh.pool.Exec(context.Background(),
			`UPDATE users SET possession_password_failed_attempts = 2 WHERE id = $1`, rh.userID); err != nil {
			t.Fatal(err)
		}
		armsFaultTrigger(t, rh.h, "arms_reauth_reset_fault", "arms_reauth_reset_trig", "users", "BEFORE UPDATE",
			"NEW.id = "+itoaInt(rh.userID)+" AND NEW.possession_password_failed_attempts = 0 AND OLD.possession_password_failed_attempts <> 0")
		rec := rh.postJSON(MFAReauthChallengePath,
			map[string]any{"password": rh.password, "operation": "recovery.regenerate"}, rh.claims(), rh.h.MFAReauthBegin)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("re-auth with faulted reset = %d, want 500", rec.Code)
		}
		var attempts int
		if err := rh.pool.QueryRow(context.Background(),
			`SELECT COALESCE(possession_password_failed_attempts, 0) FROM users WHERE id = $1`, rh.userID).Scan(&attempts); err != nil || attempts != 2 {
			t.Fatalf("counter after faulted reset = %d (%v), want 2 (nothing half-issued)", attempts, err)
		}
	})

	t.Run("faulted issuance commit issues nothing", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		armsDeferredCommitFault(t, rh.h, "arms_reauth_commit_fault", "arms_reauth_commit_trig", "mfa_reauth_step_ups", "AFTER INSERT",
			"NEW.user_id = "+itoaInt(rh.userID))
		rec := rh.postJSON(MFAReauthChallengePath,
			map[string]any{"password": rh.password, "operation": "recovery.regenerate"}, rh.claims(), rh.h.MFAReauthBegin)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("re-auth with faulted commit = %d, want 500", rec.Code)
		}
		if n := countGrantsFor(t, rh.h, rh.userID); n != 0 {
			t.Fatalf("grant rows after faulted commit = %d, want 0", n)
		}
	})
}

func TestRequirePossessionGrantArms(t *testing.T) {
	t.Run("reauthTokenFromBodyBytes ignores unparseable bodies", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/backup-codes/generate", nil)
		if got := reauthTokenFromBodyBytes(req, []byte("{not-json")); got != "" {
			t.Fatalf("reauthTokenFromBodyBytes(garbage) = %q, want empty", got)
		}
	})

	t.Run("gate generic failure answers 500 at the gated arm", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		tok := rh.seedGrant("recovery.regenerate", nil)
		// The single-use consumption DELETE is faulted: the gate must fail
		// CLOSED with 500 — never fall through to an ungated arm.
		armsFaultTrigger(t, rh.h, "arms_gate_consume_fault", "arms_gate_consume_trig", "mfa_reauth_step_ups", "BEFORE DELETE",
			"OLD.user_id = "+itoaInt(rh.userID))
		rec := rh.generate(tok)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("gated generate with faulted consume = %d, want 500", rec.Code)
		}
		if n := countGrantsFor(t, rh.h, rh.userID); n != 1 {
			t.Fatalf("grant rows after faulted consume = %d, want 1 (rolled back)", n)
		}
		var codes int
		if err := rh.pool.QueryRow(context.Background(),
			`SELECT COALESCE(array_length(totp_backup_codes_enc, 1), 0) FROM users WHERE id = $1`, rh.userID).Scan(&codes); err != nil || codes != 0 {
			t.Fatalf("backup codes after faulted consume = %d (%v), want 0 (the mutation never ran)", codes, err)
		}
	})

	t.Run("proving factor no longer live refuses the gated arm", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "totp")
		tok := rh.seedGrant("recovery.regenerate", map[string]any{"proof_method": "totp"})
		if _, err := rh.pool.Exec(context.Background(),
			`UPDATE users SET totp_enabled = FALSE WHERE id = $1`, rh.userID); err != nil {
			t.Fatal(err)
		}
		rec := rh.generate(tok)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), ReauthRequiredCode) {
			t.Fatalf("gated generate with dead proving factor = %d body %s, want 403", rec.Code, rec.Body.String())
		}
		if n := countGrantsFor(t, rh.h, rh.userID); n != 1 {
			t.Fatalf("grant rows after dead-proof generate = %d, want 1 (the refusal never burns the proof)", n)
		}
	})

	t.Run("mismatch refusal commit fault answers 500", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		rh.seedGrant("totp.enroll", nil) // the gated arm declares recovery.regenerate → mismatch
		armsDeferredCommitFault(t, rh.h, "arms_gate_mismatch_commit_fault", "arms_gate_mismatch_commit_trig", "mfa_reauth_step_ups", "AFTER DELETE",
			"OLD.user_id = "+itoaInt(rh.userID))
		rec := rh.generate("a-mismatched-token")
		if rec == nil {
			t.Fatal("no response")
		}
		// The mismatch deletes the outstanding grant in-tx; the faulted commit
		// must roll the deletion back — the grant survives.
		if n := countGrantsFor(t, rh.h, rh.userID); n != 1 {
			t.Fatalf("grant rows after faulted mismatch commit = %d, want 1 (the §1.7 delete rolled back)", n)
		}
	})
}

// --- mfa.go (gated backup-code regeneration) arms ---

func TestGenerateBackupCodesFaultArms(t *testing.T) {
	t.Run("faulted generation bump fails closed", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		tok, _ := rh.beginReauth(rh.password, "recovery.regenerate")
		armsFaultTrigger(t, rh.h, "arms_codes_bump_fault", "arms_codes_bump_trig", "users", "BEFORE UPDATE",
			"NEW.id = "+itoaInt(rh.userID)+" AND NEW.factor_generation = OLD.factor_generation + 1")
		if rec := rh.generate(tok); rec.Code != http.StatusInternalServerError {
			t.Fatalf("generate with faulted bump = %d, want 500", rec.Code)
		}
		if n := countGrantsFor(t, rh.h, rh.userID); n != 1 {
			t.Fatalf("grant rows after faulted bump = %d, want 1 (consumption rolled back)", n)
		}
	})

	t.Run("faulted audit fails closed", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		tok, _ := rh.beginReauth(rh.password, "recovery.regenerate")
		armsFaultTrigger(t, rh.h, "arms_codes_audit_fault", "arms_codes_audit_trig", "admin_audit_log", "BEFORE INSERT",
			"NEW.user_id = "+itoaInt(rh.userID)+" AND NEW.action = 'backup_codes_regenerated'")
		if rec := rh.generate(tok); rec.Code != http.StatusInternalServerError {
			t.Fatalf("generate with faulted audit = %d, want 500", rec.Code)
		}
		if n := countGrantsFor(t, rh.h, rh.userID); n != 1 {
			t.Fatalf("grant rows after faulted audit = %d, want 1 (rolled back)", n)
		}
	})

	t.Run("faulted commit stores no codes", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		tok, _ := rh.beginReauth(rh.password, "recovery.regenerate")
		armsDeferredCommitFault(t, rh.h, "arms_codes_commit_fault", "arms_codes_commit_trig", "admin_audit_log", "AFTER INSERT",
			"NEW.user_id = "+itoaInt(rh.userID)+" AND NEW.action = 'backup_codes_regenerated'")
		if rec := rh.generate(tok); rec.Code != http.StatusInternalServerError {
			t.Fatalf("generate with faulted commit = %d, want 500", rec.Code)
		}
		_, codeCount := rh.factorState()
		if codeCount != 0 {
			t.Fatalf("backup codes after faulted commit = %d, want 0 (the write rolled back)", codeCount)
		}
	})
}

// --- device.go arms ---

// armsNativeDeviceKey mints an uncompressed P-256 public key in hex (the
// native device registration payload shape).
func armsNativeDeviceKey(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("device key: %v", err)
	}
	raw := elliptic.Marshal(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y)
	return hex.EncodeToString(raw)
}

func armsPostDeviceRegister(h *AuthHandler, payload map[string]any, claims *token.Claims) *httptest.ResponseRecorder {
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/auth/devices/register", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	if claims != nil {
		req = req.WithContext(ContextWithUser(req.Context(), claims))
	}
	rr := httptest.NewRecorder()
	h.DeviceRegister(rr, req)
	return rr
}

func TestDeviceRegisterArms(t *testing.T) {
	newNativeFixture := func(t *testing.T) (*reauthStepupHarness, string) {
		t.Helper()
		// A C1 account proves at the POSSESSION endpoint (the password path
		// is refused for C1) — the proof mints the device.register.native
		// grant the native registration consumes.
		h := newPossessionHarness(t)
		userID, claims := newPossessionUserWithEmail(t, h, "arms-device", true)
		seedEnabledTOTP(t, h, userID)
		tok := matrixProof(t, h, claims, "device.register.native")
		rh := &reauthStepupHarness{t: t, pool: h.pool, userID: userID, jti: claims.JTI, password: "x", h: h}
		return rh, tok
	}
	payload := func(tok string) map[string]any {
		return map[string]any{
			"provider":          "apns",
			"push_token":        "arms-native-push-token",
			"device_public_key": armsNativeDeviceKey(t),
			"device_name":       "arms-test-device",
			"reauth_token":      tok,
		}
	}

	t.Run("gated native registration consumes the proof and registers", func(t *testing.T) {
		rh, tok := newNativeFixture(t)
		if rr := armsPostDeviceRegister(rh.h, payload(tok), rh.claims()); rr.Code != http.StatusNoContent {
			t.Fatalf("native device register = %d body %s, want 204", rr.Code, rr.Body.String())
		}
		if n := countGrantsFor(t, rh.h, rh.userID); n != 0 {
			t.Fatalf("grant rows after native register = %d, want 0 (consumed)", n)
		}
		var devices int
		if err := rh.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM push_devices WHERE user_id = $1 AND push_provider = 'apns'`, rh.userID).Scan(&devices); err != nil || devices != 1 {
			t.Fatalf("native devices = %d (%v), want 1", devices, err)
		}
		if got := readFactorGeneration(t, rh.h, rh.userID); got == 0 {
			t.Fatal("native register did not bump the factor generation (§1.8)")
		}
	})

	t.Run("impersonated native registration refused", func(t *testing.T) {
		rh, tok := newNativeFixture(t)
		if rr := armsPostDeviceRegister(rh.h, payload(tok), armsImpersonated(rh.claims())); rr.Code != http.StatusForbidden {
			t.Fatalf("native register with impersonated claims = %d, want 403", rr.Code)
		}
		var devices int
		if err := rh.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM push_devices WHERE user_id = $1 AND push_provider = 'apns'`, rh.userID).Scan(&devices); err != nil || devices != 0 {
			t.Fatalf("devices after impersonated register = %d (%v), want 0", devices, err)
		}
	})

	t.Run("faulted generation bump rolls the registration back", func(t *testing.T) {
		rh, tok := newNativeFixture(t)
		G := readFactorGeneration(t, rh.h, rh.userID)
		armsFaultTrigger(t, rh.h, "arms_device_bump_fault", "arms_device_bump_trig", "users", "BEFORE UPDATE",
			"NEW.id = "+itoaInt(rh.userID)+" AND NEW.factor_generation = OLD.factor_generation + 1")
		if rr := armsPostDeviceRegister(rh.h, payload(tok), rh.claims()); rr.Code != http.StatusInternalServerError {
			t.Fatalf("native register with faulted bump = %d, want 500", rr.Code)
		}
		if got := readFactorGeneration(t, rh.h, rh.userID); got != G {
			t.Fatalf("generation after faulted register = %d, want %d (rolled back)", got, G)
		}
		var devices int
		if err := rh.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM push_devices WHERE user_id = $1 AND push_provider = 'apns'`, rh.userID).Scan(&devices); err != nil || devices != 0 {
			t.Fatalf("devices after faulted register = %d (%v), want 0 (the insert rides the fenced tx)", devices, err)
		}
	})

	t.Run("faulted audit rolls the registration back", func(t *testing.T) {
		rh, tok := newNativeFixture(t)
		armsFaultTrigger(t, rh.h, "arms_device_audit_fault", "arms_device_audit_trig", "admin_audit_log", "BEFORE INSERT",
			"NEW.user_id = "+itoaInt(rh.userID)+" AND NEW.action = 'device_registered'")
		if rr := armsPostDeviceRegister(rh.h, payload(tok), rh.claims()); rr.Code != http.StatusInternalServerError {
			t.Fatalf("native register with faulted audit = %d, want 500", rr.Code)
		}
		var devices int
		if err := rh.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM push_devices WHERE user_id = $1 AND push_provider = 'apns'`, rh.userID).Scan(&devices); err != nil || devices != 0 {
			t.Fatalf("devices after faulted audit = %d (%v), want 0", devices, err)
		}
	})

	t.Run("faulted commit registers nothing", func(t *testing.T) {
		rh, tok := newNativeFixture(t)
		armsDeferredCommitFault(t, rh.h, "arms_device_commit_fault", "arms_device_commit_trig", "admin_audit_log", "AFTER INSERT",
			"NEW.user_id = "+itoaInt(rh.userID)+" AND NEW.action = 'device_registered'")
		if rr := armsPostDeviceRegister(rh.h, payload(tok), rh.claims()); rr.Code != http.StatusInternalServerError {
			t.Fatalf("native register with faulted commit = %d, want 500", rr.Code)
		}
		var devices int
		if err := rh.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM push_devices WHERE user_id = $1 AND push_provider = 'apns'`, rh.userID).Scan(&devices); err != nil || devices != 0 {
			t.Fatalf("devices after faulted commit = %d (%v), want 0", devices, err)
		}
		if n := countGrantsFor(t, rh.h, rh.userID); n != 1 {
			t.Fatalf("grant rows after faulted commit = %d, want 1 (consumption rolled back)", n)
		}
	})
}

// --- auth.go bootstrap grant mint arms ---

func TestIssueMFAPendingBootstrapFailClosedArms(t *testing.T) {
	t.Run("closed pool fails the bootstrap tx", func(t *testing.T) {
		pool := enrollmentHandlerPool(t)
		ensureEnrollmentLocalDomain(t, pool)
		userID := seedLocalUser(t, pool, fmt.Sprintf("arms-bootx-%d@example.test", time.Now().UnixNano()))
		h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})
		closed := enrollmentHandlerPool(t)
		closed.Close()
		_, err := h.issueMFAPendingBootstrap(context.Background(), closed, userID, "arms-bootx@example.test", CompletionRequest{})
		if err == nil || !strings.Contains(err.Error(), "bootstrap tx begin") {
			t.Fatalf("bootstrap with closed pool = %v, want the wrapped tx-begin error", err)
		}
	})

	t.Run("stale identity fence fails the bootstrap closed", func(t *testing.T) {
		pool := enrollmentHandlerPool(t)
		ensureEnrollmentLocalDomain(t, pool)
		userID := seedLocalUser(t, pool, fmt.Sprintf("arms-bootf-%d@example.test", time.Now().UnixNano()))
		h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})
		_, err := h.issueMFAPendingBootstrap(context.Background(), pool, userID, "arms-bootf@example.test", CompletionRequest{
			Metadata: CompletionMetadata{IdentityFence: &jwtutil.IdentityFenceClaim{}},
		})
		if err == nil || !strings.Contains(err.Error(), "bootstrap identity fence") {
			t.Fatalf("bootstrap with invalid identity fence = %v, want the wrapped fence error", err)
		}
	})

	t.Run("stale credential fence fails the bootstrap closed", func(t *testing.T) {
		pool := enrollmentHandlerPool(t)
		ensureEnrollmentLocalDomain(t, pool)
		userID := seedLocalUser(t, pool, fmt.Sprintf("arms-bootc-%d@example.test", time.Now().UnixNano()))
		h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})
		_, err := h.issueMFAPendingBootstrap(context.Background(), pool, userID, "arms-bootc@example.test", CompletionRequest{
			Metadata: CompletionMetadata{CredentialFence: "arms-stale-credential-fence"},
		})
		if err == nil || !strings.Contains(err.Error(), "bootstrap credential fence") {
			t.Fatalf("bootstrap with stale credential fence = %v, want the wrapped fence error", err)
		}
	})

	t.Run("faulted bootstrap commit issues no token", func(t *testing.T) {
		pool := enrollmentHandlerPool(t)
		ensureEnrollmentLocalDomain(t, pool)
		userID := seedLocalUser(t, pool, fmt.Sprintf("arms-bootm-%d@example.test", time.Now().UnixNano()))
		h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})
		// A C2 factor (push) routes the bootstrap into the password-grant
		// branch whose INSERT the deferred fault fires on at COMMIT.
		if _, err := pool.Exec(context.Background(),
			`UPDATE users SET push_mfa_enabled = TRUE WHERE id = $1`, userID); err != nil {
			t.Fatal(err)
		}
		armsDeferredCommitFault(t, h, "arms_boot_mint_commit_fault", "arms_boot_mint_commit_trig", "mfa_reauth_step_ups", "AFTER INSERT",
			"NEW.user_id = "+itoaInt(userID))
		tokenStr, err := h.issueMFAPendingBootstrap(context.Background(), pool, userID, "arms-bootm@example.test", CompletionRequest{})
		if err == nil || !strings.Contains(err.Error(), "bootstrap commit") {
			t.Fatalf("bootstrap with faulted commit = %v, want the wrapped commit error", err)
		}
		if tokenStr != "" {
			t.Fatal("a faulted bootstrap commit returned a token")
		}
		var grants int
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM mfa_reauth_step_ups WHERE user_id = $1`, userID).Scan(&grants); err != nil || grants != 0 {
			t.Fatalf("grant rows after faulted bootstrap = %d (%v), want 0", grants, err)
		}
	})
}

// --- session.go + totp_removal.go impersonation arms ---

func TestSessionTokenArms(t *testing.T) {
	h := newPossessionHarness(t)
	userID, claims := newPossessionUser(t, h, "arms-sess", true)

	t.Run("non-access token type is refused with the typed 403", func(t *testing.T) {
		pending, err := h.jwt.IssueMFAPending(userID, claims.Email)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet, "/auth/session/token", nil)
		req.Header.Set("Authorization", "Bearer "+pending)
		rr := httptest.NewRecorder()
		h.SessionToken(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("session token with a pending-type bearer = %d body %s, want 403", rr.Code, rr.Body.String())
		}
	})

	t.Run("garbage bearer is refused with 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/session/token", nil)
		req.Header.Set("Authorization", "Bearer not-a-token")
		rr := httptest.NewRecorder()
		h.SessionToken(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("session token with garbage bearer = %d, want 401", rr.Code)
		}
	})
}

func TestTOTPRemovalImpersonationArms(t *testing.T) {
	rh := newReauthStepupHarness(t, "totp")

	t.Run("impersonated removal begin refused", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/totp/remove/begin",
			strings.NewReader(`{"password":"correct-horse-battery","code":"000000"}`))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(ContextWithUser(req.Context(), armsImpersonated(rh.claims())))
		rr := httptest.NewRecorder()
		rh.h.TOTPRemovalBegin(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("removal begin with impersonated claims = %d, want 403", rr.Code)
		}
	})

	t.Run("impersonated removal confirm refused", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/totp/remove",
			strings.NewReader(`{"step_up_token":"x","confirm":"totp"}`))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(ContextWithUser(req.Context(), armsImpersonated(rh.claims())))
		rr := httptest.NewRecorder()
		rh.h.TOTPRemovalConfirm(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("removal confirm with impersonated claims = %d, want 403", rr.Code)
		}
	})
}

var _ = errors.New
