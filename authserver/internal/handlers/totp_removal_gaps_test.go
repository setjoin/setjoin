package handlers

// Gap coverage for the TOTP removal HTTP surface (totp_removal.go): the arms
// the lifecycle tests do not reach — the unauthenticated 401s, the
// missing-credential 400, the not-enabled 409s, the lockout 429, and the
// internal-error 500 arms. Every refusal must keep the factor intact and be
// audited where the contract says so.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/authserver/internal/authn"
)

// TestTOTPRemoval_NoClaimsUnauthorized: both endpoints refuse a request with
// no authenticated claims before any body parsing (the middleware normally
// guards this; the handler's own mustUser is the defense-in-depth seam).
func TestTOTPRemoval_NoClaimsUnauthorized(t *testing.T) {
	rh := newRemovalHarness(t, []string{"rec-gaps-1"})

	begin := postRemoval(t, "/auth/totp/remove/begin",
		map[string]any{"password": "x", "code": "y"}, nil, rh.beginH)
	if begin.Code != http.StatusUnauthorized {
		t.Fatalf("begin without claims status = %d, want 401", begin.Code)
	}
	confirm := postRemoval(t, "/auth/totp/remove",
		map[string]any{"step_up_token": "x", "confirm": "REMOVE"}, nil, rh.confirmH)
	if confirm.Code != http.StatusUnauthorized {
		t.Fatalf("confirm without claims status = %d, want 401", confirm.Code)
	}
	rh.factorIntact()
}

// TestTOTPRemoval_BeginRequiresPasswordAndCode: an authenticated request
// missing either credential is a 400 refusal AND a refusal audit row — it is
// still a de-enrollment attempt.
func TestTOTPRemoval_BeginRequiresPasswordAndCode(t *testing.T) {
	rh := newRemovalHarness(t, []string{"rec-gaps-2"})

	before := removalAuditCount(t, rh.pool, rh.userID, "totp_removal_step_up_refused")

	noPassword := postRemoval(t, "/auth/totp/remove/begin",
		map[string]any{"password": "", "code": "000000"},
		removalClaims(rh.userID, rh.jti), rh.beginH)
	if noPassword.Code != http.StatusBadRequest {
		t.Fatalf("missing password status = %d body %s, want 400", noPassword.Code, noPassword.Body.String())
	}
	noCode := postRemoval(t, "/auth/totp/remove/begin",
		map[string]any{"password": "correct-horse-battery", "code": ""},
		removalClaims(rh.userID, rh.jti), rh.beginH)
	if noCode.Code != http.StatusBadRequest {
		t.Fatalf("missing code status = %d body %s, want 400", noCode.Code, noCode.Body.String())
	}

	if got := removalAuditCount(t, rh.pool, rh.userID, "totp_removal_step_up_refused"); got != before+2 {
		t.Fatalf("refusal audit rows = %d, want %d (both missing-credential attempts audited)", got, before+2)
	}
	rh.factorIntact()
}

// TestTOTPRemoval_BeginNotEnabledConflict: a user without an active factor
// gets the 409 conflict, not a code check.
func TestTOTPRemoval_BeginNotEnabledConflict(t *testing.T) {
	pool := enrollmentHandlerPool(t)
	ensureEnrollmentLocalDomain(t, pool)
	email := "totp-remove-notenabled@example.test"
	userID := seedRemovalUser(t, pool, email, "correct-horse-battery", false, nil)
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})

	begin := postRemoval(t, "/auth/totp/remove/begin",
		map[string]any{"password": "correct-horse-battery", "code": "000000"},
		removalClaims(userID, "sess-notenabled"), h.TOTPRemovalBegin)
	if begin.Code != http.StatusConflict {
		t.Fatalf("begin without factor status = %d body %s, want 409", begin.Code, begin.Body.String())
	}
	if got := removalAuditCount(t, pool, userID, "totp_removal_step_up_refused"); got != 1 {
		t.Fatalf("refusal audit rows = %d, want 1", got)
	}
}

// removalFactorIntactNoCodes asserts the factor itself survives (variant of
// removalHarness.factorIntact for fixtures seeded without recovery codes).
func removalFactorIntactNoCodes(t *testing.T, pool *pgxpool.Pool, userID int64) {
	t.Helper()
	enabled, hasSecret, _ := removalUserState(t, pool, userID)
	if !enabled || !hasSecret {
		t.Fatalf("factor must remain intact: enabled=%v hasSecret=%v", enabled, hasSecret)
	}
}

// TestTOTPRemoval_BeginLockedTooManyRequests: once the shared TOTP failure
// policy locks the account, begin answers 429 with the lockout audit row.
func TestTOTPRemoval_BeginLockedTooManyRequests(t *testing.T) {
	rh := newRemovalHarness(t, nil)

	// Burn the failure budget with wrong codes (each is a 401 refusal until
	// the 5th failure locks; afterwards every attempt is a 429).
	locked := false
	for i := 0; i < 10; i++ {
		_, status := rh.begin("correct-horse-battery", "000000")
		switch status {
		case http.StatusUnauthorized:
			if locked {
				t.Fatalf("attempt %d: 401 after the account locked, want 429", i+1)
			}
		case http.StatusTooManyRequests:
			locked = true
		default:
			t.Fatalf("attempt %d status = %d, want 401 or 429", i+1, status)
		}
	}
	if !locked {
		t.Fatal("account never locked after repeated failures — the lockout policy did not engage")
	}
	if got := removalAuditCount(t, rh.pool, rh.userID, "totp_removal_step_up_refused"); got < 5 {
		t.Fatalf("refusal audit rows = %d, want >= 5 (every failed attempt audited)", got)
	}
	removalFactorIntactNoCodes(t, rh.pool, rh.userID)
}

// TestTOTPRemoval_BeginInternalErrorSurfaces500: a begin whose lockout
// bookkeeping cannot commit (the failure UPDATE is blocked past its deadline)
// is a 500, not a silent refusal — the operator sees the broken state.
func TestTOTPRemoval_BeginInternalErrorSurfaces500(t *testing.T) {
	rh := newRemovalHarness(t, nil)

	// Hold the user row locked: the TOTP failure bookkeeping UPDATE inside
	// VerifyTOTPWithLockout must block until the request deadline expires.
	lockTx, err := rh.pool.Begin(context.Background())
	if err != nil {
		t.Fatalf("begin lock tx: %v", err)
	}
	var lid int64
	if err := lockTx.QueryRow(context.Background(),
		`SELECT id FROM users WHERE id = $1 FOR UPDATE`, rh.userID).Scan(&lid); err != nil {
		_ = lockTx.Rollback(context.Background())
		t.Fatalf("lock user row: %v", err)
	}

	blockedCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req := httptest.NewRequest(http.MethodPost, "/auth/totp/remove/begin",
		strings.NewReader(`{"password":"correct-horse-battery","code":"000000"}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.Clone(blockedCtx)
	req = req.WithContext(ContextWithUser(req.Context(), removalClaims(rh.userID, rh.jti)))
	rr := httptest.NewRecorder()
	rh.beginH(rr, req)
	if rr.Code != http.StatusInternalServerError {
		_ = lockTx.Rollback(context.Background())
		t.Fatalf("begin with blocked bookkeeping status = %d body %s, want 500", rr.Code, rr.Body.String())
	}
	if err := lockTx.Rollback(context.Background()); err != nil {
		t.Fatalf("release user row lock: %v", err)
	}
}

// TestTOTPRemoval_ConfirmNotEnabledConflict: a step-up token can exist for a
// user whose factor was already removed by another path; the confirm answers
// 409 with the factor still off.
func TestTOTPRemoval_ConfirmNotEnabledConflict(t *testing.T) {
	pool := enrollmentHandlerPool(t)
	ensureEnrollmentLocalDomain(t, pool)
	email := "totp-remove-confirm-notenabled@example.test"
	userID := seedRemovalUser(t, pool, email, "correct-horse-battery", false, nil)
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})
	jti := "sess-confirm-notenabled"

	tok, err := authn.IssueTOTPRemovalStepUp(context.Background(), pool, userID, jti)
	if err != nil {
		t.Fatalf("issue step-up: %v", err)
	}
	confirm := postRemoval(t, "/auth/totp/remove",
		map[string]any{"step_up_token": tok, "confirm": "REMOVE"},
		removalClaims(userID, jti), h.TOTPRemovalConfirm)
	if confirm.Code != http.StatusConflict {
		t.Fatalf("confirm without factor status = %d body %s, want 409", confirm.Code, confirm.Body.String())
	}
	if got := removalAuditCount(t, pool, userID, "totp_removal_refused"); got != 1 {
		t.Fatalf("refusal audit rows = %d, want 1", got)
	}
}

// TestTOTPRemoval_ConfirmInternalErrorSurfaces500: when the removal
// transaction cannot take its factor fence (the users row is held past the
// request deadline), the handler answers 500 — never 204 without a removal.
func TestTOTPRemoval_ConfirmInternalErrorSurfaces500(t *testing.T) {
	rh := newRemovalHarness(t, []string{"rec-gaps-3"})
	tok, status := rh.begin("correct-horse-battery", "rec-gaps-3")
	if status != http.StatusOK || tok == "" {
		t.Fatalf("begin status = %d token %q, want 200 + token", status, tok)
	}

	lockTx, err := rh.pool.Begin(context.Background())
	if err != nil {
		t.Fatalf("begin lock tx: %v", err)
	}
	var lid int64
	if err := lockTx.QueryRow(context.Background(),
		`SELECT id FROM users WHERE id = $1 FOR UPDATE`, rh.userID).Scan(&lid); err != nil {
		_ = lockTx.Rollback(context.Background())
		t.Fatalf("lock user row: %v", err)
	}

	blockedCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req := httptest.NewRequest(http.MethodPost, "/auth/totp/remove",
		strings.NewReader(`{"step_up_token":"`+tok+`","confirm":"REMOVE"}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.Clone(blockedCtx)
	req = req.WithContext(ContextWithUser(req.Context(), removalClaims(rh.userID, rh.jti)))
	rr := httptest.NewRecorder()
	rh.confirmH(rr, req)
	if rr.Code != http.StatusInternalServerError {
		_ = lockTx.Rollback(context.Background())
		t.Fatalf("confirm with blocked fence status = %d body %s, want 500", rr.Code, rr.Body.String())
	}
	if err := lockTx.Rollback(context.Background()); err != nil {
		t.Fatalf("release user row lock: %v", err)
	}

	// The factor is intact and the token was NOT consumed (the transaction
	// rolled back): a retry after the fence releases still removes cleanly.
	rh.factorIntact()
	if got := rh.confirm(rh.jti, tok, "REMOVE"); got != http.StatusNoContent {
		t.Fatalf("confirm after fence release status = %d, want 204 (token must not have been consumed)", got)
	}
}

// TestTOTPRemoval_UnknownUserBeginSurfaces500: an access token for a since-
// deleted user reaches the begin handler; the state-lookup failure is a 500.
func TestTOTPRemoval_UnknownUserBeginSurfaces500(t *testing.T) {
	pool := enrollmentHandlerPool(t)
	ensureEnrollmentLocalDomain(t, pool)
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})

	begin := postRemoval(t, "/auth/totp/remove/begin",
		map[string]any{"password": "x", "code": "000000"},
		removalClaims(999999999, "sess-unknown"), h.TOTPRemovalBegin)
	if begin.Code != http.StatusInternalServerError {
		t.Fatalf("begin for unknown user status = %d, want 500", begin.Code)
	}
}
