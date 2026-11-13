package handlers

// possession_bootstrap_promotion_test.go — the bootstrap enrollment's secret
// promotion (r1 receipt defect 3; scheme v7 §1.6/§2.2): the confirm arm's
// promotion transaction must install the STAGED pending secret as the ACTIVE
// totp_secret_enc — enabling TOTP without its secret leaves a fresh account
// with an unusable active factor.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"setjoin.com/authserver/internal/authn"
	"setjoin.com/authserver/internal/token"
	"setjoin.com/shared/toggle"
)

// newBootstrapConfirmHarness seeds a C2/C3 bootstrap account with its
// mfa_pending grant and drives a REAL enroll/setup, returning the handler,
// pool, user id, the minted mfa_token (the grant binds its hash — confirm
// must present the SAME token), staged secret and enrollment id — the shared
// front half of the confirm-arm tests.
func newBootstrapConfirmHarness(t *testing.T, label string) (*AuthHandler, *pgxpool.Pool, int64, string, string, string) {
	t.Helper()
	pool := enrollmentHandlerPool(t)
	ensureEnrollmentLocalDomain(t, pool)
	email := fmt.Sprintf("%s-%d@example.test", label, time.Now().UnixNano())
	userID := seedLocalUser(t, pool, email)
	h := NewAuthHandler(AuthHandlerConfig{
		Pool:           pool,
		JWT:            newTestJWT(),
		Logger:         discardLogger(),
		PolicyEngine:   newStepUpEngine(),
		SignInRecorder: &captureRecorder{},
		Toggles: toggle.NewTestFlags(map[string]bool{
			toggle.FeatureTokenBinding: true,
		}),
	})

	mfaToken, err := h.jwt.IssueMFAPending(userID, email)
	if err != nil {
		t.Fatalf("issue mfa_token: %v", err)
	}
	// The grant half of the §1.5.1 login pair (the login flow commits it
	// atomically; the arms peek/consume it).
	seedBootstrapGrant(t, pool, h.jwt, mfaToken)

	// Setup: stage the pending secret.
	setup := postEnrollmentJSON(t, "/auth/totp/enroll/setup", map[string]any{
		"mfa_token": mfaToken,
	}, h.TOTPEnrollmentSetup)
	if setup.Code != http.StatusOK {
		t.Fatalf("enrollment setup: got %d, want 200: %s", setup.Code, setup.Body.String())
	}
	enrollmentID := enrollmentIDFromBody(t, setup.Body.Bytes())
	var setupBody struct {
		ProvisioningURI string `json:"provisioning_uri"`
	}
	if err := json.Unmarshal(setup.Body.Bytes(), &setupBody); err != nil {
		t.Fatalf("decode enrollment setup: %v", err)
	}
	key, err := otp.NewKeyFromURL(setupBody.ProvisioningURI)
	if err != nil {
		t.Fatalf("parse provisioning URI: %v", err)
	}
	return h, pool, userID, mfaToken, key.Secret(), enrollmentID
}

// TestBootstrapConfirmRefusesLockedBudgetWithoutEvaluation is the r3 defect 6
// reproduction: the §2.3 budget read must run UNDER the fence BEFORE code
// evaluation. The historical shape verified the code first, so a VALID staged
// code reached promotion — whose write clears totp_failed_attempts and
// totp_locked_until — and a single valid code disarmed an active lockout.
func TestBootstrapConfirmRefusesLockedBudgetWithoutEvaluation(t *testing.T) {
	h, pool, userID, mfaToken, stagedSecret, enrollmentID := newBootstrapConfirmHarness(t, "bootstrap-locked")

	// Lock the budget through the §2.3 policy writer itself: five evaluated
	// increments set totp_locked_until exactly as the shared cycle would.
	ctx := context.Background()
	for i := 0; i < authn.TOTPMaxFailures; i++ {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin increment tx: %v", err)
		}
		locked, err := authn.RecordTOTPFailure(ctx, tx, userID, i)
		if err != nil {
			t.Fatalf("record failure %d: %v", i+1, err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit increment %d: %v", i+1, err)
		}
		if i < authn.TOTPMaxFailures-1 && locked {
			t.Fatalf("failure %d locked early", i+1)
		}
		if i == authn.TOTPMaxFailures-1 && !locked {
			t.Fatal("the 5th failure did not set the lock")
		}
	}
	state, err := authn.LoadTOTPLockState(ctx, pool, userID)
	if err != nil || !state.Locked(time.Now()) {
		t.Fatalf("fixture budget not locked: %+v (%v)", state, err)
	}

	// A VALID staged code under the active lock: refused 429 WITHOUT
	// evaluation — no promotion, no unlock, no consumption.
	code, err := totp.GenerateCode(stagedSecret, time.Now())
	if err != nil {
		t.Fatalf("generate confirmation code: %v", err)
	}
	confirm := postEnrollmentJSON(t, "/auth/totp/enroll/confirm", map[string]any{
		"mfa_token":     mfaToken,
		"code":          code,
		"enrollment_id": enrollmentID,
	}, h.TOTPEnrollmentConfirm)
	if confirm.Code != http.StatusTooManyRequests {
		t.Fatalf("locked confirm with a VALID code: got %d, want 429: %s", confirm.Code, confirm.Body.String())
	}

	// Nothing moved: the factor is still uninstalled, the lock is intact at
	// exactly five failures, the grant is unconsumed.
	var enabled bool
	var installed *string
	if err := pool.QueryRow(ctx,
		`SELECT COALESCE(totp_enabled, FALSE), totp_secret_enc FROM users WHERE id = $1`, userID,
	).Scan(&enabled, &installed); err != nil {
		t.Fatalf("post-confirm user read: %v", err)
	}
	if enabled || installed != nil {
		t.Fatalf("locked confirm promoted the factor: enabled=%v installed=%v", enabled, installed != nil)
	}
	state, err = authn.LoadTOTPLockState(ctx, pool, userID)
	if err != nil {
		t.Fatal(err)
	}
	if state.FailedAttempts != authn.TOTPMaxFailures || !state.Locked(time.Now()) {
		t.Fatalf("locked confirm moved the budget: %+v, want %d failures and a live lock", state, authn.TOTPMaxFailures)
	}
	if n := countGrantsFor(t, h, userID); n != 1 {
		t.Fatalf("grant rows = %d after the locked confirm, want 1 (unconsumed)", n)
	}
}

// TestBootstrapEnrollmentInstallsPromotedSecret drives the REAL bootstrap
// arms — setup (stages the pending secret, returns its provisioning URI) and
// confirm (promotes, consumes the grant, bumps the generation) — then proves
// the promoted secret: users.totp_secret_enc decrypts to the STAGED secret,
// and a subsequent TOTP login second factor with a code from that secret
// completes.
func TestBootstrapEnrollmentInstallsPromotedSecret(t *testing.T) {
	pool := enrollmentHandlerPool(t)
	ensureEnrollmentLocalDomain(t, pool)
	email := fmt.Sprintf("bootstrap-promote-%d@example.test", time.Now().UnixNano())
	userID := seedLocalUser(t, pool, email)
	h := NewAuthHandler(AuthHandlerConfig{
		Pool:           pool,
		JWT:            newTestJWT(),
		Logger:         discardLogger(),
		PolicyEngine:   newStepUpEngine(),
		SignInRecorder: &captureRecorder{},
		Toggles: toggle.NewTestFlags(map[string]bool{
			toggle.FeatureTokenBinding: true,
		}),
	})

	mfaToken, err := h.jwt.IssueMFAPending(userID, email)
	if err != nil {
		t.Fatalf("issue mfa_token: %v", err)
	}
	// The grant half of the §1.5.1 login pair (the login flow commits it
	// atomically; the arms peek/consume it).
	seedBootstrapGrant(t, pool, h.jwt, mfaToken)

	// Setup: stage the pending secret.
	setup := postEnrollmentJSON(t, "/auth/totp/enroll/setup", map[string]any{
		"mfa_token": mfaToken,
	}, h.TOTPEnrollmentSetup)
	if setup.Code != http.StatusOK {
		t.Fatalf("enrollment setup: got %d, want 200: %s", setup.Code, setup.Body.String())
	}
	enrollmentID := enrollmentIDFromBody(t, setup.Body.Bytes())
	var setupBody struct {
		ProvisioningURI string `json:"provisioning_uri"`
	}
	if err := json.Unmarshal(setup.Body.Bytes(), &setupBody); err != nil {
		t.Fatalf("decode enrollment setup: %v", err)
	}
	key, err := otp.NewKeyFromURL(setupBody.ProvisioningURI)
	if err != nil {
		t.Fatalf("parse provisioning URI: %v", err)
	}
	stagedSecret := key.Secret()

	// Confirm: verify the staged code and promote.
	code, err := totp.GenerateCode(stagedSecret, time.Now())
	if err != nil {
		t.Fatalf("generate confirmation code: %v", err)
	}
	confirm := postEnrollmentJSON(t, "/auth/totp/enroll/confirm", map[string]any{
		"mfa_token":     mfaToken,
		"code":          code,
		"enrollment_id": enrollmentID,
	}, h.TOTPEnrollmentConfirm)
	if confirm.Code != http.StatusOK {
		t.Fatalf("enrollment confirm: got %d, want 200: %s", confirm.Code, confirm.Body.String())
	}

	// The ACTIVE secret is the staged one — the promotion installed it.
	var installed string
	if err := pool.QueryRow(context.Background(),
		`SELECT pgp_sym_decrypt(totp_secret_enc::bytea, current_setting('app.encryption_key'))
		   FROM users WHERE id = $1`, userID,
	).Scan(&installed); err != nil {
		t.Fatalf("read promoted secret: %v — the promotion left NO installed secret", err)
	}
	if installed != stagedSecret {
		t.Fatalf("promoted secret = %q, want the STAGED secret %q", installed, stagedSecret)
	}

	// The enrolled factor proves a real login second factor (the fresh login
	// mints a new mfa_token; TOTPVerify completes it with the installed
	// secret). The confirm's acceptance set the replay marker seconds ago —
	// rewind it (bounded fixture; a real login lands in a later 30s window)
	// so the login code is not refused as a same-window replay.
	fresh, err := h.jwt.IssueMFAPending(userID, email)
	if err != nil {
		t.Fatalf("issue fresh mfa_token: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`UPDATE users SET last_totp_used_at = now() - interval '31 seconds' WHERE id = $1`, userID,
	); err != nil {
		t.Fatalf("rewind replay marker: %v", err)
	}
	var freshClaims *token.Claims
	if freshClaims, err = h.jwt.Validate(fresh); err != nil || freshClaims.Type != token.TypeMFAPending {
		t.Fatalf("fresh mfa_token invalid: %v", err)
	}
	loginCode, err := totp.GenerateCode(stagedSecret, time.Now())
	if err != nil {
		t.Fatalf("generate login code: %v", err)
	}
	verify := postEnrollmentJSON(t, "/auth/totp/verify", map[string]any{
		"mfa_token": fresh,
		"code":      loginCode,
	}, h.TOTPVerify)
	if verify.Code != http.StatusOK {
		t.Fatalf("login totp verify: got %d, want 200 (the enrolled secret must prove a login): %s", verify.Code, verify.Body.String())
	}
	if accessTokenFromBody(t, verify) == "" {
		t.Fatal("totp verify issued no access token")
	}
}
