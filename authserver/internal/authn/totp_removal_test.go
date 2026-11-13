package authn

// De-enrollment decision-table coverage for the TOTP removal seam
// (totp_removal.go). The handlers package (totp_removal_test.go) proves the
// HTTP surface; these tests pin the authn-layer contract itself:
//
//   - the state lookup, password verification and lockout seams each fail
//     closed with their own sentinel/wrapped error;
//   - a locked account refuses every code path (ErrTOTPLocked);
//   - recovery codes step up WITHOUT being consumed, and a non-matching code
//     is the plain self-service refusal;
//   - a step-up token issued for one moment invalidates the previous one and
//     a consumed/expired/foreign token is ErrTOTPRemovalStepUpInvalid;
//   - the removal transaction fails closed (factor intact) when the factor is
//     already gone, when the audit write fails, or when the step-up consume
//     cannot complete.

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"setjoin.com/shared/pwhash"
)

// removalTestPassword is the working password seeded for removal-fixture
// users; it must survive pwhash round-trips (makeTOTPUser seeds the literal
// "x", which is not a verifiable hash).
const removalTestPassword = "correct-horse-battery-removal"

// makeRemovalUser builds on makeTOTPUser but seeds a REAL password hash and,
// when provided, bcrypt-hashed recovery codes exactly as the production
// GenerateBackupCodes stores them.
func makeRemovalUser(
	t *testing.T, pool *pgxpool.Pool, enabled bool, recoveryCodes []string,
) (int64, string) {
	t.Helper()
	ctx := context.Background()
	id, secret := makeTOTPUser(t, pool, enabled)

	hash, err := pwhash.HashPassword(removalTestPassword)
	if err != nil {
		t.Fatalf("hash removal password: %v", err)
	}
	hashedCodes := []string{}
	for _, code := range recoveryCodes {
		h, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.MinCost)
		if err != nil {
			t.Fatalf("hash recovery code: %v", err)
		}
		hashedCodes = append(hashedCodes, string(h))
	}
	if _, err := pool.Exec(ctx,
		`UPDATE users SET password_hash = $1, totp_backup_codes_enc = $2 WHERE id = $3`,
		hash, hashedCodes, id); err != nil {
		t.Fatalf("seed removal fixture: %v", err)
	}
	return id, secret
}

// removalCode derives a currently-valid TOTP code for a fixture secret.
func removalCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCodeCustom(secret, time.Now(), totpValidateOpts)
	if err != nil {
		t.Fatalf("generate TOTP code: %v", err)
	}
	return code
}

// TestBeginTOTPRemoval_UnknownUserFailsLookup pins the state-lookup error arm:
// a caller whose user row is absent (deleted between token mint and step-up)
// gets the wrapped lookup error, never a sentinel meant for a live account.
func TestBeginTOTPRemoval_UnknownUserFailsLookup(t *testing.T) {
	pool := integrationPool(t)
	_, err := BeginTOTPRemoval(context.Background(), pool, 999999999, "pw", "000000", "sess-x")
	if err == nil || !strings.Contains(err.Error(), "totp removal state lookup") {
		t.Fatalf("BeginTOTPRemoval(unknown user) = %v, want wrapped state-lookup error", err)
	}
}

// TestBeginTOTPRemoval_FactorNotEnabled pins the ErrTOTPNotEnabled refusal:
// no active factor means there is nothing to remove, before any password work.
func TestBeginTOTPRemoval_FactorNotEnabled(t *testing.T) {
	pool := integrationPool(t)
	id, _ := makeRemovalUser(t, pool, false, nil)

	_, err := BeginTOTPRemoval(context.Background(), pool, id, removalTestPassword, "000000", "sess-x")
	if !errors.Is(err, ErrTOTPNotEnabled) {
		t.Fatalf("BeginTOTPRemoval(disabled factor) = %v, want ErrTOTPNotEnabled", err)
	}
}

// TestVerifyTOTPRemovalPassword_UnknownUser pins the password-lookup error arm
// directly (the begin flow checks the factor first, so this arm needs the
// exported seam called on its own).
func TestVerifyTOTPRemovalPassword_UnknownUser(t *testing.T) {
	pool := integrationPool(t)
	err := VerifyTOTPRemovalPassword(context.Background(), pool, 999999999, removalTestPassword)
	if err == nil || !strings.Contains(err.Error(), "totp removal password lookup") {
		t.Fatalf("VerifyTOTPRemovalPassword(unknown user) = %v, want wrapped lookup error", err)
	}
}

// TestBeginTOTPRemoval_WrongPasswordRefused: the password gate precedes every
// code work — a wrong password is ErrInvalidRemovalPassword even with a valid
// code, and no step-up row may appear.
func TestBeginTOTPRemoval_WrongPasswordRefused(t *testing.T) {
	pool := integrationPool(t)
	id, secret := makeRemovalUser(t, pool, true, nil)

	_, err := BeginTOTPRemoval(context.Background(), pool, id, "wrong-password", removalCode(t, secret), "sess-x")
	if !errors.Is(err, ErrInvalidRemovalPassword) {
		t.Fatalf("BeginTOTPRemoval(wrong password) = %v, want ErrInvalidRemovalPassword", err)
	}
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM totp_removal_step_ups WHERE user_id = $1`, id).Scan(&n); err != nil {
		t.Fatalf("count step-ups: %v", err)
	}
	if n != 0 {
		t.Fatalf("step-up rows = %d after a wrong-password begin, want 0", n)
	}
}

// TestBeginTOTPRemoval_LockedRefusesEveryCode pins the lockout fence: after
// the shared failure policy locks the account, begin fails with
// ErrTOTPLocked even for a password holder presenting a CURRENTLY VALID code.
func TestBeginTOTPRemoval_LockedRefusesEveryCode(t *testing.T) {
	pool := integrationPool(t)
	id, secret := makeRemovalUser(t, pool, true, nil)

	for i := 0; i < totpMaxFailures; i++ {
		if _, err := BeginTOTPRemoval(context.Background(), pool, id, removalTestPassword, "000000", "sess-lock"); !errors.Is(err, ErrInvalidRemovalCode) {
			t.Fatalf("attempt %d: err = %v, want ErrInvalidRemovalCode", i+1, err)
		}
	}
	// The policy is now locked; even a valid code must be refused as locked.
	if _, err := BeginTOTPRemoval(context.Background(), pool, id, removalTestPassword, removalCode(t, secret), "sess-lock"); !errors.Is(err, ErrTOTPLocked) {
		t.Fatalf("begin while locked = %v, want ErrTOTPLocked", err)
	}
}

// TestBeginTOTPRemoval_RecoveryCodeStepsUpWithoutConsuming pins decision-table
// case 2: a valid recovery code yields a step-up token and the code itself is
// deliberately NOT consumed (the removal transaction deletes all codes).
func TestBeginTOTPRemoval_RecoveryCodeStepsUpWithoutConsuming(t *testing.T) {
	pool := integrationPool(t)
	id, secret := makeRemovalUser(t, pool, true, []string{"rem-code-1", "rem-code-2"})

	tok, err := BeginTOTPRemoval(context.Background(), pool, id, removalTestPassword, "rem-code-1", "sess-rec")
	if err != nil {
		t.Fatalf("begin with recovery code: %v", err)
	}
	if tok == "" {
		t.Fatal("begin with recovery code returned an empty step-up token")
	}

	// The valid TOTP path still works afterwards (code not burned), proving the
	// recovery code was not consumed at step-up.
	if _, err := BeginTOTPRemoval(context.Background(), pool, id, removalTestPassword, removalCode(t, secret), "sess-rec2"); err != nil {
		t.Fatalf("begin with valid TOTP after recovery-code step-up: %v", err)
	}

	// The step-up seam keeps at most one live token per user: the newer begin
	// replaced the first.
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM totp_removal_step_ups WHERE user_id = $1`, id).Scan(&n); err != nil {
		t.Fatalf("count step-ups: %v", err)
	}
	if n != 1 {
		t.Fatalf("live step-up rows = %d, want 1 (newest replaces prior)", n)
	}

	// The recovery code remains present (bcrypt row untouched).
	var codes []string
	if err := pool.QueryRow(context.Background(),
		`SELECT totp_backup_codes_enc FROM users WHERE id = $1`, id).Scan(&codes); err != nil {
		t.Fatalf("read recovery codes: %v", err)
	}
	if len(codes) != 2 {
		t.Fatalf("recovery codes = %d, want 2 (step-up must not consume)", len(codes))
	}
}

// TestBeginTOTPRemoval_UnmatchedCodeWithRecoveryCodesRefused: recovery codes
// present but the submitted code matches neither them nor the factor — the
// plain ErrInvalidRemovalCode refusal (case 3 self-service fence).
func TestBeginTOTPRemoval_UnmatchedCodeWithRecoveryCodesRefused(t *testing.T) {
	pool := integrationPool(t)
	id, _ := makeRemovalUser(t, pool, true, []string{"rem-code-3"})

	_, err := BeginTOTPRemoval(context.Background(), pool, id, removalTestPassword, "no-such-code", "sess-x")
	if !errors.Is(err, ErrInvalidRemovalCode) {
		t.Fatalf("begin with unmatched code = %v, want ErrInvalidRemovalCode", err)
	}
}

// TestHasBackupCode_MissingUserAndNonMatch covers the recovery-code scan's
// error and negative arms directly: an absent user row errors, and a present
// user whose codes do not match reports false without error.
func TestHasBackupCode_MissingUserAndNonMatch(t *testing.T) {
	pool := integrationPool(t)
	if _, err := hasBackupCode(context.Background(), pool, 999999999, "any"); err == nil {
		t.Fatal("hasBackupCode(unknown user) = nil error, want lookup error")
	}

	id, _ := makeRemovalUser(t, pool, true, []string{"rem-code-4"})
	ok, err := hasBackupCode(context.Background(), pool, id, "not-the-code")
	if err != nil {
		t.Fatalf("hasBackupCode(non-match) error: %v", err)
	}
	if ok {
		t.Fatal("hasBackupCode(non-match) = true, want false")
	}
}

// TestDisableTOTPWithStepUp_FactorAlreadyGone: a token can be consumed while
// the factor has already been removed (e.g. admin-side); the transaction must
// roll back with ErrTOTPNotEnabled — never a half-consumed token against a
// disabled factor.
func TestDisableTOTPWithStepUp_FactorAlreadyGone(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	id, _ := makeRemovalUser(t, pool, false, nil)

	tok, err := IssueTOTPRemovalStepUp(ctx, pool, id, "sess-gone")
	if err != nil {
		t.Fatalf("issue step-up: %v", err)
	}
	if err := DisableTOTPWithStepUp(ctx, pool, id, "sess-gone", tok, "127.0.0.1"); !errors.Is(err, ErrTOTPNotEnabled) {
		t.Fatalf("DisableTOTPWithStepUp(disabled factor) = %v, want ErrTOTPNotEnabled", err)
	}

	// The failed removal rolled back, so the token is NOT consumed — but the
	// factor must still be off (nothing resurrected).
	var enabled bool
	if err := pool.QueryRow(ctx, `SELECT totp_enabled FROM users WHERE id = $1`, id).Scan(&enabled); err != nil {
		t.Fatalf("read totp_enabled: %v", err)
	}
	if enabled {
		t.Fatal("failed removal must not enable the factor")
	}
}

// TestIssueTOTPRemovalStepUp_ClosedPoolFailsCleanup pins the step-up store's
// cleanup error arm: with an unusable pool the token is not issued and the
// failure names the cleanup stage.
func TestIssueTOTPRemovalStepUp_ClosedPoolFailsCleanup(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set; skipping closed-pool test")
	}
	ctx := context.Background()
	closed, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Skipf("TEST_DB_DSN set but pool open failed (%v); skipping", err)
	}
	closed.Close()

	if _, err := IssueTOTPRemovalStepUp(ctx, closed, 1, "sess-closed"); err == nil ||
		!strings.Contains(err.Error(), "totp removal step-up cleanup") {
		t.Fatalf("IssueTOTPRemovalStepUp(closed pool) = %v, want wrapped cleanup error", err)
	}
}

// TestIssueTOTPRemovalStepUp_UnknownUserFailsStore pins the step-up store's
// INSERT error arm: the prior-token cleanup succeeds (nothing to delete) but
// the insert violates the user FK, so the issue fails with a wrapped store
// error instead of a token bound to nothing.
func TestIssueTOTPRemovalStepUp_UnknownUserFailsStore(t *testing.T) {
	pool := integrationPool(t)
	_, err := IssueTOTPRemovalStepUp(context.Background(), pool, 999999999, "sess-orphan")
	if err == nil || !strings.Contains(err.Error(), "totp removal step-up store") {
		t.Fatalf("IssueTOTPRemovalStepUp(unknown user) = %v, want wrapped store error", err)
	}
}

// TestDisableTOTPWithStepUp_ClosedPoolFailsBegin pins the transaction-begin
// error arm of the removal transaction.
func TestDisableTOTPWithStepUp_ClosedPoolFailsBegin(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set; skipping closed-pool test")
	}
	ctx := context.Background()
	closed, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Skipf("TEST_DB_DSN set but pool open failed (%v); skipping", err)
	}
	closed.Close()

	err = DisableTOTPWithStepUp(ctx, closed, 1, "sess-closed", "tok", "127.0.0.1")
	if err == nil || !strings.Contains(err.Error(), "totp removal tx begin") {
		t.Fatalf("DisableTOTPWithStepUp(closed pool) = %v, want wrapped tx-begin error", err)
	}
}

// TestDisableTOTPWithStepUp_ConsumeInterruptedFailsClosed pins the consume
// error arm: while another transaction holds the step-up row locked, a removal
// whose deadline expires during the consume fails with a wrapped (non-sentinel)
// error, the token unconsumed and the factor intact.
func TestDisableTOTPWithStepUp_ConsumeInterruptedFailsClosed(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	id, secret := makeRemovalUser(t, pool, true, nil)
	tok, err := IssueTOTPRemovalStepUp(ctx, pool, id, "sess-blocked")
	if err != nil {
		t.Fatalf("issue step-up: %v", err)
	}

	// Hold the step-up row locked exactly as a concurrent consumer would.
	lockTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin lock tx: %v", err)
	}
	var lid int64
	if err := lockTx.QueryRow(ctx,
		`SELECT user_id FROM totp_removal_step_ups WHERE user_id = $1 FOR UPDATE`, id,
	).Scan(&lid); err != nil {
		_ = lockTx.Rollback(ctx)
		t.Fatalf("lock step-up row: %v", err)
	}

	blockedCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	rmErr := DisableTOTPWithStepUp(blockedCtx, pool, id, "sess-blocked", tok, "127.0.0.1")
	cancel()
	if !errors.Is(rmErr, context.DeadlineExceeded) {
		_ = lockTx.Rollback(ctx)
		t.Fatalf("removal while step-up row locked: err = %v, want deadline exceeded at the consume", rmErr)
	}
	if errors.Is(rmErr, ErrTOTPRemovalStepUpInvalid) {
		_ = lockTx.Rollback(ctx)
		t.Fatal("an interrupted consume must surface the transport error, not the replay sentinel")
	}
	if err := lockTx.Rollback(ctx); err != nil {
		t.Fatalf("release step-up lock: %v", err)
	}

	// Released: the same token now removes the factor cleanly.
	if err := DisableTOTPWithStepUp(ctx, pool, id, "sess-blocked", tok, "127.0.0.1"); err != nil {
		t.Fatalf("removal after lock release must succeed: %v", err)
	}
	_ = secret
}

// TestDisableTOTPWithStepUp_AuditFailureKeepsFactor pins the in-transaction
// audit contract: when the success audit row cannot be written (here: a
// non-INET client address cannot be cast), the whole removal rolls back — the
// factor survives and the step-up token is not consumed. No state change may
// commit without its audit row.
func TestDisableTOTPWithStepUp_AuditFailureKeepsFactor(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	id, _ := makeRemovalUser(t, pool, true, nil)
	tok, err := IssueTOTPRemovalStepUp(ctx, pool, id, "sess-audit")
	if err != nil {
		t.Fatalf("issue step-up: %v", err)
	}

	if err := DisableTOTPWithStepUp(ctx, pool, id, "sess-audit", tok, "not-an-ip-address"); err == nil {
		t.Fatal("removal with an uncastable audit IP must fail, not commit unaudited")
	}

	var enabled bool
	if err := pool.QueryRow(ctx, `SELECT totp_enabled FROM users WHERE id = $1`, id).Scan(&enabled); err != nil {
		t.Fatalf("read totp_enabled: %v", err)
	}
	if !enabled {
		t.Fatal("a failed (unaudited) removal must roll back: factor must stay enabled")
	}
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM totp_removal_step_ups WHERE user_id = $1`, id).Scan(&n); err != nil {
		t.Fatalf("count step-ups: %v", err)
	}
	if n != 1 {
		t.Fatalf("step-up rows = %d after rolled-back removal, want 1 (token not consumed)", n)
	}
}

// TestIssueAndDisableTOTPWithStepUp_EndToEnd pins the happy-path token
// contract in one sweep: issued token works, wrong jti does not, empty token
// fails closed, and a successful removal wipes codes alongside the factor.
func TestIssueAndDisableTOTPWithStepUp_EndToEnd(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	id, _ := makeRemovalUser(t, pool, true, []string{"rem-e2e-1"})

	tok, err := IssueTOTPRemovalStepUp(ctx, pool, id, "sess-e2e")
	if err != nil {
		t.Fatalf("issue step-up: %v", err)
	}
	if err := DisableTOTPWithStepUp(ctx, pool, id, "foreign-session", tok, "127.0.0.1"); !errors.Is(err, ErrTOTPRemovalStepUpInvalid) {
		t.Fatalf("foreign-session token = %v, want ErrTOTPRemovalStepUpInvalid", err)
	}
	if err := DisableTOTPWithStepUp(ctx, pool, id, "sess-e2e", "", "127.0.0.1"); !errors.Is(err, ErrTOTPRemovalStepUpInvalid) {
		t.Fatalf("empty token = %v, want ErrTOTPRemovalStepUpInvalid", err)
	}
	if err := DisableTOTPWithStepUp(ctx, pool, id, "sess-e2e", tok, "127.0.0.1"); err != nil {
		t.Fatalf("valid removal: %v", err)
	}
	if err := DisableTOTPWithStepUp(ctx, pool, id, "sess-e2e", tok, "127.0.0.1"); !errors.Is(err, ErrTOTPRemovalStepUpInvalid) {
		t.Fatalf("replayed token = %v, want ErrTOTPRemovalStepUpInvalid", err)
	}

	var enabled bool
	var codes []string
	if err := pool.QueryRow(ctx,
		`SELECT totp_enabled, COALESCE(totp_backup_codes_enc, '{}') FROM users WHERE id = $1`, id,
	).Scan(&enabled, &codes); err != nil {
		t.Fatalf("read wiped state: %v", err)
	}
	if enabled || len(codes) != 0 {
		t.Fatalf("removal must wipe factor and codes: enabled=%v codes=%d", enabled, len(codes))
	}
}
