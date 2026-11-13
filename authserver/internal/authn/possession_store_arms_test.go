package authn

// possession_store_arms_test.go — fail-closed arm coverage for the possession
// gate's storage layer (scheme v7 §1/§2). The happy paths live in the db
// integration and race suites; this file drives the refusal/error arms of
// possession.go, backup_codes.go and the shared TOTP-cycle seam:
//
//   - pure contracts: GrantMismatchError text, budget-column discrimination
//     for unknown proof methods, the provisioning-URI fallback;
//   - missing-row refusals (UsersFence / ClassifyCohort / BindGrantTarget on
//     a dead grant, ConsumeCeremony with no row, RecordPossessionFailure and
//     RecordTOTPFailure against a locked budget, VerifyBackupCode with none);
//   - statement faults through the established trigger precedent (grant
//     prior-row cleanup, §1.7 mismatch-cleanup delete, ceremony insert/
//     delete, pending-TOTP stage/delete, budget reset) — every fault is
//     scoped to the fixture user by a WHEN clause and dropped at cleanup;
//   - read-failure seams: the closed pool for wrapped-read arms and the
//     'infinity' timestamptz scan fault for *time.Time reads;
//   - fence-function faults: identity_auth_person_fence is replaced for ONE
//     fixture user (captured definition restored at cleanup), driving the
//     PersonFence wrap and the removal person-fence arm.
//
// Every test asserts the OBSERVABLE outcome (error identity, refusal state,
// preserved counters), never merely that a line executed.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// armsFaultTrigger installs a trigger that RAISES when whenSQL matches, and
// drops both objects at cleanup. fn and trig must be unique per call site.
func armsFaultTrigger(t *testing.T, pool *pgxpool.Pool, fn, trig, table, timing, whenSQL string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), fmt.Sprintf(`
		DROP TRIGGER IF EXISTS %s ON %s;
		DROP FUNCTION IF EXISTS %s();
		CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $fn$
		BEGIN
		  RAISE EXCEPTION 'injected fault (%%s)', TG_NAME;
		END $fn$;
		CREATE TRIGGER %s %s ON %s
		FOR EACH ROW WHEN (%s) EXECUTE FUNCTION %s()`,
		trig, table, fn, fn, trig, timing, table, whenSQL, fn)); err != nil {
		t.Fatalf("install fault trigger on %s: %v", table, err)
	}
	t.Cleanup(func() {
		// The drop takes ACCESS EXCLUSIVE and can race an earlier-registered
		// open fixture transaction's SHARE lock (cleanups unwind LIFO): retry
		// briefly instead of blocking forever behind it.
		for i := 0; i < 25; i++ {
			if _, err := pool.Exec(context.Background(),
				`SET lock_timeout = '200ms'; DROP TRIGGER IF EXISTS `+trig+` ON `+table); err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		_, _ = pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS `+fn+`()`)
	})
}

// armsUID renders the fixture id for trigger WHEN clauses.
func armsUID(userID int64) string { return fmt.Sprintf("%d", userID) }

// armsClosedPool opens a dedicated pool and closes it: the seam for
// read-failure arms (the first statement fails with a non-ErrNoRows error).
func armsClosedPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	p := integrationPool(t)
	p.Close()
	return p
}

// armsGrantRow inserts one live grant row for the fixture user and returns
// the raw token whose SHA-256 it stored.
func armsGrantRow(t *testing.T, pool *pgxpool.Pool, userID int64, jti, operation, scope string, target *string) string {
	t.Helper()
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 17)
	}
	token := hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	if _, err := pool.Exec(context.Background(),
		`DELETE FROM mfa_reauth_step_ups WHERE user_id = $1`, userID); err != nil {
		t.Fatalf("arms grant cleanup: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO mfa_reauth_step_ups
		  (token_hash, user_id, session_jti, operation, target_ref,
		   proof_method, bound_factor_generation, token_scope, expires_at)
		 VALUES ($1, $2, $3, $4, $5, 'password',
		         (SELECT factor_generation FROM users WHERE id = $2),
		         $6, now() + interval '5 minutes')`,
		hex.EncodeToString(sum[:]), userID, jti, operation, target, scope,
	); err != nil {
		t.Fatalf("arms grant insert: %v", err)
	}
	return token
}

func TestGrantMismatchErrorMessageContract(t *testing.T) {
	withReason := &GrantMismatchError{Reason: "operation changed"}
	if got := withReason.Error(); !strings.Contains(got, "grant mismatch") || !strings.Contains(got, "operation changed") {
		t.Fatalf("Error() = %q, want the mismatch text naming the reason", got)
	}
	empty := &GrantMismatchError{}
	if got := empty.Error(); got != "possession proof grant mismatch" {
		t.Fatalf("empty-reason Error() = %q, want the bare mismatch text", got)
	}
	var nilErr *GrantMismatchError
	if got := nilErr.Error(); got != "possession proof grant mismatch" {
		t.Fatalf("nil-receiver Error() = %q, want the bare mismatch text", got)
	}
}

func TestPersonFenceFaultFailsClosed(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	userID, _ := makeTOTPUser(t, pool, false)

	var original string
	if err := pool.QueryRow(ctx,
		`SELECT pg_get_functiondef('identity_auth_person_fence(bigint)'::regprocedure)`).Scan(&original); err != nil {
		t.Fatalf("capture original fence definition: %v", err)
	}
	faulted := fmt.Sprintf(`CREATE OR REPLACE FUNCTION identity_auth_person_fence(p_user_id BIGINT) RETURNS void
		LANGUAGE plpgsql AS $fn$
		BEGIN
		  IF p_user_id = %s THEN
		    RAISE EXCEPTION 'injected person fence failure';
		  END IF;
		  PERFORM pg_advisory_xact_lock(hashtextextended('identity-person:'||p_user_id::text, 0));
		END $fn$;`, armsUID(userID))
	if _, err := pool.Exec(ctx, faulted); err != nil {
		t.Fatalf("install fence fault: %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx, original); err != nil {
			t.Errorf("restore identity_auth_person_fence: %v", err)
		}
	})

	err := PersonFence(ctx, pool, userID)
	if err == nil || !strings.Contains(err.Error(), "person fence") || !strings.Contains(err.Error(), "injected person fence failure") {
		t.Fatalf("PersonFence error = %v, want the injected failure wrapped as a person-fence error", err)
	}
}

func TestFenceAndCohortMissingRowAndReadArms(t *testing.T) {
	pool := integrationPool(t)
	closed := armsClosedPool(t)
	ctx := context.Background()
	const absent = int64(999999999)

	// UsersFence: missing row fails closed with the typed message; a read
	// failure keeps the fence wrap.
	if _, err := UsersFence(ctx, pool, absent); err == nil || !strings.Contains(err.Error(), "user unavailable for factor work") {
		t.Fatalf("UsersFence(missing) = %v, want the unavailable-user error", err)
	}
	if _, err := UsersFence(ctx, closed, absent); err == nil || !strings.Contains(err.Error(), "users fence") {
		t.Fatalf("UsersFence(closed pool) = %v, want the wrapped users-fence error", err)
	}
	// ClassifyCohort: same split.
	if _, err := ClassifyCohort(ctx, pool, absent); err == nil || !strings.Contains(err.Error(), "user unavailable for cohort classification") {
		t.Fatalf("ClassifyCohort(missing) = %v, want the unavailable-user error", err)
	}
	if _, err := ClassifyCohort(ctx, closed, absent); err == nil || !strings.Contains(err.Error(), "cohort classification") {
		t.Fatalf("ClassifyCohort(closed pool) = %v, want the wrapped classification error", err)
	}
	// DurableRevocationRecheck: a read failure is never "not revoked".
	if _, err := DurableRevocationRecheck(ctx, closed, absent, "", "jti-x", nil); err == nil || !strings.Contains(err.Error(), "durable revocation recheck") {
		t.Fatalf("DurableRevocationRecheck(closed pool) = %v, want the wrapped recheck error", err)
	}
}

func TestGrantIssueCleanupFaultArms(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	userID, _ := makeTOTPUser(t, pool, false)

	// Seed PRIOR grant rows so the issuance's one-live-row cleanup DELETE has
	// something to touch — the fault trigger is a BEFORE DELETE trigger and
	// never fires on a zero-row delete.
	jti := "arms-issue-jti"
	_ = armsGrantRow(t, pool, userID, jti, OperationTOTPEnroll, ProofScopeSession, nil)

	fn := "arms_grant_cleanup_fault"
	trig := fn + "_trig"
	armsFaultTrigger(t, pool, fn, trig, "mfa_reauth_step_ups", "BEFORE DELETE",
		"OLD.user_id = "+armsUID(userID))

	if _, err := IssueSessionGrant(ctx, pool, userID, jti, "", OperationRecoveryRegenerate, nil, ProofMethodTOTP, nil, time.Minute); err == nil || !strings.Contains(err.Error(), "grant prior-row cleanup") {
		t.Fatalf("IssueSessionGrant with faulted cleanup = %v, want the wrapped cleanup error", err)
	}
	if err := IssueMFAPendingGrant(ctx, pool, userID, jti, "hash-x", OperationBootstrapTOTPEnroll, ProofMethodTOTP, nil, time.Minute); err == nil || !strings.Contains(err.Error(), "grant prior-row cleanup") {
		t.Fatalf("IssueMFAPendingGrant with faulted cleanup = %v, want the wrapped cleanup error", err)
	}
	// Nothing NEW was issued: the only row left is the seeded one, and it is
	// still the seeded operation — a faulted mint never half-applies.
	var op string
	if err := pool.QueryRow(ctx,
		`SELECT operation FROM mfa_reauth_step_ups WHERE user_id = $1`, userID).Scan(&op); err != nil || op != OperationTOTPEnroll {
		t.Fatalf("grant row after faulted issuance = %q (%v), want only the seeded %q", op, err, OperationTOTPEnroll)
	}
}

func TestClassifyGrantMissCleanupFault(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	userID, _ := makeTOTPUser(t, pool, false)
	jti := "arms-miss-jti"
	token := armsGrantRow(t, pool, userID, jti, OperationTOTPEnroll, ProofScopeSession, nil)

	fn := "arms_miss_cleanup_fault"
	trig := fn + "_trig"
	armsFaultTrigger(t, pool, fn, trig, "mfa_reauth_step_ups", "BEFORE DELETE",
		"OLD.user_id = "+armsUID(userID))

	// A peek whose operation does NOT match the stored tuple still finds the
	// exact {hash, jti, user} row — the §1.7 mismatch cleanup DELETES it, and
	// the faulted delete must surface, never a silent reauth_required.
	wrongOp := GrantPredicate{
		TokenHash:  ReauthTokenHash(token),
		UserID:     userID,
		SessionJTI: jti,
		Operation:  OperationRecoveryRegenerate,
		TokenScope: ProofScopeSession,
	}
	if _, err := PeekGrant(ctx, pool, wrongOp); err == nil || !strings.Contains(err.Error(), "grant mismatch cleanup") {
		t.Fatalf("mismatched peek with faulted cleanup = %v, want the wrapped cleanup error", err)
	}
}

func TestBindGrantTargetArms(t *testing.T) {
	pool := integrationPool(t)
	closed := armsClosedPool(t)
	ctx := context.Background()
	userID, _ := makeTOTPUser(t, pool, false)

	// Already bound → (false, nil): the caller applies the resume/409 rules.
	bound := "AAAA"
	jti := "arms-bind-jti"
	token := armsGrantRow(t, pool, userID, jti, OperationTOTPEnroll, ProofScopeSession, &bound)
	ok, err := BindGrantTarget(ctx, pool, ReauthTokenHash(token), userID, jti, "BBBB")
	if ok || err != nil {
		t.Fatalf("BindGrantTarget(bound) = (%v,%v), want (false,nil)", ok, err)
	}
	// Missing grant → (false, ErrGrantRequired): the dead-proof answer.
	ok, err = BindGrantTarget(ctx, pool, ReauthTokenHash("arms-absent-token"), userID, "arms-absent-jti", "BBBB")
	if ok || !errors.Is(err, ErrGrantRequired) {
		t.Fatalf("BindGrantTarget(missing) = (%v,%v), want (false,ErrGrantRequired)", ok, err)
	}
	// Read failure → the wrapped binding error, never a bind confirmation.
	ok, err = BindGrantTarget(ctx, closed, ReauthTokenHash("x"), userID, "j", "t")
	if ok || err == nil || !strings.Contains(err.Error(), "grant binding") {
		t.Fatalf("BindGrantTarget(closed pool) = (%v,%v), want the wrapped binding error", ok, err)
	}
}

func TestProvingFactorAndCleanupArms(t *testing.T) {
	pool := integrationPool(t)
	closed := armsClosedPool(t)
	ctx := context.Background()
	userID, _ := makeTOTPUser(t, pool, true)

	// TOTP arm: a failed read is a wrapped error, never "still enabled".
	if _, err := ProvingFactorStillEnabled(ctx, closed, Grant{ProofMethod: ProofMethodTOTP, UserID: userID}); err == nil || !strings.Contains(err.Error(), "proving factor check") {
		t.Fatalf("totp arm closed pool = %v, want the wrapped proving-factor error", err)
	}
	// WebAuthn arm with NO proving credential id: refusal without a query.
	live, err := ProvingFactorStillEnabled(ctx, pool, Grant{ProofMethod: ProofMethodWebAuthn, UserID: userID})
	if err != nil || live {
		t.Fatalf("webauthn arm with empty factor id = (%v,%v), want (false,nil)", live, err)
	}
	if _, err := ProvingFactorStillEnabled(ctx, closed, Grant{ProofMethod: ProofMethodWebAuthn, UserID: userID, ProvingFactorID: []byte("cred")}); err == nil || !strings.Contains(err.Error(), "proving factor check") {
		t.Fatalf("webauthn arm closed pool = %v, want the wrapped proving-factor error", err)
	}
	if err := DeleteGrantsForFactor(ctx, closed, userID, []byte("cred")); err == nil || !strings.Contains(err.Error(), "grant factor cleanup") {
		t.Fatalf("DeleteGrantsForFactor(closed pool) = %v, want the wrapped cleanup error", err)
	}
}

func TestBudgetColumnDiscriminationAndFaultArms(t *testing.T) {
	pool := integrationPool(t)
	closed := armsClosedPool(t)
	ctx := context.Background()
	userID, _ := makeTOTPUser(t, pool, false)

	// Unknown proof method: every budget entrypoint refuses the columns.
	if _, err := LoadPossessionBudget(ctx, pool, "bogus-method", userID); err == nil || !strings.Contains(err.Error(), "no possession budget columns") {
		t.Fatalf("LoadPossessionBudget(bogus) = %v, want the unknown-method error", err)
	}
	if _, err := RecordPossessionFailure(ctx, pool, "bogus-method", userID); err == nil || !strings.Contains(err.Error(), "no possession budget columns") {
		t.Fatalf("RecordPossessionFailure(bogus) = %v, want the unknown-method error", err)
	}
	if err := ResetPossessionBudget(ctx, pool, "bogus-method", userID); err == nil || !strings.Contains(err.Error(), "no possession budget columns") {
		t.Fatalf("ResetPossessionBudget(bogus) = %v, want the unknown-method error", err)
	}
	// Read failure wraps.
	if _, err := LoadPossessionBudget(ctx, closed, ProofMethodWebAuthn, userID); err == nil || !strings.Contains(err.Error(), "possession budget load") {
		t.Fatalf("LoadPossessionBudget(closed pool) = %v, want the wrapped load error", err)
	}
	// Locked budget: the increment statement matches zero rows → a REFUSAL
	// (true, nil), and the counter provably did not move.
	if _, err := pool.Exec(ctx,
		`UPDATE users SET possession_webauthn_locked_until = now() + interval '10 min' WHERE id = $1`, userID); err != nil {
		t.Fatalf("park lock: %v", err)
	}
	locked, err := RecordPossessionFailure(ctx, pool, ProofMethodWebAuthn, userID)
	if err != nil || !locked {
		t.Fatalf("RecordPossessionFailure(locked) = (%v,%v), want (true,nil)", locked, err)
	}
	var attempts int
	if err := pool.QueryRow(ctx,
		`SELECT COALESCE(possession_webauthn_failed_attempts, 0) FROM users WHERE id = $1`, userID).Scan(&attempts); err != nil || attempts != 0 {
		t.Fatalf("locked refusal moved the counter to %d (%v), want 0", attempts, err)
	}
	// Reset fault: the reset UPDATE is faulted only for a REAL rewrite (2→0)
	// so the wrap arm surfaces; the parked counter stays 2.
	if _, err := pool.Exec(ctx,
		`UPDATE users SET possession_webauthn_failed_attempts = 2 WHERE id = $1`, userID); err != nil {
		t.Fatalf("park counter: %v", err)
	}
	fn := "arms_budget_reset_fault"
	trig := fn + "_trig"
	armsFaultTrigger(t, pool, fn, trig, "users", "BEFORE UPDATE",
		"NEW.id = "+armsUID(userID)+" AND NEW.possession_webauthn_failed_attempts = 0 AND OLD.possession_webauthn_failed_attempts <> 0")
	if err := ResetPossessionBudget(ctx, pool, ProofMethodWebAuthn, userID); err == nil || !strings.Contains(err.Error(), "possession budget reset") {
		t.Fatalf("ResetPossessionBudget(faulted) = %v, want the wrapped reset error", err)
	}
}

// seedArmsCeremony inserts one live ceremony row directly so the cleanup-
// fault triggers (BEFORE DELETE) have a row to fire on.
func seedArmsCeremony(t *testing.T, pool *pgxpool.Pool, userID int64) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		DELETE FROM webauthn_ceremonies WHERE user_id = $1 AND kind = 'registration'`, userID); err != nil {
		t.Fatalf("seed ceremony cleanup: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO webauthn_ceremonies
		  (challenge_hash, user_id, kind, operation, target_ref,
		   session_jti, token_scope, refresh_family_id, expires_at)
		 VALUES ('hash-seed', $1, 'registration', $2, NULL,
		         'jti-arms', 'session', NULL, now() + interval '5 minutes')`,
		userID, OperationWebAuthnRegister); err != nil {
		t.Fatalf("seed ceremony: %v", err)
	}
}

func TestCreateCeremonyCleanupFaultArm(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	userID, _ := makeTOTPUser(t, pool, false)
	seedArmsCeremony(t, pool, userID)

	fn := "arms_ceremony_delete_fault"
	trig := fn + "_trig"
	armsFaultTrigger(t, pool, fn, trig, "webauthn_ceremonies", "BEFORE DELETE",
		"OLD.user_id = "+armsUID(userID))
	err := CreateCeremony(ctx, pool, Ceremony{ChallengeHash: "hash-x", UserID: userID, Kind: "registration", Operation: OperationWebAuthnRegister, SessionJTI: "jti-arms", TokenScope: ProofScopeSession})
	if err == nil || !strings.Contains(err.Error(), "ceremony prior-row cleanup") {
		t.Fatalf("CreateCeremony with faulted cleanup = %v, want the wrapped cleanup error", err)
	}
	// The seeded row survived: the failure rolled back with the tx-less Exec.
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM webauthn_ceremonies WHERE user_id = $1 AND kind = 'registration'`, userID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("ceremony rows = %d (%v), want 1 (the faulted insert never half-applied)", n, err)
	}
}

func TestCreateCeremonyInsertFaultArm(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	userID, _ := makeTOTPUser(t, pool, false)

	fn := "arms_ceremony_insert_fault"
	trig := fn + "_trig"
	armsFaultTrigger(t, pool, fn, trig, "webauthn_ceremonies", "BEFORE INSERT",
		"NEW.user_id = "+armsUID(userID))
	if err := CreateCeremony(ctx, pool, Ceremony{ChallengeHash: "hash-x", UserID: userID, Kind: "registration", Operation: OperationWebAuthnRegister, SessionJTI: "jti-arms", TokenScope: ProofScopeSession}); err == nil || !strings.Contains(err.Error(), "ceremony insert") {
		t.Fatalf("CreateCeremony with faulted insert = %v, want the wrapped insert error", err)
	}
}

func TestCeremonyReadAndConsumeArms(t *testing.T) {
	pool := integrationPool(t)
	closed := armsClosedPool(t)
	ctx := context.Background()
	userID, _ := makeTOTPUser(t, pool, false)

	if _, err := PeekCeremony(ctx, closed, userID, "registration", ProofScopeSession, "jti-arms"); err == nil || !strings.Contains(err.Error(), "ceremony lookup") {
		t.Fatalf("PeekCeremony(closed pool) = %v, want the wrapped lookup error", err)
	}
	// Single-use consume with no live row → the typed grant-required error.
	if _, err := ConsumeCeremony(ctx, pool, userID, "registration", ProofScopeSession, "jti-arms", "hash-x"); !errors.Is(err, ErrGrantRequired) {
		t.Fatalf("ConsumeCeremony(missing) = %v, want ErrGrantRequired", err)
	}
	if _, err := ConsumeCeremony(ctx, closed, userID, "registration", ProofScopeSession, "jti-arms", "hash-x"); err == nil || !strings.Contains(err.Error(), "ceremony consume") {
		t.Fatalf("ConsumeCeremony(closed pool) = %v, want the wrapped consume error", err)
	}
}

func TestStagePendingTOTPEnrollmentInsertFaultArm(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	userID, secret := makeTOTPUser(t, pool, false)

	fn := "arms_pending_insert_fault"
	trig := fn + "_trig"
	armsFaultTrigger(t, pool, fn, trig, "totp_pending_enrollments", "BEFORE INSERT",
		"NEW.user_id = "+armsUID(userID))
	if _, err := StagePendingTOTPEnrollment(ctx, pool, userID, secret, "jti-arms", "totp_setup"); err == nil || !strings.Contains(err.Error(), "stage pending totp") {
		t.Fatalf("StagePendingTOTPEnrollment(faulted) = %v, want the wrapped stage error", err)
	}
	// Nothing staged.
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM totp_pending_enrollments WHERE user_id = $1`, userID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("pending rows = %d (%v), want 0 after the faulted stage", n, err)
	}
}

func TestDeletePendingTOTPEnrollmentFaultArm(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	userID, secret := makeTOTPUser(t, pool, false)
	id, err := StagePendingTOTPEnrollment(ctx, pool, userID, secret, "jti-arms", "totp_setup")
	if err != nil {
		t.Fatalf("stage pending before delete fault: %v", err)
	}

	fn := "arms_pending_delete_fault"
	trig := fn + "_trig"
	armsFaultTrigger(t, pool, fn, trig, "totp_pending_enrollments", "BEFORE DELETE",
		"OLD.user_id = "+armsUID(userID))
	if err := DeletePendingTOTPEnrollment(ctx, pool, userID, id); err == nil || !strings.Contains(err.Error(), "delete pending totp") {
		t.Fatalf("DeletePendingTOTPEnrollment(faulted) = %v, want the wrapped delete error", err)
	}
	// The staged row survived the faulted delete (the active factor discipline:
	// nothing partial ever applies).
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM totp_pending_enrollments WHERE user_id = $1`, userID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("pending rows = %d (%v), want 1 after the faulted delete", n, err)
	}
}

func TestBackupCodeStoreArms(t *testing.T) {
	pool := integrationPool(t)
	closed := armsClosedPool(t)
	ctx := context.Background()
	userID, _ := makeTOTPUser(t, pool, false)

	// The pool-level generator's wrap arm: a failed store is the wrapped
	// error, never a silent success.
	if _, err := GenerateBackupCodes(ctx, closed, userID); err == nil || !strings.Contains(err.Error(), "store backup codes") {
		t.Fatalf("GenerateBackupCodes(closed pool) = %v, want the wrapped store error", err)
	}
	codes, err := GenerateBackupCodes(ctx, pool, userID)
	if err != nil || len(codes) != 10 {
		t.Fatalf("GenerateBackupCodes = %d codes (%v), want 10", len(codes), err)
	}
	// Stored form is 10 bcrypt hashes — never the raw codes.
	var stored []string
	if err := pool.QueryRow(ctx,
		`SELECT totp_backup_codes_enc FROM users WHERE id = $1`, userID).Scan(&stored); err != nil || len(stored) != 10 {
		t.Fatalf("stored codes = %d (%v), want 10 hashes", len(stored), err)
	}
	if bcrypt.CompareHashAndPassword([]byte(stored[0]), []byte(codes[0])) != nil {
		t.Fatal("stored code[0] does not verify against its own raw code")
	}
	// A user whose code set is empty answers (false, nil) — nothing to
	// consume is a refusal, not a failure.
	var none int64
	if err := pool.QueryRow(ctx, `SELECT 1`).Scan(&none); err != nil {
		t.Fatal(err)
	}
	if ok, err := VerifyBackupCode(ctx, pool, userID, "00000000"); ok || err != nil {
		t.Fatalf("VerifyBackupCode(consumed set) = (%v,%v), want (false,nil)", ok, err)
	}
}

func TestProvisioningURIFallbackForUnparseableSecret(t *testing.T) {
	uri, err := ProvisioningURIForSecret("!!!not-base32!!!", "user@example.test", "SetJoin")
	if err != nil {
		t.Fatalf("ProvisioningURIForSecret fallback errored: %v", err)
	}
	for _, want := range []string{"otpauth://totp/", "user@example.test", "issuer=SetJoin", "digits=6", "period=30", "secret=!!!not-base32!!!"} {
		if !strings.Contains(uri, want) {
			t.Fatalf("fallback uri %q missing %q", uri, want)
		}
	}
}

func TestTOTPLockedUnderFenceArms(t *testing.T) {
	pool := integrationPool(t)
	closed := armsClosedPool(t)
	ctx := context.Background()
	userID, _ := makeTOTPUser(t, pool, false)

	// Missing row under the fence: nothing to lock (the caller's earlier
	// fence read has already refused a deleted user).
	locked, err := TOTPLockedUnderFence(ctx, pool, 999999999)
	if err != nil || locked {
		t.Fatalf("TOTPLockedUnderFence(missing) = (%v,%v), want (false,nil)", locked, err)
	}
	if _, err := TOTPLockedUnderFence(ctx, closed, userID); err == nil || !strings.Contains(err.Error(), "totp lock-state read") {
		t.Fatalf("TOTPLockedUnderFence(closed pool) = %v, want the wrapped read error", err)
	}
}

func TestRecordTOTPFailureArms(t *testing.T) {
	pool := integrationPool(t)
	closed := armsClosedPool(t)
	ctx := context.Background()
	userID, _ := makeTOTPUser(t, pool, false)

	// Locked budget: zero rows match → a refusal (true, nil), no increment.
	if _, err := pool.Exec(ctx,
		`UPDATE users SET totp_locked_until = now() + interval '10 min' WHERE id = $1`, userID); err != nil {
		t.Fatalf("park totp lock: %v", err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	gotLocked, err := RecordTOTPFailure(ctx, tx, userID, 0)
	if err != nil || !gotLocked {
		t.Fatalf("RecordTOTPFailure(locked) = (%v,%v), want (true,nil)", gotLocked, err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var attempts int
	if err := pool.QueryRow(ctx,
		`SELECT COALESCE(totp_failed_attempts, 0) FROM users WHERE id = $1`, userID).Scan(&attempts); err != nil || attempts != 0 {
		t.Fatalf("locked refusal moved the counter to %d (%v), want 0", attempts, err)
	}
	// Read failure: closed pool → raw error (the cycle maps it closed).
	if _, err := RecordTOTPFailure(ctx, closed, userID, 0); err == nil {
		t.Fatal("RecordTOTPFailure(closed pool) returned no error")
	}
}

func TestVerifyTOTPWithLockoutInvalidAndCommitFaultArms(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	userID, secret := makeTOTPUser(t, pool, true)

	// Evaluated invalid code: TOTPInvalid with the counter advanced by the
	// single-statement atomic increment — never a bookkeeping error.
	outcome, err := VerifyTOTPWithLockout(ctx, pool, userID, "000000")
	if err != nil || outcome != TOTPInvalid {
		t.Fatalf("invalid code = (%v,%v), want TOTPInvalid with no error", outcome, err)
	}
	var attempts int
	if err := pool.QueryRow(ctx,
		`SELECT COALESCE(totp_failed_attempts, 0) FROM users WHERE id = $1`, userID).Scan(&attempts); err != nil || attempts != 1 {
		t.Fatalf("attempts = %d (%v), want 1 after the evaluated failure", attempts, err)
	}

	// Commit fault: a deferred constraint trigger on the success reset fires
	// at COMMIT — the wrapper must map it to the bookkeeping error, never
	// report acceptance, and the counter must stay exactly as before.
	fn := "arms_lockout_commit_fault"
	trig := fn + "_trig"
	if _, err := pool.Exec(ctx, fmt.Sprintf(`
		CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $fn$
		BEGIN
		  RAISE EXCEPTION 'injected lockout commit failure' USING ERRCODE='40001';
		END $fn$;
		CREATE CONSTRAINT TRIGGER %s AFTER UPDATE ON users
		DEFERRABLE INITIALLY DEFERRED
		FOR EACH ROW
		WHEN (NEW.id = %s AND NEW.totp_failed_attempts = 0 AND OLD.totp_failed_attempts > 0)
		EXECUTE FUNCTION %s()`, fn, trig, armsUID(userID), fn)); err != nil {
		t.Fatalf("install deferred commit fault: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DROP TRIGGER IF EXISTS `+trig+` ON users`)
		_, _ = pool.Exec(ctx, `DROP FUNCTION IF EXISTS `+fn+`()`)
	})

	valid, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	outcome, err = VerifyTOTPWithLockout(ctx, pool, userID, valid)
	if outcome != TOTPBookkeepingError || err == nil || !strings.Contains(err.Error(), "commit totp lockout cycle") {
		t.Fatalf("commit-faulted verify = (%v,%v), want bookkeeping error naming the commit", outcome, err)
	}
	attempts, lock := readArmsBudget(t, pool, userID)
	if attempts != 1 || lock != nil {
		t.Fatalf("budget after the faulted success = %d/%v, want exactly 1/nil (the reset rolled back)", attempts, lock)
	}
}
func readArmsBudget(t *testing.T, pool *pgxpool.Pool, userID int64) (int, *time.Time) {
	t.Helper()
	var n int
	var lock *time.Time
	if err := pool.QueryRow(context.Background(),
		`SELECT COALESCE(totp_failed_attempts, 0), totp_locked_until FROM users WHERE id = $1`, userID,
	).Scan(&n, &lock); err != nil {
		t.Fatalf("read arms budget: %v", err)
	}
	return n, lock
}

func TestBeginTOTPRemovalBookkeepingFault(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	userID, secret := makeRemovalUser(t, pool, true, nil)
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// The shared cycle's budget read faults ('infinity' refuses to scan into
	// *time.Time) — removal must fail closed with the wrapped bookkeeping
	// error and MUST NOT fall through to the recovery-code path.
	if _, err := pool.Exec(ctx,
		`UPDATE users SET totp_locked_until = 'infinity'::timestamptz WHERE id = $1`, userID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `UPDATE users SET totp_locked_until = NULL WHERE id = $1`, userID)
	})

	_, beginErr := BeginTOTPRemoval(ctx, pool, userID, removalTestPassword, code, "arms-removal-jti")
	if beginErr == nil || !strings.Contains(beginErr.Error(), "totp removal lockout bookkeeping") {
		t.Fatalf("BeginTOTPRemoval with faulted cycle = %v, want the wrapped bookkeeping error", beginErr)
	}
	// The fault marker is untouched: nothing evaluated, nothing wrote. (Read
	// the marker through a text cast — 'infinity' is itself the fault and
	// refuses to scan into *time.Time.)
	var lockText *string
	if err := pool.QueryRow(ctx,
		`SELECT totp_locked_until::text FROM users WHERE id = $1`, userID).Scan(&lockText); err != nil || lockText == nil || *lockText != "infinity" {
		t.Fatalf("fault marker after the faulted removal begin = %v (%v), want 'infinity'", lockText, err)
	}
}

func TestDisableTOTPWithStepUpPersonFenceFault(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	userID, _ := makeRemovalUser(t, pool, true, nil)

	var original string
	if err := pool.QueryRow(ctx,
		`SELECT pg_get_functiondef('identity_auth_person_fence(bigint)'::regprocedure)`).Scan(&original); err != nil {
		t.Fatalf("capture original fence definition: %v", err)
	}
	if _, err := pool.Exec(ctx, fmt.Sprintf(`CREATE OR REPLACE FUNCTION identity_auth_person_fence(p_user_id BIGINT) RETURNS void
		LANGUAGE plpgsql AS $fn$
		BEGIN
		  IF p_user_id = %s THEN
		    RAISE EXCEPTION 'injected removal person fence failure';
		  END IF;
		  PERFORM pg_advisory_xact_lock(hashtextextended('identity-person:'||p_user_id::text, 0));
		END $fn$;`, armsUID(userID))); err != nil {
		t.Fatalf("install fence fault: %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx, original); err != nil {
			t.Errorf("restore identity_auth_person_fence: %v", err)
		}
	})

	err := DisableTOTPWithStepUp(ctx, pool, userID, "arms-removal-jti", "stepup-token", "127.0.0.1")
	if err == nil || !strings.Contains(err.Error(), "totp removal person fence") {
		t.Fatalf("DisableTOTPWithStepUp with faulted fence = %v, want the wrapped person-fence error", err)
	}
}

// TestLoginUserHandlePersistFault drives the loadUser handle-mint arm: a
// user whose webauthn_user_handle is still NULL mints one inside loadUser,
// and a faulted persist UPDATE must surface as the wrapped error (FinishLogin
// propagates loadUser failures verbatim — the caller refuses closed).
func TestLoginUserHandlePersistFault(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	userID, _ := makeTOTPUser(t, pool, false)

	var handle *[]byte
	if err := pool.QueryRow(ctx,
		`SELECT webauthn_user_handle FROM users WHERE id = $1`, userID).Scan(&handle); err != nil {
		t.Fatalf("read fixture handle: %v", err)
	}
	if handle != nil {
		t.Fatal("fixture already carries a webauthn_user_handle; the mint arm would never run")
	}

	fn := "arms_handle_persist_fault"
	trig := fn + "_trig"
	armsFaultTrigger(t, pool, fn, trig, "users", "BEFORE UPDATE",
		"NEW.id = "+armsUID(userID)+" AND OLD.webauthn_user_handle IS NULL")
	provider, err := NewPasskeyProvider(pool, "localhost", "SetJoin", "http://localhost:8080")
	if err != nil {
		t.Fatalf("build passkey provider: %v", err)
	}
	err = provider.FinishLogin(ctx, userID, []byte("{}"), nil)
	if err == nil || !strings.Contains(err.Error(), "persist user handle") {
		t.Fatalf("FinishLogin with faulted handle persist = %v, want the wrapped persist error", err)
	}
	// The NULL handle is preserved: the conditional mint committed nothing.
	if err := pool.QueryRow(ctx,
		`SELECT webauthn_user_handle FROM users WHERE id = $1`, userID).Scan(&handle); err != nil || handle != nil {
		t.Fatalf("handle after faulted persist = %v (%v), want NULL", handle, err)
	}
}

var _ = pgx.ErrNoRows

func TestVerifyTOTPWithLockoutMissingUserArm(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	userID, _ := makeTOTPUser(t, pool, true)
	if _, err := pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID); err != nil {
		t.Fatal(err)
	}
	// The cycle's step-1 lock read finds no row: the missing-user arm answers
	// TOTPInvalid with NO error (the caller reports an invalid code, never a
	// bookkeeping failure, for a deleted principal).
	outcome, err := VerifyTOTPWithLockout(ctx, pool, userID, "000000")
	if err != nil || outcome != TOTPInvalid {
		t.Fatalf("cycle for a deleted user = (%v,%v), want TOTPInvalid with no error", outcome, err)
	}
}

func TestBackupCodeStoreRemainingArms(t *testing.T) {
	pool := integrationPool(t)
	closed := armsClosedPool(t)
	ctx := context.Background()
	userID, _ := makeTOTPUser(t, pool, false)

	// VerifyBackupCode: a failed read is an error, and an EMPTY stored set is
	// a clean (false, nil) refusal — never a match.
	if _, err := VerifyBackupCode(ctx, closed, userID, "00000000"); err == nil {
		t.Fatal("VerifyBackupCode(closed pool) returned no error")
	}
	if _, err := pool.Exec(ctx,
		`UPDATE users SET totp_backup_codes_enc = '{}' WHERE id = $1`, userID); err != nil {
		t.Fatal(err)
	}
	if ok, err := VerifyBackupCode(ctx, pool, userID, "00000000"); ok || err != nil {
		t.Fatalf("VerifyBackupCode(empty set) = (%v,%v), want (false,nil)", ok, err)
	}

	// The tx-variant generator's wrap arm: a faulted codes write inside the
	// caller's transaction surfaces as the wrapped store error.
	fn := "arms_backup_tx_store_fault"
	trig := fn + "_trig"
	armsFaultTrigger(t, pool, fn, trig, "users", "BEFORE UPDATE",
		"NEW.id = "+armsUID(userID)+" AND NEW.totp_backup_codes_enc IS DISTINCT FROM OLD.totp_backup_codes_enc")
	tx, txErr := pool.Begin(ctx)
	if txErr != nil {
		t.Fatal(txErr)
	}
	if _, err := GenerateBackupCodesTx(ctx, tx, userID); err == nil || !contains(err.Error(), "store backup codes") {
		t.Fatalf("GenerateBackupCodesTx with faulted store = %v, want the wrapped store error", err)
	}
	_ = tx.Rollback(ctx)
}
