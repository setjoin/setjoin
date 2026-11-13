package authn

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

// totpIntegrationKey is the pgcrypto symmetric key used for the integration
// tests' app.encryption_key session variable.
const totpIntegrationKey = "test-totp-encryption-key-32chars"

// integrationPool opens a pool against TEST_DB_DSN with the encryption-key
// AfterConnect hook (so pgp_sym_encrypt/decrypt work), or skips the test.
func integrationPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set; skipping TOTP DB integration test")
	}
	pool, err := pgxutil.OpenPool(context.Background(), dsn, 5, totpIntegrationKey, "")
	if err != nil {
		t.Skipf("TEST_DB_DSN set but pool open failed (%v); skipping", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// makeTOTPUser inserts a throwaway user with a pending TOTP secret and returns
// its id and base32 secret. enabled controls totp_enabled.
func makeTOTPUser(t *testing.T, pool *pgxpool.Pool, enabled bool) (int64, string) {
	t.Helper()
	ctx := context.Background()

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer: "test", AccountName: "totp-it@example.com", SecretSize: 32,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("totp.Generate: %v", err)
	}

	// users.username and users.domain_id are NOT NULL — resolve (or create) a
	// local test domain and supply a unique username, or the INSERT violates the
	// constraint. (This fixture predates those columns being required.)
	var domainID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM domains WHERE name = 'totp-it.test'`).Scan(&domainID); err != nil {
		if err := pool.QueryRow(ctx,
			`INSERT INTO domains (name, is_local) VALUES ('totp-it.test', TRUE) RETURNING id`).Scan(&domainID); err != nil {
			t.Fatalf("ensure test domain: %v", err)
		}
	}
	uniq := time.Now().Format("150405.000000")
	email := "totp-it-" + uniq + "@example.com"

	var id int64
	err = pool.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name, password_hash, totp_secret_enc, totp_enabled)
		 VALUES ($1, $2, $3, $3, 'x',
		         pgp_sym_encrypt($4, current_setting('app.encryption_key')),
		         $5)
		 RETURNING id`,
		"totp-it-"+uniq, domainID, email, key.Secret(), enabled,
	).Scan(&id)
	if err != nil {
		t.Fatalf("insert test user: %v", err)
	}
	t.Cleanup(func() { pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, id) })
	return id, key.Secret()
}

// TestConfirmTOTP_EnrollmentSucceeds_DB is the integration proof of the
// ConfirmTOTP regression fix: with totp_enabled still FALSE (enrollment),
// confirming with a VALID code must succeed and flip totp_enabled to TRUE.
// Against the OLD code (ConfirmTOTP -> VerifyTOTP, which filters
// totp_enabled = TRUE) this would ALWAYS fail.
func TestConfirmTOTP_EnrollmentSucceeds_DB(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	id, secret := makeTOTPUser(t, pool, false) // pending: totp_enabled = FALSE

	code, err := totp.GenerateCodeCustom(secret, time.Now(), totpValidateOpts)
	if err != nil {
		t.Fatalf("GenerateCodeCustom: %v", err)
	}

	if err := ConfirmTOTP(ctx, pool, id, code); err != nil {
		t.Fatalf("enrollment confirm with a valid code must succeed, got: %v", err)
	}

	var enabled bool
	if err := pool.QueryRow(ctx, `SELECT totp_enabled FROM users WHERE id = $1`, id).Scan(&enabled); err != nil {
		t.Fatalf("read totp_enabled: %v", err)
	}
	if !enabled {
		t.Error("ConfirmTOTP must set totp_enabled = TRUE after a successful confirm")
	}
}

// removalInterleaveSeed seeds an ENABLED factor and mints a valid step-up
// token for it, the preconditions both sides of the removal/confirm fence
// race start from.
func removalInterleaveSeed(t *testing.T, pool *pgxpool.Pool) (int64, string, string) {
	t.Helper()
	ctx := context.Background()
	id, secret := makeTOTPUser(t, pool, true)
	stepUp, err := IssueTOTPRemovalStepUp(ctx, pool, id, "sess-interleave")
	if err != nil {
		t.Fatalf("issue step-up token: %v", err)
	}
	return id, secret, stepUp
}

// factorState reads (totp_enabled, secret_is_null) — the resurrect detector:
// the bug state this fence exists for is enabled=TRUE over a NULL secret.
// The read is bounded so a wedged or contended server fails the test fast
// instead of stalling the whole package (these tests intentionally hold row
// locks, so every read helper must assume the server can be slow).
func factorState(t *testing.T, pool *pgxpool.Pool, id int64) (bool, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var enabled bool
	var secretNull bool
	if err := pool.QueryRow(ctx,
		`SELECT totp_enabled, totp_secret_enc IS NULL FROM users WHERE id = $1`, id,
	).Scan(&enabled, &secretNull); err != nil {
		t.Fatalf("read factor state: %v", err)
	}
	return enabled, secretNull
}

// TestConfirmTOTP_ConfirmAfterRemovalFailsClosed_DB proves the removal-first
// interleaving converges consistent: DisableTOTPWithStepUp commits the full
// wipe (factor, secret, recovery codes), and a confirmation carrying the
// still-valid code that lands AFTER that commit must fail closed — never
// resurrect an enabled factor over erased secrets.
func TestConfirmTOTP_ConfirmAfterRemovalFailsClosed_DB(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	id, secret, stepUp := removalInterleaveSeed(t, pool)

	if err := DisableTOTPWithStepUp(ctx, pool, id, "sess-interleave", stepUp, "127.0.0.1"); err != nil {
		t.Fatalf("removal must commit: %v", err)
	}

	// The in-flight confirmation's code (verification may even have passed
	// before the removal committed): the confirm landing afterwards must
	// re-derive the wiped state under the fence and refuse.
	code, err := totp.GenerateCodeCustom(secret, time.Now(), totpValidateOpts)
	if err != nil {
		t.Fatalf("GenerateCodeCustom: %v", err)
	}
	if err := ConfirmTOTP(ctx, pool, id, code); err == nil {
		t.Fatal("a confirm landing after a committed removal must fail closed, not succeed")
	}

	enabled, secretNull := factorState(t, pool, id)
	if enabled {
		t.Fatal("totp_enabled must stay FALSE after the refused confirm (resurrected factor over erased secrets)")
	}
	if !secretNull {
		t.Fatal("totp_secret_enc must stay erased after the refused confirm")
	}
}

// TestConfirmTOTP_FenceExcludesConcurrentRemoval_DB proves the confirm-first
// interleaving deterministically, without sleeps: while the confirm's fence
// (the exact FOR NO KEY UPDATE ConfirmTOTP holds for its whole critical
// section) is held on the user row, DisableTOTPWithStepUp must BLOCK — not
// complete — until the fence releases, and then converge by wiping the
// committed factor fully. Against an unsynchronized confirm this order is
// exactly "verification → removal → enable flip"; the fence makes it
// impossible.
//
// While the fence is held this test performs NO other database access: another
// suite's DDL on users queued behind the fence would otherwise queue every
// fresh read behind itself (lock-fairness queue), so every state assertion
// happens after the release.
func TestConfirmTOTP_FenceExcludesConcurrentRemoval_DB(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	id, _, stepUp := removalInterleaveSeed(t, pool)

	// Hold the confirm fence on its own connection.
	fence, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin fence tx: %v", err)
	}
	var fid int64
	if err := fence.QueryRow(ctx,
		`SELECT id FROM users WHERE id = $1 FOR NO KEY UPDATE`, id,
	).Scan(&fid); err != nil {
		_ = fence.Rollback(ctx)
		t.Fatalf("take confirm fence: %v", err)
	}

	// The removal must block on the fence: a bounded context proves it cannot
	// interleave into the confirm's critical section.
	blockedCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	err = DisableTOTPWithStepUp(blockedCtx, pool, id, "sess-interleave", stepUp, "127.0.0.1")
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		_ = fence.Rollback(ctx)
		t.Fatalf("removal while confirm fence held: err = %v, want deadline exceeded (the removal must block on the fence)", err)
	}

	// Release the fence before touching the database again (see the comment
	// above): the blocked attempt's transaction died with its context, so its
	// step-up consume can never have committed.
	if err := fence.Commit(ctx); err != nil {
		t.Fatalf("release fence: %v", err)
	}

	// The blocked attempt committed nothing: the factor is intact.
	if enabled, secretNull := factorState(t, pool, id); !enabled || secretNull {
		t.Fatalf("blocked removal must leave the factor intact: enabled=%v secretNull=%v", enabled, secretNull)
	}

	// After release the removal proceeds against the committed state and wipes
	// everything.
	if err := DisableTOTPWithStepUp(ctx, pool, id, "sess-interleave", stepUp, "127.0.0.1"); err != nil {
		t.Fatalf("removal after fence release must succeed: %v", err)
	}
	if enabled, secretNull := factorState(t, pool, id); enabled || !secretNull {
		t.Fatalf("post-release removal must wipe the factor fully: enabled=%v secretNull=%v", enabled, secretNull)
	}
}

// TestConfirmTOTP_BlocksOnHeldRemovalLock_DB proves the mirror direction: while
// a transaction holds the user row FOR UPDATE exactly as DisableTOTPWithStepUp
// does between consuming the step-up token and the wipe, ConfirmTOTP must block
// on the same fence BEFORE completing — it can never land its enable flip
// inside a removal's critical section. After release, the confirm re-reads the
// row and proceeds consistently.
//
// Like the fence test above, no database access happens while the lock is
// held: every state assertion happens after the release.
func TestConfirmTOTP_BlocksOnHeldRemovalLock_DB(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	id, secret := makeTOTPUser(t, pool, false) // pending enrollment
	code, err := totp.GenerateCodeCustom(secret, time.Now(), totpValidateOpts)
	if err != nil {
		t.Fatalf("GenerateCodeCustom: %v", err)
	}

	// Hold the removal's lock shape (FOR UPDATE) on its own connection.
	removalLock, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin removal-lock tx: %v", err)
	}
	var lid int64
	if err := removalLock.QueryRow(ctx,
		`SELECT id FROM users WHERE id = $1 FOR UPDATE`, id,
	).Scan(&lid); err != nil {
		_ = removalLock.Rollback(ctx)
		t.Fatalf("take removal lock: %v", err)
	}

	confirmCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	err = ConfirmTOTP(confirmCtx, pool, id, code)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		_ = removalLock.Rollback(ctx)
		t.Fatalf("confirm while removal lock held: err = %v, want deadline exceeded (confirm must take the fence before verifying)", err)
	}

	// Release before touching the database again (see the fence test comment):
	// the blocked confirm's transaction rolled back with its context, so it
	// enabled nothing.
	if err := removalLock.Rollback(ctx); err != nil {
		t.Fatalf("release removal lock: %v", err)
	}
	if enabled, secretNull := factorState(t, pool, id); enabled || secretNull {
		t.Fatalf("blocked confirm must not have enabled the factor: enabled=%v secretNull=%v", enabled, secretNull)
	}

	// Release done: the confirm re-reads the pending row under its fence and
	// succeeds with the guarded enable.
	if err := ConfirmTOTP(ctx, pool, id, code); err != nil {
		t.Fatalf("confirm after the removal lock released must succeed: %v", err)
	}
	if enabled, secretNull := factorState(t, pool, id); !enabled || secretNull {
		t.Fatalf("post-release confirm must enable the factor over its secret: enabled=%v secretNull=%v", enabled, secretNull)
	}
}

func TestGenerateTOTPEnrollmentSecret_ActiveFactorIsNotOverwritten_DB(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	id, secret := makeTOTPUser(t, pool, true)

	_, err := GenerateTOTPEnrollmentSecret(ctx, pool, id, "totp-it@example.com", "SetJoin")
	if !errors.Is(err, ErrTOTPEnrollmentUnavailable) {
		t.Fatalf("active factor setup error = %v, want ErrTOTPEnrollmentUnavailable", err)
	}
	var stored string
	if err := pool.QueryRow(ctx,
		`SELECT pgp_sym_decrypt(totp_secret_enc::bytea, current_setting('app.encryption_key'))
		   FROM users WHERE id = $1`, id).Scan(&stored); err != nil {
		t.Fatalf("read active secret: %v", err)
	}
	if stored != secret {
		t.Fatal("mandatory-enrollment setup overwrote an active TOTP secret")
	}
}

func TestConfirmTOTPEnrollment_ConcurrentEnableExactlyOnce_DB(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	id, secret := makeTOTPUser(t, pool, false)
	code, err := totp.GenerateCodeCustom(secret, time.Now(), totpValidateOpts)
	if err != nil {
		t.Fatalf("GenerateCodeCustom: %v", err)
	}

	const racers = 8
	var successes int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			outcome, confirmErr := ConfirmTOTPEnrollment(ctx, pool, id, code, "127.0.0.1")
			if confirmErr == nil && outcome == TOTPAccepted {
				atomic.AddInt64(&successes, 1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := atomic.LoadInt64(&successes); got != 1 {
		t.Fatalf("concurrent enrollment confirmations accepted %d times, want exactly 1", got)
	}
}

func TestConfirmTOTPEnrollment_LocksAfterFiveFailures_DB(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	id, _ := makeTOTPUser(t, pool, false)

	for i := 0; i < totpMaxFailures; i++ {
		outcome, err := ConfirmTOTPEnrollment(ctx, pool, id, "000000", "127.0.0.1")
		if err != nil {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
		if i < totpMaxFailures-1 && outcome != TOTPInvalid {
			t.Fatalf("attempt %d outcome=%d, want TOTPInvalid", i+1, outcome)
		}
		if i == totpMaxFailures-1 && outcome != TOTPLocked {
			t.Fatalf("threshold attempt outcome=%d, want TOTPLocked", outcome)
		}
	}
	outcome, err := ConfirmTOTPEnrollment(ctx, pool, id, "000000", "127.0.0.1")
	if err != nil || outcome != TOTPLocked {
		t.Fatalf("locked follow-up outcome=%d err=%v, want TOTPLocked", outcome, err)
	}
}

// TestVerifyTOTP_ConcurrentReplayRace_DB is the integration proof of the TOCTOU
// replay-race fix: two concurrent VerifyTOTP calls with the SAME valid code must
// yield exactly ONE success (the replay claim is atomic). Against the OLD code
// (fetch / SELECT last_used / UPDATE as three steps) BOTH could pass.
func TestVerifyTOTP_ConcurrentReplayRace_DB(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	id, secret := makeTOTPUser(t, pool, true) // enabled

	code, err := totp.GenerateCodeCustom(secret, time.Now(), totpValidateOpts)
	if err != nil {
		t.Fatalf("GenerateCodeCustom: %v", err)
	}

	const racers = 8
	var successes int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ok, verr := VerifyTOTP(ctx, pool, id, code)
			if verr == nil && ok {
				atomic.AddInt64(&successes, 1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := atomic.LoadInt64(&successes); got != 1 {
		t.Errorf("concurrent same-code verifies succeeded %d times, want exactly 1 (replay race)", got)
	}
}

// TestVerifyTOTP_GUCMissing_FailsClosed proves the totp_secret_enc family fails
// closed — never accepts a code, never returns a usable secret — when the
// AfterConnect hook that sets app.encryption_key is absent (a misconfigured or
// bypassed pool). Exercises the REAL VerifyTOTP code path.
func TestVerifyTOTP_GUCMissing_FailsClosed(t *testing.T) {
	seedPool := testsupport.OpenTestPoolWithGUC(t, totpIntegrationKey)
	id, secret := makeTOTPUser(t, seedPool, true) // enabled

	code, err := totp.GenerateCodeCustom(secret, time.Now(), totpValidateOpts)
	if err != nil {
		t.Fatalf("GenerateCodeCustom: %v", err)
	}

	noGUCPool := testsupport.OpenTestPoolWithGUC(t, "") // GUC never set
	ok, verr := VerifyTOTP(context.Background(), noGUCPool, id, code)
	if verr == nil {
		t.Fatal("VerifyTOTP must error when app.encryption_key GUC is unset, not silently succeed")
	}
	if ok {
		t.Fatal("VerifyTOTP must never accept a code when app.encryption_key GUC is unset")
	}
}

// TestVerifyTOTP_WrongGUC_FailsClosed proves the same family fails loudly (an
// error, not a garbage-secret false accept) when app.encryption_key is set to
// the WRONG value.
func TestVerifyTOTP_WrongGUC_FailsClosed(t *testing.T) {
	seedPool := testsupport.OpenTestPoolWithGUC(t, totpIntegrationKey)
	id, secret := makeTOTPUser(t, seedPool, true) // enabled

	code, err := totp.GenerateCodeCustom(secret, time.Now(), totpValidateOpts)
	if err != nil {
		t.Fatalf("GenerateCodeCustom: %v", err)
	}

	wrongPool := testsupport.OpenTestPoolWithGUC(t, "definitely-the-wrong-totp-key-x")
	ok, verr := VerifyTOTP(context.Background(), wrongPool, id, code)
	if verr == nil {
		t.Fatal("VerifyTOTP must error when app.encryption_key GUC is wrong, not silently succeed")
	}
	if ok {
		t.Fatal("VerifyTOTP must never accept a code when app.encryption_key GUC is wrong")
	}
}

// TestVerifyTOTPWithLockout_LocksAfterFailures_DB proves the shared lockout seam
// trips after totpMaxFailures consecutive bad codes and then short-circuits with
// TOTPLocked — the policy the forgot-password TOTP path now shares.
func TestVerifyTOTPWithLockout_LocksAfterFailures_DB(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	id, _ := makeTOTPUser(t, pool, true)

	for i := 0; i < totpMaxFailures; i++ {
		outcome, _ := VerifyTOTPWithLockout(ctx, pool, id, "000000")
		if outcome == TOTPAccepted {
			t.Fatalf("attempt %d: a wrong code must never be accepted", i+1)
		}
	}

	// The next attempt must be short-circuited as locked, even with a wrong code.
	outcome, _ := VerifyTOTPWithLockout(ctx, pool, id, "000000")
	if outcome != TOTPLocked {
		t.Errorf("after %d failures the account must be locked (TOTPLocked), got outcome %d",
			totpMaxFailures, outcome)
	}
}
