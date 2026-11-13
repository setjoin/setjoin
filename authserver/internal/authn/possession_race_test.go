package authn

// possession_race_test.go — DB race/fault tests for the possession gate's
// storage authority (scheme v7 §4.1, as feasible against a live test DB).
//
//   - TestGrantConsumeExactlyOnceConcurrent: N transactions race the
//     DELETE ... RETURNING consumption — exactly one commits.
//   - TestProofBudgetSerializedUnderLoad: the §2.3 management oracle —
//     N ≥ 5 concurrent evaluated failures of one method leave the counter
//     at EXACTLY 5 with the lock set by the 5th and every later attempt a
//     locked refusal that does NOT increment; zero grants issued.
//   - TestBudgetLockedRefusalDoesNotIncrement: while locked, refused
//     attempts leave counter and lock untouched (both possession pairs and
//     the TOTP pair through the shared cycle).
//   - TestTOTPBudgetMixedEntryPointsSerialize: failures through the shared
//     fenced cycle serialize under the users fence — the counter caps at
//     exactly 5 regardless of which entry point delivered the failure, and
//     later entrants are refused locked without increment (the lost-update
//     repair of the historical read-then-write RecordTOTPFailure).
//   - TestPausedLoginCannotClearConcurrentLock: the whole-cycle-in-one-
//     transaction property — a cycle that reads "unlocked" and pauses can
//     never clear a lock established before its reset, because the lock
//     check and the reset share the users fence.

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"
)

// possessionRaceUser seeds a throwaway user with an enabled TOTP secret.
func possessionRaceUser(t *testing.T, pool *pgxpool.Pool, label string, enabled bool) (int64, string) {
	t.Helper()
	userID, secret := makeTOTPUser(t, pool, enabled)
	if !enabled {
		var id int64
		if err := pool.QueryRow(context.Background(),
			`UPDATE users SET totp_enabled = TRUE, totp_enabled_at = now() WHERE id = $1 RETURNING id`,
			userID).Scan(&id); err != nil {
			t.Fatalf("enable totp fixture: %v", err)
		}
	}
	_ = label
	return userID, secret
}

func TestGrantConsumeExactlyOnceConcurrent(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	userID, _ := possessionRaceUser(t, pool, "consume-once", true)

	// Seed one live grant.
	if _, err := pool.Exec(ctx,
		`DELETE FROM mfa_reauth_step_ups WHERE user_id = $1`, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO mfa_reauth_step_ups
		   (token_hash, user_id, session_jti, operation, proof_method,
		    bound_factor_generation, token_scope, expires_at)
		 VALUES ('race-token-hash', $1, 'race-jti', 'recovery.regenerate', 'password',
		         (SELECT factor_generation FROM users WHERE id = $1),
		         'session', now() + interval '5 minutes')`, userID); err != nil {
		t.Fatal(err)
	}

	const racers = 8
	pred := GrantPredicate{
		TokenHash:   "race-token-hash",
		UserID:      userID,
		SessionJTI:  "race-jti",
		Operation:   "recovery.regenerate",
		TokenScope:  "session",
		FamilyBound: false,
	}
	var winners atomic.Int32
	var refused atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Errorf("begin: %v", err)
				return
			}
			defer func() { _ = tx.Rollback(ctx) }()
			if _, err := ConsumeGrant(ctx, tx, pred); err != nil {
				if err == ErrGrantRequired || IsGrantRequired(err) {
					refused.Add(1)
					return
				}
				t.Errorf("consume: %v", err)
				return
			}
			if err := tx.Commit(ctx); err != nil {
				t.Errorf("commit: %v", err)
				return
			}
			winners.Add(1)
		}()
	}
	wg.Wait()

	if winners.Load() != 1 {
		t.Fatalf("winners = %d, want exactly 1", winners.Load())
	}
	if refused.Load() != racers-1 {
		t.Fatalf("refused = %d, want %d", refused.Load(), racers-1)
	}
}

// IsGrantRequired reports whether err is the missing-grant sentinel (the
// exported seam for the handler package's errors.Is usage).
func IsGrantRequired(err error) bool { return err == ErrGrantRequired }

func TestProofBudgetSerializedUnderLoad(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	for _, method := range []string{ProofMethodPassword, ProofMethodWebAuthn} {
		t.Run(method, func(t *testing.T) {
			userID, _ := possessionRaceUser(t, pool, "budget-"+method, false)
			if _, err := pool.Exec(ctx,
				`UPDATE users SET possession_password_failed_attempts = 0,
				                  possession_password_locked_until = NULL,
				                  possession_webauthn_failed_attempts = 0,
				                  possession_webauthn_locked_until = NULL
				  WHERE id = $1`, userID); err != nil {
				t.Fatal(err)
			}

			const racers = 8
			var locked atomic.Int32
			var wg sync.WaitGroup
			for i := 0; i < racers; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					tx, err := pool.Begin(ctx)
					if err != nil {
						t.Errorf("begin: %v", err)
						return
					}
					defer func() { _ = tx.Rollback(ctx) }()
					// The §2.2 fences, then the single-statement increment —
					// the shape the issuance transactions run.
					if err := PersonFence(ctx, tx, userID); err != nil {
						t.Errorf("fence: %v", err)
						return
					}
					if _, err := UsersFence(ctx, tx, userID); err != nil {
						t.Errorf("users fence: %v", err)
						return
					}
					isLocked, err := RecordPossessionFailure(ctx, tx, method, userID)
					if err != nil {
						t.Errorf("increment: %v", err)
						return
					}
					if err := tx.Commit(ctx); err != nil {
						t.Errorf("commit: %v", err)
						return
					}
					if isLocked {
						locked.Add(1)
					}
				}()
			}
			wg.Wait()

			state, err := LoadPossessionBudget(ctx, pool, method, userID)
			if err != nil {
				t.Fatal(err)
			}
			if state.FailedAttempts != 5 {
				t.Fatalf("counter = %d, want EXACTLY 5 (evaluated failures capped by the lock)", state.FailedAttempts)
			}
			if !state.Locked(time.Now()) {
				t.Fatal("lock timestamp not set by the 5th failure")
			}
			// Later entrants are locked refusals that do not increment.
			tx2, _ := pool.Begin(ctx)
			defer tx2.Rollback(ctx)
			isLocked, err := RecordPossessionFailure(ctx, tx2, method, userID)
			if err != nil {
				t.Fatal(err)
			}
			if !isLocked {
				t.Fatal("locked budget must report refusal, not increment")
			}
			after, _ := LoadPossessionBudget(ctx, pool, method, userID)
			if after.FailedAttempts != 5 {
				t.Fatalf("locked refusal incremented the counter: %d", after.FailedAttempts)
			}
			_ = locked.Load()
		})
	}
}

func TestBudgetLockedRefusalDoesNotIncrement_TOTPCycle(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	userID, secret := possessionRaceUser(t, pool, "totp-locked", true)

	badCode := "000000"
	// Drive 5 evaluated failures through the shared fenced cycle.
	for i := 0; i < 5; i++ {
		outcome, err := VerifyTOTPWithLockout(ctx, pool, userID, badCode)
		if err != nil {
			t.Fatalf("cycle %d: %v", i, err)
		}
		if outcome != TOTPInvalid {
			t.Fatalf("cycle %d outcome = %v, want TOTPInvalid", i, outcome)
		}
	}
	// The 6th is refused LOCKED without verify and without increment.
	outcome, err := VerifyTOTPWithLockout(ctx, pool, userID, badCode)
	if err != nil {
		t.Fatal(err)
	}
	if outcome != TOTPLocked {
		t.Fatalf("outcome = %v, want TOTPLocked", outcome)
	}
	var attempts int
	var lockUntil *time.Time
	if err := pool.QueryRow(ctx,
		`SELECT totp_failed_attempts, totp_locked_until FROM users WHERE id = $1`, userID,
	).Scan(&attempts, &lockUntil); err != nil {
		t.Fatal(err)
	}
	if attempts != 5 {
		t.Fatalf("counter = %d, want exactly 5", attempts)
	}
	if lockUntil == nil {
		t.Fatal("lock not set")
	}
	// A VALID code is also refused while locked — without consuming it.
	valid, err := totp.GenerateCodeCustom(secret, time.Now(), totpValidateOpts)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err = VerifyTOTPWithLockout(ctx, pool, userID, valid)
	if err != nil {
		t.Fatal(err)
	}
	if outcome != TOTPLocked {
		t.Fatalf("valid code under lock: outcome = %v, want TOTPLocked (refused without evaluation)", outcome)
	}
	after, _ := LoadTOTPLockState(ctx, pool, userID)
	if after.FailedAttempts != 5 {
		t.Fatalf("locked refusal moved the counter: %d", after.FailedAttempts)
	}
}

func TestTOTPBudgetMixedEntryPointsSerialize(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	userID, _ := possessionRaceUser(t, pool, "mixed", true)
	if _, err := pool.Exec(ctx,
		`UPDATE users SET totp_failed_attempts = 0, totp_locked_until = NULL WHERE id = $1`, userID,
	); err != nil {
		t.Fatal(err)
	}

	// The three shared-cycle entry points deliver concurrent evaluated
	// failures against ONE users-row budget. The fence serializes them;
	// regardless of interleaving the counter caps at EXACTLY 5 with the lock
	// set, and every subsequent entrant (from every entry point) is refused
	// locked WITHOUT increment — no lost update.
	const racers = 12
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			outcome, _ := VerifyTOTPWithLockout(ctx, pool, userID, "000000")
			if outcome == TOTPBookkeepingError {
				t.Error("bookkeeping error under load")
			}
		}()
	}
	wg.Wait()

	state, err := LoadTOTPLockState(ctx, pool, userID)
	if err != nil {
		t.Fatal(err)
	}
	if state.FailedAttempts != 5 {
		t.Fatalf("counter = %d, want exactly 5", state.FailedAttempts)
	}
	if !state.Locked(time.Now()) {
		t.Fatal("lock not set by the 5th failure")
	}
}

func TestPausedLoginCannotClearConcurrentLock(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	userID, secret := possessionRaceUser(t, pool, "paused", true)

	// (i) A login cycle that read "unlocked" and then PAUSES can never clear
	// a lock established before its reset: with the fence held by the test
	// (standing in for the pause), a concurrent lock commits, and the
	// resumed cycle's step 1 re-reads state under the fence → TOTPLocked
	// WITHOUT verify, WITHOUT reset.
	// The reset runs BEFORE the fence is taken — the fence is a row lock on
	// the same users row, and a pool-level write would self-block behind it.
	if _, err := pool.Exec(ctx,
		`UPDATE users SET totp_failed_attempts = 0, totp_locked_until = NULL WHERE id = $1`, userID,
	); err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := UsersFence(ctx, tx, userID); err != nil { // the pause holds the fence
		t.Fatal(err)
	}

	resumed := make(chan TOTPVerifyOutcome, 1)
	go func() {
		// This cycle BLOCKS on the users fence until the pause commits —
		// its reset, if it ran, would erase the concurrent lock.
		outcome, _ := VerifyTOTPWithLockout(ctx, pool, userID, "000000")
		resumed <- outcome
	}()

	time.Sleep(50 * time.Millisecond) // let the goroutine park on the fence
	// Concurrent failures commit while the login is paused: the budget locks
	// at the 5th evaluated failure.
	if _, err := tx.Exec(ctx,
		`UPDATE users SET totp_failed_attempts = 5,
		                  totp_locked_until = now() + interval '15 minutes'
		  WHERE id = $1`, userID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	select {
	case outcome := <-resumed:
		if outcome != TOTPLocked {
			t.Fatalf("(i) resumed login outcome = %v, want TOTPLocked — the stale-unlocked reset never ran", outcome)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("(i) resumed cycle never completed (fence deadlock?)")
	}

	// (ii) A reset never runs against a lock established before its read:
	// the failures-first ordering — the cycle's step 1 sees the lock and
	// refuses without verify.
	if _, err := pool.Exec(ctx,
		`UPDATE users SET totp_failed_attempts = 5,
		                  totp_locked_until = now() + interval '15 minutes'
		  WHERE id = $1`, userID); err != nil {
		t.Fatal(err)
	}
	outcome, err := VerifyTOTPWithLockoutTx(ctx, pool, userID, "000000")
	_ = err
	if outcome != TOTPLocked {
		t.Fatalf("(ii) outcome = %v, want TOTPLocked without verify", outcome)
	}

	// (iii) The SUCCESSFUL-LOGIN-FIRST interleaving (r2 defect 5b): a login
	// cycle that verifies a VALID code commits its reset BEFORE the
	// concurrent failures commit — and the account STILL locks at exactly
	// the 5th evaluated failure. A successful reset never immunizes the
	// account against the failures that follow it, and the reset-then-fail
	// ordering never yields a lost update.
	if _, err := pool.Exec(ctx,
		`UPDATE users SET totp_failed_attempts = 3, totp_locked_until = NULL WHERE id = $1`, userID,
	); err != nil {
		t.Fatal(err)
	}
	valid, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("valid code: %v", err)
	}
	good, err := VerifyTOTPWithLockout(ctx, pool, userID, valid)
	if err != nil || good != TOTPAccepted {
		t.Fatalf("(iii) successful login outcome = %v (%v), want TOTPAccepted", good, err)
	}
	state, err := LoadTOTPLockState(ctx, pool, userID)
	if err != nil {
		t.Fatal(err)
	}
	if state.FailedAttempts != 0 || state.Locked(time.Now()) {
		t.Fatalf("(iii) post-success state = %+v, want a cleared counter and no lock", state)
	}

	// The failures initiated AFTER the successful login (freshly minted
	// codes would still be mid-flight in a real browser; here the racer
	// goroutines are launched after the reset committed) still serialize
	// through the ONE cycle: counter EXACTLY 5, lock set by the 5th.
	const racers = 12
	var wg2 sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			out, _ := VerifyTOTPWithLockout(ctx, pool, userID, "000000")
			if out == TOTPBookkeepingError {
				t.Error("bookkeeping error under load (iii)")
			}
		}()
	}
	wg2.Wait()
	state, err = LoadTOTPLockState(ctx, pool, userID)
	if err != nil {
		t.Fatal(err)
	}
	if state.FailedAttempts != 5 {
		t.Fatalf("(iii) counter = %d after the successful-login-first interleaving, want exactly 5 (no lost update, no immunization)", state.FailedAttempts)
	}
	if !state.Locked(time.Now()) {
		t.Fatal("(iii) lock not set by the 5th evaluated failure after the successful reset")
	}
}

// waitForDBWaiter polls pg_stat_activity until at least one OTHER session is
// parked on the named lock wait event running a query matching queryLike —
// the OBSERVED database wait state that replaces sleep-based sequencing in
// the race tests (r3 acceptance F): the test releases a gate only after the
// waiter it means to interleave is demonstrably queued. The observer runs on
// a DEDICATED connection (acquire one before anything parks): the parked
// goroutines hold the fixture pool's connections, so a pool-level poll would
// starve in Acquire.
func waitForDBWaiter(t *testing.T, q interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}, waitEvent, queryLike string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var n int
		err := q.QueryRow(context.Background(), `
			SELECT count(*) FROM pg_stat_activity
			 WHERE datname = current_database()
			   AND wait_event_type = 'Lock'
			   AND wait_event = $1
			   AND pid <> pg_backend_pid()
			   AND query ILIKE $2`,
			waitEvent, "%"+queryLike+"%").Scan(&n)
		if err == nil && n > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no session observed waiting %q on query ~%q within 10s", waitEvent, queryLike)
}

// TestPausedLoginResetBeforeCommitDoesNotImmunize is the r3 acceptance
// successful-login-first interleaving: the login is PAUSED after its budget
// reset but BEFORE its response commit (an advisory-gate trigger parks the
// reset statement mid-transaction while the login tx holds the users fence),
// concurrent failures are fired INTO that pause — observed parked on the
// fence via pg_stat_activity, not sleeps — and only then is the login
// released. The reset commits first and the failures run after it: the
// account STILL locks at exactly the 5th evaluated failure. A successful
// reset never immunizes the account against the failures that follow it in
// commit order, and the pause never lets the stale reset erase their
// increments.
func TestPausedLoginResetBeforeCommitDoesNotImmunize(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	userID, secret := possessionRaceUser(t, pool, "pause-reset", true)

	// Park the counter at 3 so the successful login's reset is a REAL rewrite
	// (3 → 0), not a no-op write of an already-zero counter.
	if _, err := pool.Exec(ctx,
		`UPDATE users SET totp_failed_attempts = 3, totp_locked_until = NULL WHERE id = $1`, userID,
	); err != nil {
		t.Fatal(err)
	}

	// The pause gate: the login tx's reset statement (totp_failed_attempts
	// 3 → 0) blocks on an advisory lock the test holds, keeping the fence
	// held with the reset applied-but-uncommitted.
	const gateKey = 918273647
	held, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	if _, err := held.Exec(ctx, `SELECT pg_advisory_lock($1)`, gateKey); err != nil {
		t.Fatal(err)
	}
	// The wait-state observer's own connection, taken BEFORE anything parks —
	// the parked goroutines hold the rest of the fixture pool.
	obs, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer obs.Release()
	if _, err := pool.Exec(ctx, `
		CREATE OR REPLACE FUNCTION possession_pause_reset_gate() RETURNS trigger AS $fn$
		BEGIN
			PERFORM pg_advisory_lock(918273647);
			PERFORM pg_advisory_unlock(918273647);
			RETURN NEW;
		END $fn$ LANGUAGE plpgsql`); err != nil {
		t.Fatal(err)
	}
	// Idempotent install: a previously timed-out run can leave the gate
	// behind (the panic path skips t.Cleanup).
	if _, err := pool.Exec(ctx, `DROP TRIGGER IF EXISTS possession_pause_reset_gate ON users`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		CREATE TRIGGER possession_pause_reset_gate
		AFTER UPDATE OF totp_failed_attempts ON users
		FOR EACH ROW
		WHEN (NEW.id = `+strconv.FormatInt(userID, 10)+` AND NEW.totp_failed_attempts = 0 AND OLD.totp_failed_attempts <> 0)
		EXECUTE FUNCTION possession_pause_reset_gate()`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS possession_pause_reset_gate ON users`)
		_, _ = pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS possession_pause_reset_gate()`)
	})

	// The successful login: fences, verifies the VALID code, applies its
	// reset — and parks at the gate, holding the users row fence.
	valid, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("valid code: %v", err)
	}
	loginDone := make(chan TOTPVerifyOutcome, 1)
	go func() {
		outcome, _ := VerifyTOTPWithLockout(ctx, pool, userID, valid)
		loginDone <- outcome
	}()
	// Observed park: the login's reset statement waiting on the advisory gate.
	waitForDBWaiter(t, obs, "advisory", "totp_failed_attempts = 0")

	// Fire the concurrent failures INTO the pause. Each blocks on the users
	// fence the paused login holds — observed, not assumed.
	const racers = 8
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, _ := VerifyTOTPWithLockout(ctx, pool, userID, "000000")
			if out == TOTPBookkeepingError {
				t.Error("bookkeeping error under the paused-login race")
			}
		}()
	}
	// Observed queue: failure cycles parked on the transactionid the paused
	// login holds (its fence SELECT ... FOR NO KEY UPDATE).
	waitForDBWaiter(t, obs, "transactionid", "FOR NO KEY UPDATE")

	// Release: the reset commits (TOTPAccepted), the fence frees, and the
	// queued failures run against the post-reset budget — 0 → 5, lock set.
	if _, err := held.Exec(ctx, `SELECT pg_advisory_unlock($1)`, gateKey); err != nil {
		t.Fatal(err)
	}
	select {
	case outcome := <-loginDone:
		if outcome != TOTPAccepted {
			t.Fatalf("paused login outcome = %v, want TOTPAccepted", outcome)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("paused login never completed after the gate release")
	}
	wg.Wait()

	state, err := LoadTOTPLockState(ctx, pool, userID)
	if err != nil {
		t.Fatal(err)
	}
	if state.FailedAttempts != 5 {
		t.Fatalf("counter = %d after the paused-login interleaving, want EXACTLY 5 (no lost update, no immunization)", state.FailedAttempts)
	}
	if !state.Locked(time.Now()) {
		t.Fatal("lock not set by the 5th evaluated failure after the successful reset")
	}
}
