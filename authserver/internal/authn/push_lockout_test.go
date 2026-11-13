package authn

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/testsupport"
)

// pushLockoutLogger returns a no-op slog logger so the seam's lockout-engaged
// warning never panics on a nil logger in tests.
func pushLockoutLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// ── Policy pin: the push seam shares the documented TOTP lockout policy ──────

// TestPushLockout_PinnedToTOTPPolicy is the lockout-threshold reconciliation
// the security proposal requires: the push recovery seam's threshold is pinned
// to the SAME documented threshold as the TOTP seam (5, not the per-challenge
// burn at 3), and the lockout window equals the TOTP lock duration. The
// constants are compile-time aliases of the TOTP constants, so this test also
// fails if anyone de-aliases them into independent values.
func TestPushLockout_PinnedToTOTPPolicy(t *testing.T) {
	if pushVerifyMaxFailures != totpMaxFailures {
		t.Errorf("push recovery threshold = %d, want the SAME documented threshold as TOTP (%d)",
			pushVerifyMaxFailures, totpMaxFailures)
	}
	if pushVerifyMaxFailures != 5 {
		t.Errorf("push recovery threshold = %d, want 5 (documented TOTP threshold)", pushVerifyMaxFailures)
	}
	if pushVerifyLockWindow != totpLockDuration {
		t.Errorf("push lockout window = %v, want the SAME window as the TOTP lock (%v)",
			pushVerifyLockWindow, totpLockDuration)
	}
}

// ── Pure accumulation-window logic ──────────────────────────────────────────

// TestPushWindowPriorFailures proves the window semantics that replaced the old
// in-process counter: failures last touched within the window accumulate, and a
// failure arriving after the window has passed restarts the count instead of
// stacking onto stale failures (so 4 old failures + 1 new one does not lock).
func TestPushWindowPriorFailures(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	if got := pushWindowPriorFailures(4, now.Add(-pushVerifyLockWindow+time.Second), now); got != 4 {
		t.Errorf("failures inside the window must accumulate: got %d, want 4", got)
	}
	// At exactly the window age the failures are stale (>= semantics, matching
	// the previous in-process counter).
	if got := pushWindowPriorFailures(4, now.Add(-pushVerifyLockWindow), now); got != 0 {
		t.Errorf("failures at the window boundary must restart the count: got %d, want 0", got)
	}
	if got := pushWindowPriorFailures(4, now.Add(-2*pushVerifyLockWindow), now); got != 0 {
		t.Errorf("stale failures must restart the count: got %d, want 0", got)
	}
}

// ── Fail-closed on an unreachable DB ─────────────────────────────────────────

// TestVerifyChallengeWithLockout_UnreachableDBFailsClosed is the round-2
// fail-closed invariant: with the database unreachable, the seam REJECTS (the
// uniform PushVerifyInvalid plus a logged error) — it never falls through to
// verification, never grants access, and never reports a lock it cannot read.
// (The round-1 seam failed open here: a purpose-read error silently proceeded
// to verification.)
func TestVerifyChallengeWithLockout_UnreachableDBFailsClosed(t *testing.T) {
	p := &NumberMatchPushProvider{pool: closedPool(t), logger: pushLockoutLogger()}
	outcome, err := p.VerifyChallengeWithLockout(context.Background(), 42, "00ff", "42")
	if outcome == PushVerifyAccepted {
		t.Fatal("a DB error must NEVER yield PushVerifyAccepted (would grant access on failure)")
	}
	if outcome == PushVerifyLocked {
		t.Fatal("an unreadable lock state must not be reported as a lock")
	}
	if outcome != PushVerifyInvalid {
		t.Fatalf("outcome on DB error = %d, want PushVerifyInvalid (fail-closed rejection)", outcome)
	}
	if err == nil {
		t.Fatal("a fail-closed rejection must return the error so the caller can log it")
	}
}

// TestVerifyChallengeWithLockout_InvalidNonceIsUniformInvalid proves the
// uniform contract for garbage input: an undecodable nonce is PushVerifyInvalid
// (the wire 401) with no error and no DB round trip, indistinguishable from a
// wrong answer.
func TestVerifyChallengeWithLockout_InvalidNonceIsUniformInvalid(t *testing.T) {
	p := &NumberMatchPushProvider{pool: closedPool(t), logger: pushLockoutLogger()}
	outcome, err := p.VerifyChallengeWithLockout(context.Background(), 42, "not-hex-zz", "00")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if outcome != PushVerifyInvalid {
		t.Errorf("undecodable nonce outcome = %d, want PushVerifyInvalid", outcome)
	}
}

// ── DB-backed suite (shared auth_lockouts storage) ───────────────────────────

// newPushLockoutDBProvider builds a provider over the shared test database.
// Tests skip (not fail) when DB_DSN is unset, per the shared connect-or-skip
// policy; CI sets REQUIRE_DB so the suite cannot silently skip there.
func newPushLockoutDBProvider(t *testing.T) (*NumberMatchPushProvider, *pgxpool.Pool) {
	t.Helper()
	pool := testsupport.OpenTestPool(t)
	return &NumberMatchPushProvider{pool: pool, logger: pushLockoutLogger()}, pool
}

// seedPushRecoveryUser creates a disposable account for the lockout tests and
// registers cleanup for its challenge, lockout, and user rows.
func seedPushRecoveryUser(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	ctx := context.Background()

	// Fresh CI databases seed no is_local domain (dev-DB residue used to mask
	// this) — self-seed a unique one instead of skipping. Skipping is exactly
	// what REQUIRE_DB exists to prevent: these tests cover the recovery
	// lockout seam, the paths CI most needs to execute.
	domainName := fmt.Sprintf("push-lockout-test-%d.example", time.Now().UnixNano())
	var domainID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`, domainName,
	).Scan(&domainID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM domains WHERE id = $1`, domainID)
	})
	var userID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, sync_source, enabled, password_hash, must_change_password)
		 VALUES ($1, $1, 'push lockout test', $2, 'local', TRUE, 'x', FALSE) RETURNING id`,
		fmt.Sprintf("push-lockout-%d@example.com", time.Now().UnixNano()), domainID,
	).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM push_mfa_challenges WHERE user_id = $1`, userID)
		pool.Exec(ctx, `DELETE FROM auth_lockouts WHERE lockout_key = $1`, pushLockoutKey(userID))
		pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
	})
	return userID
}

// seedPushRecoveryChallenge inserts an active, purpose-stamped recovery
// challenge with a KNOWN code ("42") so tests can submit exact wrong/correct
// answers without the push dispatch machinery.
func seedPushRecoveryChallenge(t *testing.T, pool *pgxpool.Pool, userID int64) (nonceHex, code string) {
	t.Helper()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	nonceHex = hex.EncodeToString(nonce)
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO push_mfa_challenges (user_id, challenge_code, nonce, session_id, expires_at)
		 VALUES ($1, '42', decode($2, 'hex'), $3, now() + interval '120 seconds')`,
		userID, nonceHex, ForgotPasswordChallengePurpose,
	); err != nil {
		t.Fatalf("seed challenge: %v", err)
	}
	return nonceHex, "42"
}

// pushLockoutRowCount reads the account's shared failure counter.
func pushLockoutRowCount(t *testing.T, pool *pgxpool.Pool, userID int64) (count int, lockedUntil time.Time, exists bool) {
	t.Helper()
	err := pool.QueryRow(context.Background(),
		`SELECT failed_count, locked_until FROM auth_lockouts WHERE lockout_key = $1`,
		pushLockoutKey(userID),
	).Scan(&count, &lockedUntil)
	if err != nil {
		return 0, time.Time{}, false
	}
	return count, lockedUntil, true
}

// TestVerifyChallengeWithLockout_LocksAtFifthFailure_DB is the core live-DB
// lockout proof against the SHARED auth_lockouts row: five failed answers (the
// first four on one challenge — proving the per-challenge burn at 3 keeps
// counting toward the account budget once burned — the fifth on a fresh one,
// the cross-challenge grinding case) trip the ACCOUNT-level lock, and once it
// trips even a CORRECT answer is refused without being verified. A second
// account is untouched (per-account, never per-challenge or per-IP), and expiry
// restores verification.
func TestVerifyChallengeWithLockout_LocksAtFifthFailure_DB(t *testing.T) {
	p, pool := newPushLockoutDBProvider(t)
	ctx := context.Background()

	userA := seedPushRecoveryUser(t, pool)

	// Four wrong answers on one challenge (the challenge burns at 3; the
	// 4th still counts toward the account budget).
	nonce, _ := seedPushRecoveryChallenge(t, pool, userA)
	for i := 1; i <= 4; i++ {
		outcome, err := p.VerifyChallengeWithLockout(ctx, userA, nonce, "07")
		if err != nil {
			t.Fatalf("attempt %d: unexpected error: %v", i, err)
		}
		if outcome != PushVerifyInvalid {
			t.Fatalf("attempt %d: outcome = %d, want PushVerifyInvalid", i, outcome)
		}
	}
	if count, _, ok := pushLockoutRowCount(t, pool, userA); !ok || count != 4 {
		t.Fatalf("after 4 failures: count=%d exists=%v, want 4", count, ok)
	}

	// The 5th failure arrives on a FRESH challenge (mint-new-challenge
	// grinding): it must trip the account lock.
	nonce, _ = seedPushRecoveryChallenge(t, pool, userA)
	if outcome, err := p.VerifyChallengeWithLockout(ctx, userA, nonce, "07"); err != nil || outcome != PushVerifyInvalid {
		t.Fatalf("5th attempt: outcome=%d err=%v, want PushVerifyInvalid/nil", outcome, err)
	}
	count, lockedUntil, ok := pushLockoutRowCount(t, pool, userA)
	if !ok || count != pushVerifyMaxFailures {
		t.Fatalf("after 5 failures: count=%d exists=%v, want %d", count, ok, pushVerifyMaxFailures)
	}
	if !lockedUntil.After(time.Now()) {
		t.Fatal("the 5th failure must lock the account")
	}

	// While locked, even the CORRECT answer is refused without verification.
	nonce, code := seedPushRecoveryChallenge(t, pool, userA)
	outcome, err := p.VerifyChallengeWithLockout(ctx, userA, nonce, code)
	if err != nil {
		t.Fatalf("locked correct attempt: unexpected error: %v", err)
	}
	if outcome != PushVerifyLocked {
		t.Fatalf("locked correct attempt outcome = %d, want PushVerifyLocked (429 path)", outcome)
	}
	var verified int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM push_mfa_challenges WHERE nonce = decode($1, 'hex') AND verified_at IS NOT NULL`,
		nonce,
	).Scan(&verified); err != nil {
		t.Fatal(err)
	}
	if verified != 0 {
		t.Fatal("a locked attempt must never consume/verify a challenge")
	}

	// Another account is NOT locked by user A's failures.
	userB := seedPushRecoveryUser(t, pool)
	nonceB, codeB := seedPushRecoveryChallenge(t, pool, userB)
	if outcome, err := p.VerifyChallengeWithLockout(ctx, userB, nonceB, codeB); err != nil || outcome != PushVerifyAccepted {
		t.Fatalf("user B must be unaffected: outcome=%d err=%v, want PushVerifyAccepted/nil", outcome, err)
	}

	// Once the lock expires, verification is attempted again: a correct answer
	// is accepted and the counter resets.
	if _, err := pool.Exec(ctx,
		`UPDATE auth_lockouts SET locked_until = now() - interval '1 second' WHERE lockout_key = $1`,
		pushLockoutKey(userA),
	); err != nil {
		t.Fatal(err)
	}
	nonce, code = seedPushRecoveryChallenge(t, pool, userA)
	if outcome, err := p.VerifyChallengeWithLockout(ctx, userA, nonce, code); err != nil || outcome != PushVerifyAccepted {
		t.Fatalf("post-expiry correct attempt: outcome=%d err=%v, want PushVerifyAccepted/nil", outcome, err)
	}
	if count, _, ok := pushLockoutRowCount(t, pool, userA); !ok || count != 0 {
		t.Fatalf("success must reset the shared counter: count=%d exists=%v, want 0", count, ok)
	}
}

// TestVerifyChallengeWithLockout_WindowRestartsCount_DB proves the accumulation
// window on the shared row: failures older than pushVerifyLockWindow restart
// the count, so 4 stale failures + 1 fresh one does NOT lock.
func TestVerifyChallengeWithLockout_WindowRestartsCount_DB(t *testing.T) {
	p, pool := newPushLockoutDBProvider(t)
	ctx := context.Background()

	user := seedPushRecoveryUser(t, pool)
	for i := 0; i < pushVerifyMaxFailures-1; i++ {
		nonce, _ := seedPushRecoveryChallenge(t, pool, user)
		if outcome, err := p.VerifyChallengeWithLockout(ctx, user, nonce, "07"); err != nil || outcome != PushVerifyInvalid {
			t.Fatalf("attempt %d: outcome=%d err=%v, want PushVerifyInvalid/nil", i+1, outcome, err)
		}
	}

	// Age every failure out of the window, then fail once more.
	if _, err := pool.Exec(ctx,
		`UPDATE auth_lockouts SET updated_at = now() - make_interval(secs => $1) WHERE lockout_key = $2`,
		(2 * pushVerifyLockWindow).Seconds(), pushLockoutKey(user),
	); err != nil {
		t.Fatal(err)
	}
	nonce, _ := seedPushRecoveryChallenge(t, pool, user)
	if outcome, err := p.VerifyChallengeWithLockout(ctx, user, nonce, "07"); err != nil || outcome != PushVerifyInvalid {
		t.Fatalf("stale-window attempt: outcome=%d err=%v, want PushVerifyInvalid/nil", outcome, err)
	}
	count, lockedUntil, ok := pushLockoutRowCount(t, pool, user)
	if !ok || count != 1 {
		t.Fatalf("stale failures must restart the count: count=%d exists=%v, want 1", count, ok)
	}
	if lockedUntil.After(time.Now()) {
		t.Fatal("a single fresh failure after a window restart must not lock")
	}

	// Still unlocked: the correct answer is accepted and resets the counter.
	nonce, code := seedPushRecoveryChallenge(t, pool, user)
	if outcome, err := p.VerifyChallengeWithLockout(ctx, user, nonce, code); err != nil || outcome != PushVerifyAccepted {
		t.Fatalf("correct answer after window restart: outcome=%d err=%v, want PushVerifyAccepted/nil", outcome, err)
	}
}

// TestVerifyChallengeWithLockout_ConcurrentExactCount is the round-2
// concurrency regression for the exact attack the seam exists for: 10
// goroutines simultaneously submit wrong answers, each against its own fresh
// purpose-stamped challenge (the cross-challenge number-match grind). Because
// check, verification, and outcome recording run in ONE transaction holding
// the account's auth_lockouts row, the attempts serialize on that row: exactly
// the first pushVerifyMaxFailures to acquire it are verified (each recording
// exactly one failure, the 5th tripping the lock), every later attempt is
// Locked without verification, and the recorded budget equals the wrong
// answers — no lost updates, no double counting, no race past the threshold.
func TestVerifyChallengeWithLockout_ConcurrentExactCount(t *testing.T) {
	p, pool := newPushLockoutDBProvider(t)
	ctx := context.Background()

	user := seedPushRecoveryUser(t, pool)

	const attempts = 10
	nonces := make([]string, attempts)
	for i := range nonces {
		nonces[i], _ = seedPushRecoveryChallenge(t, pool, user)
	}

	type attempt struct {
		outcome PushVerifyOutcome
		err     error
	}
	results := make([]attempt, attempts)
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			outcome, err := p.VerifyChallengeWithLockout(ctx, user, nonces[i], "07")
			results[i] = attempt{outcome, err}
		}(i)
	}
	wg.Wait()

	processed, lockedOut := 0, 0
	for i, r := range results {
		if r.err != nil {
			t.Fatalf("attempt %d: unexpected error: %v", i+1, r.err)
		}
		switch r.outcome {
		case PushVerifyInvalid:
			processed++
		case PushVerifyLocked:
			lockedOut++
		default:
			t.Fatalf("attempt %d: outcome = %d; a wrong answer must never be Accepted", i+1, r.outcome)
		}
	}
	if processed != pushVerifyMaxFailures {
		t.Errorf("processed attempts = %d, want exactly %d (the serialized budget; the rest must be locked, not verified)",
			processed, pushVerifyMaxFailures)
	}
	if lockedOut != attempts-pushVerifyMaxFailures {
		t.Errorf("locked attempts = %d, want %d (once the 5th failure lands ALL subsequent attempts are locked)",
			lockedOut, attempts-pushVerifyMaxFailures)
	}

	// Every wrong answer recorded EXACTLY one failure on the shared row — the
	// 5 processed failures plus count-only records for the refused attempts —
	// none lost, none double-counted.
	count, lockedUntil, ok := pushLockoutRowCount(t, pool, user)
	if !ok || count != attempts {
		t.Errorf("recorded failures = %d (exists=%v), want exactly %d — one per wrong answer",
			count, ok, attempts)
	}
	if !lockedUntil.After(time.Now()) {
		t.Error("the threshold failure must have locked the account")
	}

	// Once tripped, the lock holds for fresh attempts even with correct answers.
	nonce2, code2 := seedPushRecoveryChallenge(t, pool, user)
	if outcome, err := p.VerifyChallengeWithLockout(ctx, user, nonce2, code2); err != nil || outcome != PushVerifyLocked {
		t.Fatalf("post-race attempt: outcome=%d err=%v, want PushVerifyLocked/nil", outcome, err)
	}
}

// TestVerifyChallengeWithLockout_ConcurrentSingleChallenge pins the interaction
// of the two controls when 10 goroutines hammer ONE challenge: the per-challenge
// burn at 3 must hold (failed_attempts <= 3, exactly one answer reaching the
// burn), every attempt is refused, and the answers arriving after the burn are
// purpose mismatches (no active challenge) that are deliberately NOT recorded —
// a garbage or stale nonce never compares the answer and must never become
// free lockout ammunition against an account.
func TestVerifyChallengeWithLockout_ConcurrentSingleChallenge(t *testing.T) {
	p, pool := newPushLockoutDBProvider(t)
	ctx := context.Background()

	user := seedPushRecoveryUser(t, pool)
	nonce, _ := seedPushRecoveryChallenge(t, pool, user)

	const attempts = 10
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			outcome, err := p.VerifyChallengeWithLockout(ctx, user, nonce, "07")
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if outcome != PushVerifyInvalid {
				t.Errorf("outcome = %d, want PushVerifyInvalid for every wrong answer on one challenge", outcome)
			}
		}()
	}
	wg.Wait()

	var fa int
	var verified bool
	if err := pool.QueryRow(ctx,
		`SELECT COALESCE(failed_attempts, 0), COALESCE(verified_at IS NOT NULL, FALSE)
		 FROM push_mfa_challenges WHERE nonce = decode($1, 'hex')`,
		nonce,
	).Scan(&fa, &verified); err != nil {
		t.Fatal(err)
	}
	if fa > 3 {
		t.Errorf("challenge failed_attempts = %d, want <= 3 (per-challenge burn must hold under concurrency)", fa)
	}
	if !verified {
		t.Error("a concurrently exhausted challenge must end up burned (verified_at set)")
	}
	// Only the attempts that found the challenge active were recorded
	// (three wrong-answer increments + the burn); the rest were unrecorded
	// mismatches, so the account is NOT yet locked.
	count, lockedUntil, ok := pushLockoutRowCount(t, pool, user)
	if !ok || count != 4 {
		t.Errorf("recorded failures = %d (exists=%v), want 4 (3 increments + the burn)", count, ok)
	}
	if lockedUntil.After(time.Now()) {
		t.Error("a single burned challenge must not by itself trip the account lock")
	}

	// The next REAL attempt (fresh active challenge, still a wrong answer)
	// records the 5th failure and trips the lock.
	nonce2, _ := seedPushRecoveryChallenge(t, pool, user)
	if outcome, err := p.VerifyChallengeWithLockout(ctx, user, nonce2, "07"); err != nil || outcome != PushVerifyInvalid {
		t.Fatalf("5th failure attempt: outcome=%d err=%v, want PushVerifyInvalid/nil", outcome, err)
	}
	if _, lockedUntil, _ := pushLockoutRowCount(t, pool, user); !lockedUntil.After(time.Now()) {
		t.Fatal("the 5th recorded failure must trip the account lock")
	}
}

// TestVerifyChallengeWithLockout_CrossReplicaSharesBudget simulates two
// authserver replicas as two provider instances over the SAME database: five
// failures split across the two instances must trip ONE shared lock (5 total,
// not 10), and both replicas must observe it.
func TestVerifyChallengeWithLockout_CrossReplicaSharesBudget(t *testing.T) {
	pA, pool := newPushLockoutDBProvider(t)
	pB := &NumberMatchPushProvider{pool: pool, logger: pushLockoutLogger()}
	ctx := context.Background()

	user := seedPushRecoveryUser(t, pool)

	// Alternate wrong answers between the "replicas", each on a fresh challenge.
	for i := 0; i < pushVerifyMaxFailures; i++ {
		p := pA
		if i%2 == 1 {
			p = pB
		}
		nonce, _ := seedPushRecoveryChallenge(t, pool, user)
		if outcome, err := p.VerifyChallengeWithLockout(ctx, user, nonce, "07"); err != nil || outcome != PushVerifyInvalid {
			t.Fatalf("replica-%d attempt %d: outcome=%d err=%v, want PushVerifyInvalid/nil",
				i%2+1, i+1, outcome, err)
		}
	}

	// The shared budget is exhausted at 5 TOTAL (not 10): both replicas see the lock.
	for _, rp := range []struct {
		name string
		p    *NumberMatchPushProvider
	}{{"replica-1", pA}, {"replica-2", pB}} {
		nonce, code := seedPushRecoveryChallenge(t, pool, user)
		outcome, err := rp.p.VerifyChallengeWithLockout(ctx, user, nonce, code)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", rp.name, err)
		}
		if outcome != PushVerifyLocked {
			t.Fatalf("%s: outcome = %d, want PushVerifyLocked (the lock budget is shared DB state, not per-process)", rp.name, outcome)
		}
	}
}

// TestVerifyChallengeWithLockout_PurposeTransientErrorFailsClosed is the
// round-2 fail-closed proof for the purpose probe: an injected transient
// purpose-read failure REJECTS the request (uniform invalid + error to log)
// instead of falling through to verification. The challenge is left untouched
// (not consumed, not burned) and no failure is recorded — the attempt never
// reached verification.
func TestVerifyChallengeWithLockout_PurposeTransientErrorFailsClosed(t *testing.T) {
	p, pool := newPushLockoutDBProvider(t)
	ctx := context.Background()

	user := seedPushRecoveryUser(t, pool)
	nonce, code := seedPushRecoveryChallenge(t, pool, user)

	p.purposeProbe = func(context.Context, lockoutQuerier, []byte, int64, string) (bool, error) {
		return false, errors.New("injected transient purpose-read failure")
	}

	outcome, err := p.VerifyChallengeWithLockout(ctx, user, nonce, code)
	if outcome != PushVerifyInvalid {
		t.Fatalf("outcome = %d, want PushVerifyInvalid (fail-closed rejection)", outcome)
	}
	if err == nil {
		t.Fatal("a transient purpose-read failure must surface an error for the caller to log")
	}

	// The request was NOT processed: the challenge is still active and
	// unverified, and nothing was recorded against the account.
	var active int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM push_mfa_challenges
		 WHERE nonce = decode($1, 'hex') AND verified_at IS NULL AND failed_attempts = 0`,
		nonce,
	).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 1 {
		t.Fatal("a fail-closed rejection must leave the challenge untouched (not consumed, not burned)")
	}
	if _, _, exists := pushLockoutRowCount(t, pool, user); exists {
		t.Fatal("a rejected-before-verification attempt must not create or mutate lockout state")
	}

	// A DEFINITIVE mismatch (false, nil error) stays the uniform invalid
	// outcome with no error — the fail-closed path is only for failures.
	p.purposeProbe = func(context.Context, lockoutQuerier, []byte, int64, string) (bool, error) {
		return false, nil
	}
	if outcome, err := p.VerifyChallengeWithLockout(ctx, user, nonce, code); err != nil || outcome != PushVerifyInvalid {
		t.Fatalf("definitive purpose mismatch: outcome=%d err=%v, want PushVerifyInvalid/nil", outcome, err)
	}
}

// TestChallengePurposeMatches_DB proves the session_id purpose binding against
// a live schema: only a challenge stamped with ForgotPasswordChallengePurpose
// matches; login-style stamps (an MFA token or empty session_id) and unknown
// nonces are rejected. The method returns errors instead of swallowing them
// (round-2 fail-closed contract).
func TestChallengePurposeMatches_DB(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	user := seedPushRecoveryUser(t, pool)
	p := &NumberMatchPushProvider{pool: pool}

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	nonceHex := hex.EncodeToString(nonce)
	if _, err := pool.Exec(ctx,
		`INSERT INTO push_mfa_challenges (user_id, challenge_code, nonce, session_id, expires_at)
		 VALUES ($1, '42', decode($2, 'hex'), $3, now() + interval '120 seconds')`,
		user, nonceHex, "some-login-mfa-token",
	); err != nil {
		t.Fatalf("seed challenge: %v", err)
	}

	// A login-generated challenge (real MFA-token session_id) is NOT consumable
	// on the recovery path.
	if matched, err := p.challengePurposeMatches(ctx, pool, nonce, user, ForgotPasswordChallengePurpose); err != nil || matched {
		t.Errorf("login-stamped challenge: matched=%v err=%v, want matched=false err=nil", matched, err)
	}

	// Re-stamp it as a recovery challenge: now it matches.
	if _, err := pool.Exec(ctx,
		`UPDATE push_mfa_challenges SET session_id = $2 WHERE user_id = $1 AND nonce = decode($3, 'hex')`,
		user, ForgotPasswordChallengePurpose, nonceHex,
	); err != nil {
		t.Fatal(err)
	}
	if matched, err := p.challengePurposeMatches(ctx, pool, nonce, user, ForgotPasswordChallengePurpose); err != nil || !matched {
		t.Errorf("recovery-stamped challenge: matched=%v err=%v, want matched=true err=nil", matched, err)
	}

	// An unknown nonce is checked but does not match.
	if matched, err := p.challengePurposeMatches(ctx, pool, []byte{0x00, 0xff}, user, ForgotPasswordChallengePurpose); err != nil || matched {
		t.Errorf("unknown nonce: matched=%v err=%v, want matched=false err=nil", matched, err)
	}
}

// ── Round-3 correction: definitive outcomes COMMIT, internal errors roll back ─

// TestVerifyChallengeWithLockout_RejectedAttemptCommits_DB is the round-3
// direct-wrapper regression: a wrong answer through VerifyChallengeWithLockout
// is a DEFINITIVE invalid outcome, so the shared transaction must COMMIT —
// re-querying through fresh connections shows the failure increment persisted
// on the account row AND the attempt persisted on the challenge, up to the
// per-challenge burn at 3 (whose burn must equally persist).
func TestVerifyChallengeWithLockout_RejectedAttemptCommits_DB(t *testing.T) {
	p, pool := newPushLockoutDBProvider(t)
	ctx := context.Background()

	user := seedPushRecoveryUser(t, pool)
	nonce, _ := seedPushRecoveryChallenge(t, pool, user)

	challengeState := func() (fa int, burned bool) {
		t.Helper()
		if err := pool.QueryRow(ctx,
			`SELECT COALESCE(failed_attempts, 0), COALESCE(verified_at IS NOT NULL, FALSE)
			 FROM push_mfa_challenges WHERE nonce = decode($1, 'hex')`, nonce,
		).Scan(&fa, &burned); err != nil {
			t.Fatal(err)
		}
		return fa, burned
	}

	if outcome, err := p.VerifyChallengeWithLockout(ctx, user, nonce, "07"); err != nil || outcome != PushVerifyInvalid {
		t.Fatalf("wrong answer: outcome=%d err=%v, want PushVerifyInvalid/nil", outcome, err)
	}
	if count, _, ok := pushLockoutRowCount(t, pool, user); !ok || count != 1 {
		t.Fatalf("failure increment not persisted after commit: count=%d exists=%v, want 1", count, ok)
	}
	if fa, burned := challengeState(); fa != 1 || burned {
		t.Fatalf("challenge state after rejection = (failed_attempts=%d, burned=%v), want (1, false) — the attempt must persist", fa, burned)
	}

	// Two more rejections record failures 2 and 3; the burn fires on the NEXT
	// submission (failed_attempts >= 3 at read time), which is itself a
	// definitive outcome whose burn must persist.
	for i := 2; i <= 3; i++ {
		if outcome, err := p.VerifyChallengeWithLockout(ctx, user, nonce, "07"); err != nil || outcome != PushVerifyInvalid {
			t.Fatalf("attempt %d: outcome=%d err=%v, want PushVerifyInvalid/nil", i, outcome, err)
		}
	}
	if fa, burned := challengeState(); fa != 3 || burned {
		t.Fatalf("challenge state before burn = (failed_attempts=%d, burned=%v), want (3, false)", fa, burned)
	}
	if outcome, err := p.VerifyChallengeWithLockout(ctx, user, nonce, "07"); err != nil || outcome != PushVerifyInvalid {
		t.Fatalf("burning attempt: outcome=%d err=%v, want PushVerifyInvalid/nil", outcome, err)
	}
	if fa, burned := challengeState(); fa != 3 || !burned {
		t.Fatalf("challenge state after burn = (failed_attempts=%d, burned=%v), want (3, true) — the burn must persist", fa, burned)
	}
	if count, _, _ := pushLockoutRowCount(t, pool, user); count != 4 {
		t.Fatalf("account count = %d, want 4 (one recorded failure per definitive rejection, the burn included)", count)
	}
}

// TestVerifyChallenge_CommitsRejectedAttempts_DB is the round-3 regression for
// the plain wrapper itself: VerifyChallenge used to return on
// ErrChallengeInvalid BEFORE committing, so the deferred rollback silently
// erased every wrong-answer increment and made the burn-at-3 unreachable. Both
// definitive mutations must now persist across independently re-opened
// connections (the login path refuses in-band answers, but the method stays
// exported ChallengeProvider surface and must honor its own contract).
func TestVerifyChallenge_CommitsRejectedAttempts_DB(t *testing.T) {
	p, pool := newPushLockoutDBProvider(t)
	ctx := context.Background()

	user := seedPushRecoveryUser(t, pool)
	nonce, _ := seedPushRecoveryChallenge(t, pool, user)

	for i := 1; i <= 2; i++ {
		if err := p.VerifyChallenge(ctx, user, nonce, "07"); !errors.Is(err, ErrChallengeInvalid) {
			t.Fatalf("attempt %d: err=%v, want ErrChallengeInvalid", i, err)
		}
	}
	var fa int
	if err := pool.QueryRow(ctx,
		`SELECT COALESCE(failed_attempts, 0) FROM push_mfa_challenges WHERE nonce = decode($1, 'hex')`, nonce,
	).Scan(&fa); err != nil {
		t.Fatal(err)
	}
	if fa != 2 {
		t.Fatalf("failed_attempts = %d after 2 rejected answers, want 2 (the increments must COMMIT, not roll back)", fa)
	}

	// The burn fires on the submission after the 3rd recorded failure (the
	// lookup reads failed_attempts >= 3); the burn must also persist.
	if err := p.VerifyChallenge(ctx, user, nonce, "07"); !errors.Is(err, ErrChallengeInvalid) {
		t.Fatalf("attempt 3: err=%v, want ErrChallengeInvalid", err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT COALESCE(failed_attempts, 0) FROM push_mfa_challenges WHERE nonce = decode($1, 'hex')`, nonce,
	).Scan(&fa); err != nil {
		t.Fatal(err)
	}
	if fa != 3 {
		t.Fatalf("failed_attempts = %d before the burn, want 3", fa)
	}
	if err := p.VerifyChallenge(ctx, user, nonce, "07"); !errors.Is(err, ErrChallengeInvalid) {
		t.Fatalf("burning attempt: err=%v, want ErrChallengeInvalid", err)
	}
	var burned bool
	if err := pool.QueryRow(ctx,
		`SELECT COALESCE(verified_at IS NOT NULL, FALSE), COALESCE(failed_attempts, 0) FROM push_mfa_challenges WHERE nonce = decode($1, 'hex')`, nonce,
	).Scan(&burned, &fa); err != nil {
		t.Fatal(err)
	}
	if !burned {
		t.Fatal("the challenge burn must persist as a definitive outcome (verified_at set)")
	}
	if fa != 3 {
		t.Fatalf("failed_attempts after burn = %d, want 3 (the burn does not increment)", fa)
	}
}

// TestVerifyChallengeWithLockout_InternalErrorRollsBack_DB is the round-3
// counterpart to commit-on-definitive: only an AMBIGUOUS internal error rolls
// back. The purpose-probe seam (test-only) cancels the request context right
// before verification, so the in-transaction challenge lookup fails at the
// driver level AFTER the account row is locked — an internal error, which must
// discard the WHOLE transaction (no failure recorded, challenge untouched), and
// the next attempts must behave exactly as if the failed one never happened.
func TestVerifyChallengeWithLockout_InternalErrorRollsBack_DB(t *testing.T) {
	p, pool := newPushLockoutDBProvider(t)
	ctx := context.Background()

	user := seedPushRecoveryUser(t, pool)
	nonce, code := seedPushRecoveryChallenge(t, pool, user)

	pctx, cancel := context.WithCancel(ctx)
	defer cancel()
	p.purposeProbe = func(context.Context, lockoutQuerier, []byte, int64, string) (bool, error) {
		cancel() // real driver-level DB failure for every subsequent statement
		return true, nil
	}

	outcome, err := p.VerifyChallengeWithLockout(pctx, user, nonce, code)
	if outcome != PushVerifyInvalid {
		t.Fatalf("outcome = %d, want PushVerifyInvalid (fail-closed rejection)", outcome)
	}
	if err == nil {
		t.Fatal("an ambiguous internal error must surface an error for the caller to log")
	}
	if errors.Is(err, ErrChallengeInvalid) {
		t.Fatalf("internal error must NOT be classified as the definitive sentinel: %v", err)
	}
	p.purposeProbe = nil

	// NOTHING persisted: no lockout row was created and the challenge is
	// untouched — the transaction rolled back completely.
	if _, _, exists := pushLockoutRowCount(t, pool, user); exists {
		t.Fatal("an ambiguous internal error must not create or mutate lockout state")
	}
	var fa int
	var burned bool
	if err := pool.QueryRow(ctx,
		`SELECT COALESCE(failed_attempts, 0), COALESCE(verified_at IS NOT NULL, FALSE)
		 FROM push_mfa_challenges WHERE nonce = decode($1, 'hex')`, nonce,
	).Scan(&fa, &burned); err != nil {
		t.Fatal(err)
	}
	if fa != 0 || burned {
		t.Fatalf("challenge state after internal error = (failed_attempts=%d, burned=%v), want (0, false) — nothing may persist", fa, burned)
	}

	// The next attempt behaves as if the failed one never happened: a wrong
	// answer records EXACTLY one failure (no phantom from the rolled-back
	// attempt), then the correct answer is accepted and resets the counter.
	if outcome, err := p.VerifyChallengeWithLockout(ctx, user, nonce, "07"); err != nil || outcome != PushVerifyInvalid {
		t.Fatalf("retry wrong answer: outcome=%d err=%v, want PushVerifyInvalid/nil", outcome, err)
	}
	if count, _, ok := pushLockoutRowCount(t, pool, user); !ok || count != 1 {
		t.Fatalf("count after retry = %d (exists=%v), want exactly 1 — the rolled-back attempt must not have recorded", count, ok)
	}
	nonce2, code2 := seedPushRecoveryChallenge(t, pool, user)
	if outcome, err := p.VerifyChallengeWithLockout(ctx, user, nonce2, code2); err != nil || outcome != PushVerifyAccepted {
		t.Fatalf("retry correct answer: outcome=%d err=%v, want PushVerifyAccepted/nil", outcome, err)
	}
	if count, _, _ := pushLockoutRowCount(t, pool, user); count != 0 {
		t.Fatalf("count after success = %d, want 0 (reset)", count)
	}
}

// ── verifyChallengeTx error classification (definitive vs internal) ──────────

// verifyChallengeErrorQuerier is a stub lockoutQuerier whose row scan fails
// with a controlled error; used to pin the error classes of verifyChallengeTx
// without a database.
type verifyChallengeErrorQuerier struct{ rowErr error }

func (q verifyChallengeErrorQuerier) QueryRow(context.Context, string, ...any) pgx.Row {
	return verifyChallengeErrorRow{err: q.rowErr}
}
func (verifyChallengeErrorQuerier) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}

type verifyChallengeErrorRow struct{ err error }

func (r verifyChallengeErrorRow) Scan(...any) error { return r.err }
func (verifyChallengeErrorRow) Close()              {}

// TestVerifyChallengeTx_ErrorClasses pins the round-3 classification that
// lets callers commit definitive rejections but roll back internal failures:
// a no-row lookup IS the uniform ErrChallengeInvalid (definitive), while any
// other lookup failure must surface as a WRAPPED cause — never the sentinel.
func TestVerifyChallengeTx_ErrorClasses(t *testing.T) {
	p := &NumberMatchPushProvider{}

	// Definitive: no active challenge for this user.
	err := p.verifyChallengeTx(context.Background(), verifyChallengeErrorQuerier{rowErr: pgx.ErrNoRows}, 42, []byte{0x00}, "42")
	if !errors.Is(err, ErrChallengeInvalid) {
		t.Fatalf("no-row lookup: err=%v, want ErrChallengeInvalid", err)
	}

	// Internal: a transient read failure must NOT be folded into the sentinel.
	err = p.verifyChallengeTx(context.Background(), verifyChallengeErrorQuerier{rowErr: errors.New("injected read failure")}, 42, []byte{0x00}, "42")
	if err == nil {
		t.Fatal("a transient lookup failure must return an error")
	}
	if errors.Is(err, ErrChallengeInvalid) {
		t.Fatalf("transient lookup failure must not be classified as definitive: %v", err)
	}
}

// TestVerifyChallengeArmsWrongBurnConsume exercises the plain (non-lockout)
// challenge arms the recovery tests never reach: wrong-answer failure
// counting, the three-strike burn, correct-answer consumption, and single-use
// rejection after consumption.
func TestVerifyChallengeArmsWrongBurnConsume(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	userID := seedPushRecoveryUser(t, pool)
	provider := NewNumberMatchPushProvider(context.Background(), pool, nil, "", "", pushLockoutLogger())

	nonce, code := seedPushRecoveryChallenge(t, pool, userID)
	wrong := "00"
	if code == wrong {
		wrong = "11"
	}
	for i := 0; i < 3; i++ {
		if err := provider.VerifyChallenge(context.Background(), userID, nonce, wrong); !errors.Is(err, ErrChallengeInvalid) {
			t.Fatalf("wrong answer %d: err=%v", i, err)
		}
	}
	// Third strike burned the challenge: even the CORRECT answer now fails.
	if err := provider.VerifyChallenge(context.Background(), userID, nonce, code); !errors.Is(err, ErrChallengeInvalid) {
		t.Fatalf("burned challenge accepted: err=%v", err)
	}

	nonce2, code2 := seedPushRecoveryChallenge(t, pool, userID)
	if err := provider.VerifyChallenge(context.Background(), userID, nonce2, code2); err != nil {
		t.Fatalf("correct answer rejected: %v", err)
	}
	// Single-use: a consumed challenge rejects a second submission.
	if err := provider.VerifyChallenge(context.Background(), userID, nonce2, code2); !errors.Is(err, ErrChallengeInvalid) {
		t.Fatalf("consumed challenge accepted: err=%v", err)
	}
}

// seedLoginPurposeChallenge mints a challenge stamped with a NON-recovery
// session purpose (as the login flow would), for the purpose-mismatch arm.
func seedLoginPurposeChallenge(t *testing.T, pool *pgxpool.Pool, userID int64) (nonceHex, code string) {
	t.Helper()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	nonceHex = hex.EncodeToString(nonce)
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO push_mfa_challenges (user_id, challenge_code, nonce, session_id, expires_at)
		 VALUES ($1, '42', decode($2, 'hex'), $3, now() + interval '120 seconds')`,
		userID, nonceHex, "login-session-purpose",
	); err != nil {
		t.Fatalf("seed login-purpose challenge: %v", err)
	}
	return nonceHex, "42"
}

// TestVerifyChallengeWithLockout_LockedAttemptCountsButNeverExtends drives an
// attempt arriving AFTER the lock has engaged: it must be refused with
// PushVerifyLocked, counted (budget stays honest) and — critically — must NOT
// extend locked_until (the lock expires on schedule no matter the grinding).
func TestVerifyChallengeWithLockout_LockedAttemptCountsButNeverExtends(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	userID := seedPushRecoveryUser(t, pool)
	provider := NewNumberMatchPushProvider(context.Background(), pool, nil, "", "", pushLockoutLogger())

	wrong := "00"
	// One FRESH challenge per strike: a single challenge burns after three
	// wrong answers, so the account-level lock is only reachable through the
	// real grinding pattern — a new challenge each attempt, one wrong answer
	// each (exactly what the lockout exists to stop).
	for i := 0; i < 5; i++ {
		nonce, _ := seedPushRecoveryChallenge(t, pool, userID)
		outcome, err := provider.VerifyChallengeWithLockout(context.Background(), userID, nonce, wrong)
		if outcome != PushVerifyInvalid || err != nil {
			t.Fatalf("strike %d: outcome=%v err=%v", i+1, outcome, err)
		}
	}
	_, lockedUntilBefore, exists := pushLockoutRowCount(t, pool, userID)
	if !exists || lockedUntilBefore.IsZero() {
		t.Fatalf("5 strikes must engage the lock (locked_until set), got exists=%v until=%v", exists, lockedUntilBefore)
	}

	// A post-lock attempt — even a FRESH, purpose-stamped challenge with the
	// CORRECT answer — is refused with the LOCKED outcome (not the uniform
	// invalid) and only counts. (The original challenge is burned by the
	// strikes; a burned one would exit via the purpose-mismatch arm instead.)
	nonce6, code6 := seedPushRecoveryChallenge(t, pool, userID)
	outcome, err := provider.VerifyChallengeWithLockout(context.Background(), userID, nonce6, code6)
	if outcome != PushVerifyLocked {
		t.Fatalf("post-lock attempt: outcome=%v err=%v, want PushVerifyLocked", outcome, err)
	}
	count, lockedUntilAfter, _ := pushLockoutRowCount(t, pool, userID)
	if count != 6 {
		t.Errorf("post-lock attempt must count (failed_count=6), got %d", count)
	}
	if !lockedUntilAfter.Equal(lockedUntilBefore) {
		t.Errorf("locked_until moved: before=%v after=%v — locked attempts must never extend the lock", lockedUntilBefore, lockedUntilAfter)
	}
}

// TestVerifyChallengeWithLockout_PurposeMismatchCommitsNoFailure pins the
// round-3 commit semantics: a challenge minted for a DIFFERENT purpose (e.g.
// login) is a DEFINITIVE mismatch — committed, not rolled back — and no
// failure is counted against the account.
func TestVerifyChallengeWithLockout_PurposeMismatchCommitsNoFailure(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	userID := seedPushRecoveryUser(t, pool)
	provider := NewNumberMatchPushProvider(context.Background(), pool, nil, "", "", pushLockoutLogger())

	nonce, _ := seedLoginPurposeChallenge(t, pool, userID)
	outcome, err := provider.VerifyChallengeWithLockout(context.Background(), userID, nonce, "42")
	if outcome != PushVerifyInvalid || err != nil {
		t.Fatalf("purpose mismatch: outcome=%v err=%v", outcome, err)
	}
	// No failure counted: the mismatch is definitive but not a recovery
	// grinding attempt, so the shared budget must stay untouched.
	if count, _, _ := pushLockoutRowCount(t, pool, userID); count != 0 {
		t.Errorf("purpose mismatch counted a failure: failed_count=%d, want 0", count)
	}
}
