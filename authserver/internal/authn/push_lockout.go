package authn

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ── Per-account push-verification lockout (forgot-password recovery path) ───
//
// The forgot-password push branch is the only in-band consumer of
// VerifyChallenge (the login path hard-refuses in-band answers with 410 and
// the device-approval path verifies device-signed assertions). Each challenge
// only burns at 3 answers, but an attacker who knows the victim's email can
// mint fresh challenges and grind the 100-value number-match space ACROSS
// challenges. This seam closes that with the SAME per-account policy the TOTP
// recovery branch enforces via VerifyTOTPWithLockout:
//
//	pushVerifyMaxFailures (5) failed answers within pushVerifyLockWindow
//	(15 minutes) → the account is locked against recovery-path push
//	verification for pushVerifyLockWindow.
//
// Lock state is keyed by user_id (account level) — never by challenge or IP —
// and the locked check runs BEFORE any verification is attempted, so even the
// correct answer is refused while locked. The legacy per-challenge burn at 3
// inside VerifyChallenge is a separate, per-challenge control and is
// deliberately left untouched (the proposal records the 3-vs-5 reconciliation:
// 5 is the account-level threshold matching the documented TOTP threshold;
// 3 stays the per-challenge burn).
//
// Storage is the SHARED auth_lockouts table (round-2 correction: the previous
// in-process per-replica map was unacceptable for an account-wide limit —
// replicas each enforced the threshold independently, multiplying the real
// budget by the replica count). The row key is pushLockoutKey: the table's
// documented dimension:value convention (ip:{ip} / user:{username} /
// ip_user:{ip}:{username}) with method='push' and the numeric account id, so
// every authserver replica shares one lock budget per account. Under the V259
// deny-all FORCE flip (PLAN-20260913 D2) every statement below reaches the
// table ONLY through the worker-owned SECURITY DEFINER accessors in
// authserver/sql/reducers/push_lockout_accessors.sql — the accessors run as
// setjoin_worker (BYPASSRLS) inside the caller's transaction, so the row-lock
// serialization below is unchanged while the table itself stays deny-all.
//
// Atomicity (round-2 correction): check, verification, and outcome recording
// now run inside ONE transaction that holds the account's lockout row from the
// start (INSERT .. ON CONFLICT DO UPDATE acquires the row lock on both the
// fresh-insert and conflicting-update paths). Every attempt for an account
// therefore serializes: a request that arrives after the 5th failure committed
// reads locked_until in the future and is refused before any verification —
// the old check-then-verify-then-record race across three separate
// transactions cannot re-open.
//
// Failure semantics: every refusal of a submitted answer is counted (so the
// recorded budget equals the answers actually consumed), but while locked the
// count is bookkeeping-only — the lock horizon is never extended by the
// attacker's own traffic. Transient database failures FAIL CLOSED: the purpose
// probe, the lock-state read, and an internal failure inside the challenge
// transaction itself all reject the request with the uniform invalid outcome
// (plus a returned error the caller logs) instead of falling through to
// verification, and their transaction rolls back with nothing recorded.
// Definitive invalid outcomes — wrong answer, burned challenge, purpose
// mismatch — COMMIT (round-3 correction: a definitive verdict must be durable).

const (
	// pushVerifyMaxFailures is pinned to the SAME documented threshold as the
	// TOTP seam (totpMaxFailures = 5). Aliasing the TOTP constant (instead of
	// restating 5) makes policy drift a compile error; the pin is also asserted
	// by TestPushLockout_PinnedToTOTPPolicy.
	pushVerifyMaxFailures = totpMaxFailures
	// pushVerifyLockWindow is both the failure-accumulation window and the
	// lock duration, aliased to totpLockDuration so both recovery branches
	// share one documented lockout window by construction.
	pushVerifyLockWindow = totpLockDuration
)

// ForgotPasswordChallengePurpose is the session_id value stamped onto push
// challenges created by ForgotPasswordBegin (login generators pass either the
// MFA-pending token or "" today). VerifyChallengeWithLockout only accepts
// challenges carrying this purpose, so a login-generated challenge can never
// be consumed through the recovery path.
const ForgotPasswordChallengePurpose = "forgot-password"

// PushVerifyOutcome is the result of VerifyChallengeWithLockout: either the
// answer was accepted, the account is locked, or the answer/challenge was
// rejected (uniform with VerifyChallenge's ErrChallengeInvalid on the wire).
type PushVerifyOutcome int

const (
	// PushVerifyInvalid means verification failed (wrong answer, unknown
	// challenge, purpose mismatch, or an internal/transient error — which is a
	// fail-closed rejection) and the failure was recorded toward the account
	// lockout counter.
	PushVerifyInvalid PushVerifyOutcome = iota
	// PushVerifyLocked means the account is currently locked out; no
	// verification was attempted (the attempt is still counted, count-only).
	PushVerifyLocked
	// PushVerifyAccepted means the answer validated and the lockout counter
	// was reset.
	PushVerifyAccepted
)

// pushLockoutKey is the auth_lockouts row key for one account's push recovery
// budget: method dimension + user_id under the table's dimension:value key
// convention. The prefix cannot collide with the threat pipeline's ip:/user:/
// ip_user: keys. SQL-side ownership of the convention is the worker-only
// accessor push_lockout_acquire/record/count_locked (authserver/sql/reducers/
// push_lockout_accessors.sql), whose statements build the identical
// 'push_user:' || p_user_id key — this builder remains the test-side parity
// pin (Go tests address the shared row through it) and the documented
// convention source.
func pushLockoutKey(userID int64) string {
	return "push_user:" + strconv.FormatInt(userID, 10)
}

// pushLockRow is one account's shared lockout state as read under the
// transaction's row lock.
type pushLockRow struct {
	failedCount int
	lockedUntil time.Time // "unlocked" is a not-after-now timestamp (the table's column is NOT NULL)
	updatedAt   time.Time // last failure time — the accumulation-window anchor
}

func (r pushLockRow) locked(now time.Time) bool { return r.lockedUntil.After(now) }

// lockoutQuerier is the narrow statement surface the lockout seam needs.
// Satisfied by pgx.Tx (the seam's own transaction); the same shape as
// totpEnrollmentStore in totp.go.
type lockoutQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

// lockPushAccountRow atomically acquires the account's lockout row and reads
// the verdict through the worker-owned SECURITY DEFINER accessor
// push_lockout_acquire (V259 deny-all FORCE: auth_lockouts has zero permissive
// policies, so this seam — not the table — is the write surface). The
// INSERT .. ON CONFLICT DO UPDATE inside the accessor takes the row lock on
// BOTH paths — a first-ever attempt inserts a count-0 row whose locked_until
// (=now) is already expired, and a concurrent attempt conflicts and blocks on
// the existing row — so every verification attempt for the account serializes
// on this statement and reads the freshest committed state; the row lock is
// held by the caller's transaction to commit. The fresh insert uses
// locked_until = now() as the "never locked" sentinel, matching
// lockout_escalate's insert convention for the same table.
func lockPushAccountRow(ctx context.Context, q lockoutQuerier, userID int64) (pushLockRow, error) {
	var row pushLockRow
	err := q.QueryRow(ctx,
		`SELECT failed_count, locked_until, updated_at
		   FROM push_lockout_acquire($1)`,
		userID,
	).Scan(&row.failedCount, &row.lockedUntil, &row.updatedAt)
	return row, err
}

// pushWindowPriorFailures applies the failure-accumulation window: failures
// last touched before pushVerifyLockWindow ago are stale and restart the count
// instead of accumulating (so 4 old failures + 1 fresh one does not lock).
func pushWindowPriorFailures(count int, lastFailure, now time.Time) int {
	if now.Sub(lastFailure) >= pushVerifyLockWindow {
		return 0
	}
	return count
}

// recordPushVerificationOutcome writes the post-verification counter state in
// the caller's transaction (which already holds the row lock) through the
// worker-only push_lockout_record accessor (V259 deny-all FORCE seam):
// failure → prior + 1 with the TOTP lock at the threshold; success → reset
// (count 0 + the unlocked sentinel). A nil lock horizon means "re-arm the
// unlocked sentinel (now())" — the sentinel convention lives SQL-side.
// Returns whether this outcome just locked the account.
func recordPushVerificationOutcome(ctx context.Context, q lockoutQuerier, userID int64, success bool, prior int, now time.Time) (locked bool, err error) {
	if success {
		_, err = q.Exec(ctx,
			`SELECT push_lockout_record($1, 0, NULL)`,
			userID)
		return false, err
	}
	newCount, lockUntil := NextTOTPLockout(prior, now)
	var until *time.Time // nil → the accessor re-arms the unlocked sentinel
	if lockUntil != nil {
		until = lockUntil
	}
	if _, err = q.Exec(ctx,
		`SELECT push_lockout_record($1, $2, $3)`,
		userID, newCount, until); err != nil {
		return false, err
	}
	return lockUntil != nil, nil
}

// countLockedAttempt records a count-only failure for an attempt refused by an
// active lock, through the worker-only push_lockout_count_locked accessor
// (V259 deny-all FORCE seam): the shared budget keeps accounting for grinding
// traffic, but locked_until is deliberately NOT recomputed, so the lock always
// expires on schedule and an attacker cannot extend it by hammering.
func countLockedAttempt(ctx context.Context, q lockoutQuerier, userID int64) error {
	_, err := q.Exec(ctx,
		`SELECT push_lockout_count_locked($1)`,
		userID)
	return err
}

// challengePurposeMatches reports whether nonceHex maps to an active,
// unverified challenge for userID whose session_id stamp equals purpose.
// Round-2 correction: evaluation errors (undecodable nonce, DB failure) are
// RETURNED, not swallowed — the caller must fail closed and never fall through
// to verification on a transient read failure.
func (p *NumberMatchPushProvider) challengePurposeMatches(ctx context.Context, q lockoutQuerier, nonce []byte, userID int64, purpose string) (bool, error) {
	var matched bool
	err := q.QueryRow(ctx,
		`SELECT EXISTS (
			SELECT 1 FROM push_mfa_challenges
			WHERE nonce = $1 AND user_id = $2
			  AND verified_at IS NULL AND expires_at > now()
			  AND COALESCE(session_id, '') = $3
		)`,
		nonce, userID, purpose,
	).Scan(&matched)
	if err != nil {
		return false, fmt.Errorf("push challenge purpose lookup: %w", err)
	}
	return matched, nil
}

// purposeProbe, when non-nil, replaces the DB purpose lookup. It exists solely
// as the test injection seam for the fail-closed contract (a failing probe
// must reject the request); production wiring leaves it nil.
func (p *NumberMatchPushProvider) purposeCheck(ctx context.Context, q lockoutQuerier, nonce []byte, userID int64, purpose string) (bool, error) {
	if p.purposeProbe != nil {
		return p.purposeProbe(ctx, q, nonce, userID, purpose)
	}
	return p.challengePurposeMatches(ctx, q, nonce, userID, purpose)
}

// VerifyChallengeWithLockout is the SINGLE entry point the forgot-password
// push branch may use, mirroring VerifyTOTPWithLockout for push: it folds the
// per-account lockout policy (lock → check-locked → purpose binding → verify →
// record-failure / reset) and the challenge purpose binding around the
// unchanged VerifyChallenge challenge logic, so the recovery path cannot be
// used to grind number-match answers across fresh challenges without hitting
// the same 5-failures → 15-minute lock the TOTP branch enforces.
//
// The whole verdict is ONE transaction: the account's auth_lockouts row is
// locked first, so concurrent attempts (and replicas sharing the database)
// serialize; the challenge row lock is taken after the account row lock and no
// other path locks these two tables in the opposite order, so the composition
// is deadlock-free.
//
// The transaction runs on the WORKER credential (p.lockoutPool, nil →
// p.pool): every auth_lockouts statement inside it goes through the
// worker-owned SECURITY DEFINER push_lockout_* accessors (V259 deny-all
// FORCE), and only setjoin_worker holds EXECUTE on those — a constrained
// request credential would fail with 42501 at acquisition. The entire
// verdict (acquire → purpose probe → verify → record) stays on this ONE
// pool/transaction, so the row-lock serialization and all-or-nothing commit
// semantics are unchanged — only the credential context moves.
//
// The login path is unaffected: it never consumes VerifyChallenge in-band
// (handlers/push.go refuses with 410) and keeps calling VerifyChallenge
// directly through the ChallengeProvider interface with its uniform
// ErrChallengeInvalid contract intact.
//
// Fail-closed: a transient failure of the lock-state read or the purpose probe
// rejects the request (PushVerifyInvalid + returned error to log) — it never
// falls through to verification.
//
// Commit semantics (round-3 correction): every DEFINITIVE outcome commits —
// accepted (counter reset), wrong answer or burned challenge (failure
// increment + challenge mutation, atomically), and an unauthenticated purpose
// mismatch (no failure counted). Only an internal/transient DB error — lock
// read, purpose probe, or a wrapped failure from the challenge transaction —
// rolls the whole transaction back with nothing recorded, so the next attempt
// behaves as if it never happened. Locked accounts refuse in-transaction
// without mutating the lock horizon.
func (p *NumberMatchPushProvider) VerifyChallengeWithLockout(ctx context.Context, userID int64, nonceHex, answer string) (PushVerifyOutcome, error) {
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		// Uniform: an unparseable nonce is indistinguishable from a non-existent
		// one; no DB work is needed to reject it.
		return PushVerifyInvalid, nil
	}

	// The complete lockout/verification transaction rides the WORKER pool:
	// the push_lockout_* SECURITY DEFINER accessors it calls are
	// worker-only EXECUTE (V259), and splitting the verdict across pools
	// would break the single-transaction atomicity contract.
	beginPool := p.lockoutPool
	if beginPool == nil {
		beginPool = p.pool // INERT alias until DB_WORKER_DSN is set (W1b)
	}
	tx, err := beginPool.Begin(ctx)
	if err != nil {
		return PushVerifyInvalid, fmt.Errorf("push lockout begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// txProbe: test-only injection seam (see the field comment on the
	// provider); nil in production, where the transaction is the querier.
	var q lockoutQuerier = tx
	if p.txProbe != nil {
		q = p.txProbe(q)
	}

	// Atomic shared check: acquire + read the account's lockout row under the
	// transaction's row lock. Attempts that arrive after the 5th failure
	// committed block here until it does, then see the lock.
	state, err := lockPushAccountRow(ctx, q, userID)
	if err != nil {
		// FAIL CLOSED: a transient read failure must never fall through to
		// verification (round-2 Astra item 3).
		return PushVerifyInvalid, fmt.Errorf("push lockout check: %w", err)
	}
	now := time.Now()
	if state.locked(now) {
		// The lock dominates: nothing is verified (even a correct answer is
		// refused) and the purpose probe is skipped. The attempt is still
		// counted, count-only, so the shared budget stays honest without ever
		// extending the lock horizon.
		if cerr := countLockedAttempt(ctx, q, userID); cerr != nil {
			return PushVerifyLocked, fmt.Errorf("count locked push attempt: %w", cerr)
		}
		if cerr := tx.Commit(ctx); cerr != nil {
			return PushVerifyLocked, fmt.Errorf("commit locked push attempt: %w", cerr)
		}
		return PushVerifyLocked, nil
	}

	// Purpose binding: only challenges minted by ForgotPasswordBegin carry the
	// forgot-password purpose. Errors fail CLOSED; a definitive mismatch is the
	// uniform invalid outcome.
	matched, err := p.purposeCheck(ctx, q, nonce, userID, ForgotPasswordChallengePurpose)
	if err != nil {
		return PushVerifyInvalid, fmt.Errorf("push purpose check: %w", err)
	}
	if !matched {
		// Definitive outcome: a challenge not minted for this purpose can never
		// be consumed here. COMMIT it (round-3 correction) — the previous early
		// return triggered the deferred rollback, so a definitive verdict was
		// never durable. Nothing was verified and no failure is counted; the
		// only committed mutation is the account row's count-0 upsert.
		if cerr := tx.Commit(ctx); cerr != nil {
			return PushVerifyInvalid, fmt.Errorf("commit push purpose mismatch: %w", cerr)
		}
		return PushVerifyInvalid, nil
	}

	verr := p.verifyChallengeTx(ctx, q, userID, nonce, answer)
	if verr != nil && !errors.Is(verr, ErrChallengeInvalid) {
		// Internal/transient failure inside verification (challenge-lookup read
		// error, burn/increment write failure): the outcome is ambiguous, so
		// NOTHING is recorded and the whole transaction rolls back — the same
		// fail-closed semantics as the lock-state and purpose reads. The
		// deferred rollback discards the account-row upsert and any partial
		// challenge mutation, so the next attempt starts from pre-attempt state.
		return PushVerifyInvalid, fmt.Errorf("push verify: %w", verr)
	}
	if verr != nil {
		// Definitive rejection (wrong answer or burned challenge): record the
		// account failure and COMMIT (round-3 correction) — the challenge
		// burn/increment from verifyChallengeTx and the counter update land
		// together or not at all, and a definitive verdict must be durable.
		locked, recErr := recordPushVerificationOutcome(ctx, q, userID, false,
			pushWindowPriorFailures(state.failedCount, state.updatedAt, now), now)
		if recErr != nil {
			return PushVerifyInvalid, fmt.Errorf("record push failure: %w", recErr)
		}
		if cerr := tx.Commit(ctx); cerr != nil {
			return PushVerifyInvalid, fmt.Errorf("commit push failure: %w", cerr)
		}
		if locked && p.logger != nil {
			p.logger.Warn("push recovery verification locked out", "user_id", userID)
		}
		return PushVerifyInvalid, nil
	}

	if _, err := recordPushVerificationOutcome(ctx, q, userID, true, 0, now); err != nil {
		return PushVerifyInvalid, fmt.Errorf("reset push lockout: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return PushVerifyInvalid, fmt.Errorf("commit push verify: %w", err)
	}
	return PushVerifyAccepted, nil
}
