package authn

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/testsupport"
)

// Deterministic fault injection for the DB-error arms of the push seam. The
// production code has no failure hooks inside its transaction flows, so the
// wrapper stands in for the querier: failN modes return an injected error at
// the Nth Exec/QueryRow; poisonAtN modes let the real call succeed and then
// execute a failing statement through the transaction, so the pending COMMIT
// fails exactly like a real mid-transaction fault.
type injectedQuerier struct {
	inner        lockoutQuerier
	failExecN    int
	failQueryN   int
	poisonExecN  int
	poisonQueryN int
	execCalls    int
	queryCalls   int
}

func probeWith(failExecN, failQueryN, poisonExecN, poisonQueryN int) func(lockoutQuerier) lockoutQuerier {
	return func(inner lockoutQuerier) lockoutQuerier {
		return &injectedQuerier{
			inner: inner, failExecN: failExecN, failQueryN: failQueryN,
			poisonExecN: poisonExecN, poisonQueryN: poisonQueryN,
		}
	}
}

var errInjected = errors.New("injected failure (test seam)")

type injectedFailRow struct{}

func (injectedFailRow) Scan(...any) error { return errInjected }

func (q *injectedQuerier) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	q.execCalls++
	if q.failExecN > 0 && q.execCalls == q.failExecN {
		return pgconn.CommandTag{}, errInjected
	}
	tag, err := q.inner.Exec(ctx, sql, args...)
	if err == nil && q.poisonExecN > 0 && q.execCalls == q.poisonExecN {
		_, _ = q.inner.Exec(ctx, "SELECT 1/(1-1)") // abort the tx: the COMMIT must fail
	}
	return tag, err
}

func (q *injectedQuerier) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	q.queryCalls++
	if q.failQueryN > 0 && q.queryCalls == q.failQueryN {
		return injectedFailRow{}
	}
	row := q.inner.QueryRow(ctx, sql, args...)
	if q.poisonQueryN > 0 && q.queryCalls == q.poisonQueryN {
		_, _ = q.inner.Exec(ctx, "SELECT 1/(1-1)") // abort the tx: the COMMIT must fail
	}
	return row
}

// challengeRow snapshots the persisted challenge state for one user.
func challengeRow(t *testing.T, pool *pgxpool.Pool, userID int64) (failedAttempts int, verified bool, exists bool) {
	t.Helper()
	var verifiedAt *time.Time
	err := pool.QueryRow(context.Background(),
		`SELECT COALESCE(failed_attempts, 0), verified_at FROM push_mfa_challenges WHERE user_id = $1`,
		userID).Scan(&failedAttempts, &verifiedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return failedAttempts, verifiedAt != nil, true
}

// lockoutRowExists reports whether the account's lockout row survived.
func lockoutRowExists(t *testing.T, pool *pgxpool.Pool, userID int64) bool {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM auth_lockouts WHERE lockout_key = $1`,
		pushLockoutKey(userID)).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n > 0
}

// challengeSnap is the persisted state of ONE challenge row, identified by
// its nonce — the purpose-mismatch fixture seeds several rows per user, so
// user-scoped snapshots are ambiguous.
type challengeSnap struct {
	exists   bool
	fa       int
	verified bool
}

func snapChallengeByNonce(t *testing.T, pool *pgxpool.Pool, nonceHex string) challengeSnap {
	t.Helper()
	var cs challengeSnap
	var verifiedAt *time.Time
	err := pool.QueryRow(context.Background(),
		`SELECT COALESCE(failed_attempts, 0), verified_at FROM push_mfa_challenges WHERE nonce = decode($1, 'hex')`,
		nonceHex).Scan(&cs.fa, &verifiedAt)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return challengeSnap{}
	case err != nil:
		t.Fatal(err)
	}
	cs.exists, cs.verified = true, verifiedAt != nil
	return cs
}

// lockoutSnap is the full persisted lockout row state.
type lockoutSnap struct {
	exists      bool
	failedCount int
	lockedUntil time.Time
	updatedAt   time.Time
}

func snapLockout(t *testing.T, pool *pgxpool.Pool, userID int64) lockoutSnap {
	t.Helper()
	var ls lockoutSnap
	err := pool.QueryRow(context.Background(),
		`SELECT failed_count, locked_until, updated_at FROM auth_lockouts WHERE lockout_key = $1`,
		pushLockoutKey(userID)).Scan(&ls.failedCount, &ls.lockedUntil, &ls.updatedAt)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return lockoutSnap{}
	case err != nil:
		t.Fatal(err)
	}
	ls.exists = true
	return ls
}

func newSeamProvider(t *testing.T, pool *pgxpool.Pool, failExecN, failQueryN, poisonExecN, poisonQueryN int) *NumberMatchPushProvider {
	t.Helper()
	p := NewNumberMatchPushProvider(context.Background(), pool, nil, "", "", pushLockoutLogger())
	p.txProbe = probeWith(failExecN, failQueryN, poisonExecN, poisonQueryN)
	return p
}

// TestVerifyChallenge_ErrorArms covers VerifyChallenge's DB-error returns:
// Begin failure (closed pool), challenge-lookup failure (non-sentinel
// propagation), burn/increment/consume UPDATE failures, and the COMMIT
// failure (poisoned transaction).
func TestVerifyChallenge_ErrorArms(t *testing.T) {

	t.Run("begin failure on closed pool", func(t *testing.T) {
		closed := testsupport.OpenTestPool(t)
		closed.Close()
		p := NewNumberMatchPushProvider(context.Background(), closed, nil, "", "", pushLockoutLogger())
		if err := p.VerifyChallenge(context.Background(), 1, "00", "00"); err == nil {
			t.Fatal("closed pool must fail closed")
		}
	})

	t.Run("lookup failure propagates non-sentinel", func(t *testing.T) {
		pool := testsupport.OpenTestPool(t)
		userID := seedPushRecoveryUser(t, pool)
		p := newSeamProvider(t, pool, 0, 1, 0, 0)
		nonce, _ := seedPushRecoveryChallenge(t, pool, userID)
		err := p.VerifyChallenge(context.Background(), userID, nonce, "42")
		if err == nil || errors.Is(err, ErrChallengeInvalid) {
			t.Fatalf("lookup failure must propagate a wrapped cause, got %v", err)
		}
	})

	t.Run("burn update failure", func(t *testing.T) {
		pool := testsupport.OpenTestPool(t)
		userID := seedPushRecoveryUser(t, pool)
		nonce, code := seedPushRecoveryChallenge(t, pool, userID)
		// Force failed_attempts to the burn threshold (3): the next wrong
		// answer takes the burn UPDATE — which the probe fails.
		if _, err := pool.Exec(context.Background(),
			`UPDATE push_mfa_challenges SET failed_attempts = 3 WHERE user_id = $1 AND nonce = decode($2,'hex')`,
			userID, nonce); err != nil {
			t.Fatal(err)
		}
		p := newSeamProvider(t, pool, 1, 0, 0, 0)
		if err := p.VerifyChallenge(context.Background(), userID, nonce, code); err == nil || errors.Is(err, ErrChallengeInvalid) {
			t.Fatalf("burn failure must propagate a wrapped cause, got %v", err)
		}
	})

	t.Run("increment update failure", func(t *testing.T) {
		pool := testsupport.OpenTestPool(t)
		userID := seedPushRecoveryUser(t, pool)
		nonce, _ := seedPushRecoveryChallenge(t, pool, userID)
		p := newSeamProvider(t, pool, 1, 0, 0, 0)
		if err := p.VerifyChallenge(context.Background(), userID, nonce, "00"); err == nil || errors.Is(err, ErrChallengeInvalid) {
			t.Fatalf("increment failure must propagate a wrapped cause, got %v", err)
		}
	})

	t.Run("consume update failure", func(t *testing.T) {
		pool := testsupport.OpenTestPool(t)
		userID := seedPushRecoveryUser(t, pool)
		nonce, code := seedPushRecoveryChallenge(t, pool, userID)
		p := newSeamProvider(t, pool, 1, 0, 0, 0)
		if err := p.VerifyChallenge(context.Background(), userID, nonce, code); err == nil || errors.Is(err, ErrChallengeInvalid) {
			t.Fatalf("consume failure must propagate a wrapped cause, got %v", err)
		}
	})

	t.Run("commit failure on poisoned transaction", func(t *testing.T) {
		pool := testsupport.OpenTestPool(t)
		userID := seedPushRecoveryUser(t, pool)
		nonce, code := seedPushRecoveryChallenge(t, pool, userID)
		p := newSeamProvider(t, pool, 0, 0, 1, 0)
		if err := p.VerifyChallenge(context.Background(), userID, nonce, code); err == nil {
			t.Fatal("poisoned commit must fail closed")
		}
	})
}

// TestVerifyChallenge_ResetAndCommitArms covers the ACCEPTED path's error
// returns: the post-acceptance lockout reset UPDATE and the COMMIT itself.
func TestVerifyChallenge_ResetAndCommitArms(t *testing.T) {
	t.Run("reset update failure", func(t *testing.T) {
		pool := testsupport.OpenTestPool(t)
		userID := seedPushRecoveryUser(t, pool)
		nonce, code := seedPushRecoveryChallenge(t, pool, userID)
		p := newSeamProvider(t, pool, 1, 0, 0, 0)
		if err := p.VerifyChallenge(context.Background(), userID, nonce, code); err == nil || errors.Is(err, ErrChallengeInvalid) {
			t.Fatalf("reset failure must propagate a wrapped cause, got %v", err)
		}
	})

	t.Run("commit failure on poisoned transaction", func(t *testing.T) {
		pool := testsupport.OpenTestPool(t)
		userID := seedPushRecoveryUser(t, pool)
		nonce, code := seedPushRecoveryChallenge(t, pool, userID)
		p := newSeamProvider(t, pool, 0, 0, 1, 0)
		if err := p.VerifyChallenge(context.Background(), userID, nonce, code); err == nil {
			t.Fatal("poisoned commit must fail closed")
		}
	})
}

// TestVerifyChallengeWithLockout_ErrorArms covers the lockout seam's
// DB-error returns: lock-row read, purpose probe, challenge lookup
// (non-sentinel rollback), record-failure UPDATE, the locked attempt's
// count-only UPDATE, and the three COMMIT points (locked attempt, purpose
// mismatch, wrong answer) via the poisoned transaction.
func TestVerifyChallengeWithLockout_ErrorArms(t *testing.T) {
	cases := []struct {
		name                      string
		failExecN, failQueryN     int
		poisonExecN, poisonQueryN int
		probe                     func(q lockoutQuerier) (bool, error)
		setup                     func(t *testing.T, pool *pgxpool.Pool, userID int64)
		wantOutcome               PushVerifyOutcome
		wantErr                   bool
	}{
		{
			name: "lock row read fails closed", failQueryN: 1,
			wantOutcome: PushVerifyInvalid, wantErr: true,
		},
		{
			name: "purpose probe fails closed", failQueryN: 2,
			wantOutcome: PushVerifyInvalid, wantErr: true,
		},
		{
			name: "challenge lookup fails closed and rolls back", failQueryN: 3,
			wantOutcome: PushVerifyInvalid, wantErr: true,
		},
		{
			name: "record failure update fails closed", failExecN: 2,
			wantOutcome: PushVerifyInvalid, wantErr: true,
		},
		{
			name: "locked attempt count update fails closed", failExecN: 1,
			setup: func(t *testing.T, pool *pgxpool.Pool, userID int64) {
				// Deterministic active lock: the count-only UPDATE is the first
				// Exec of the locked attempt, so failExecN=1 hits 298-299.
				if _, err := pool.Exec(context.Background(),
					`INSERT INTO auth_lockouts (lockout_key, failed_count, locked_until)
					 VALUES ($1, 5, now() + interval '15 minutes') ON CONFLICT (lockout_key) DO UPDATE
					 SET failed_count = 5, locked_until = now() + interval '15 minutes'`,
					pushLockoutKey(userID)); err != nil {
					t.Fatal(err)
				}
			},
			wantOutcome: PushVerifyLocked, wantErr: true,
		},
		{
			name: "locked attempt commit fails closed", poisonExecN: 1,
			setup: func(t *testing.T, pool *pgxpool.Pool, userID int64) {
				if _, err := pool.Exec(context.Background(),
					`INSERT INTO auth_lockouts (lockout_key, failed_count, locked_until)
					 VALUES ($1, 5, now() + interval '15 minutes') ON CONFLICT (lockout_key) DO UPDATE
					 SET failed_count = 5, locked_until = now() + interval '15 minutes'`,
					pushLockoutKey(userID)); err != nil {
					t.Fatal(err)
				}
			},
			wantOutcome: PushVerifyLocked, wantErr: true,
		},
		{
			name:        "purpose mismatch commit fails closed",
			wantOutcome: PushVerifyInvalid, wantErr: true,
			setup: func(t *testing.T, pool *pgxpool.Pool, userID int64) {
				nonce, _ := seedLoginPurposeChallenge(t, pool, userID)
				_ = nonce
			},
			probe: func(q lockoutQuerier) (bool, error) {
				_, _ = q.Exec(context.Background(), "SELECT 1/(1-1)") // abort the tx
				return false, nil                                     // definitive mismatch
			},
		},
		{
			name: "wrong answer commit fails closed", poisonExecN: 2,
			wantOutcome: PushVerifyInvalid, wantErr: true,
		},
		{
			// ACCEPTED path: the post-acceptance lockout reset UPDATE fails.
			name: "reset update fails closed", failExecN: 2,
			wantOutcome: PushVerifyInvalid, wantErr: true,
		},
		{
			// ACCEPTED path: the reset succeeds but the poisoned COMMIT fails.
			name: "accepted commit fails closed", poisonExecN: 2,
			wantOutcome: PushVerifyInvalid, wantErr: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			pool := testsupport.OpenTestPool(t)
			userID := seedPushRecoveryUser(t, pool)
			if tc.setup != nil {
				tc.setup(t, pool, userID)
			}
			nonce, code := seedPushRecoveryChallenge(t, pool, userID)
			p := newSeamProvider(t, pool, tc.failExecN, tc.failQueryN, tc.poisonExecN, tc.poisonQueryN)
			if tc.probe != nil {
				p.purposeProbe = func(ctx context.Context, q lockoutQuerier, _ []byte, _ int64, _ string) (bool, error) {
					return tc.probe(q)
				}
			}

			answer := code
			if tc.name == "wrong answer commit fails closed" || tc.name == "record failure update fails closed" {
				answer = "00"
				if answer == code {
					answer = "11"
				}
			}
			if tc.name == "purpose mismatch commit fails closed" {
				nonce, _ = seedLoginPurposeChallenge(t, pool, userID)
			}
			beforeChallenge := snapChallengeByNonce(t, pool, nonce)
			beforeLock := snapLockout(t, pool, userID)

			outcome, err := p.VerifyChallengeWithLockout(context.Background(), userID, nonce, answer)
			if outcome != tc.wantOutcome {
				t.Fatalf("outcome = %v, want %v (err=%v)", outcome, tc.wantOutcome, err)
			}
			if tc.wantErr {
				if err == nil {
					t.Fatal("want a wrapped cause for the injected failure")
				}
				if tc.poisonExecN > 0 || tc.poisonQueryN > 0 || tc.probe != nil {
					// pgx surfaces the aborted-transaction COMMIT either as
					// ErrTxCommitRollback or as the server's 25P02.
					var pgErr *pgconn.PgError
					if !errors.Is(err, pgx.ErrTxCommitRollback) && !(errors.As(err, &pgErr) && pgErr.Code == "25P02") {
						t.Fatalf("poisoned commit: err = %v, want an aborted-transaction commit failure", err)
					}
				} else if !errors.Is(err, errInjected) {
					t.Fatalf("err = %v, want errors.Is(errInjected)", err)
				}
			}

			// Rollback / no-partial-state, compared FIELD BY FIELD: the whole
			// transaction must roll back — the challenge row identical (the
			// increment never lands) and the lockout row byte-identical
			// (existence, counter, horizon, last-touch).
			if afterChallenge := snapChallengeByNonce(t, pool, nonce); beforeChallenge != afterChallenge {
				t.Fatalf("challenge state changed across injected failure: %+v -> %+v", beforeChallenge, afterChallenge)
			}
			if afterLock := snapLockout(t, pool, userID); beforeLock != afterLock {
				t.Fatalf("lockout state changed across injected failure: %+v -> %+v", beforeLock, afterLock)
			}
		})
	}
}
