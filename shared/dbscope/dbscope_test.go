package dbscope

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"setjoin.com/shared/testsupport"
)

// fakeTx records the statements run on it and the commit/rollback outcome, so a
// test can assert RunScoped sets the GUC first, runs fn, and commits — with NO
// Postgres. It implements just enough of pgx.Tx for RunScoped's path (Exec +
// Commit + Rollback); the rest panics if ever reached (it shouldn't be).
type fakeTx struct {
	pgx.Tx
	execs      []string
	committed  bool
	rolledBack bool
	execErr    error
}

func (f *fakeTx) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	f.execs = append(f.execs, sql)
	return pgconn.CommandTag{}, f.execErr
}
func (f *fakeTx) Commit(context.Context) error   { f.committed = true; return nil }
func (f *fakeTx) Rollback(context.Context) error { f.rolledBack = true; return nil }

// fakePool hands back a single fakeTx and records Begin errors.
type fakePool struct {
	tx       *fakeTx
	beginErr error
}

func (p *fakePool) Begin(context.Context) (pgx.Tx, error) {
	if p.beginErr != nil {
		return nil, p.beginErr
	}
	return p.tx, nil
}

func TestRunScoped_SetsGUCThenCommits(t *testing.T) {
	tx := &fakeTx{}
	p := &fakePool{tx: tx}
	var ran bool
	err := RunScoped(context.Background(), p, 42, func(pgx.Tx) error { ran = true; return nil })
	if err != nil {
		t.Fatalf("RunScoped returned error: %v", err)
	}
	if !ran {
		t.Fatal("fn was not run")
	}
	if len(tx.execs) != 1 || tx.execs[0] != "SELECT set_config('app.current_mailbox_id', $1, true)" {
		t.Fatalf("expected the transaction-scoped set_config Exec first, got %v", tx.execs)
	}
	if !tx.committed {
		t.Fatal("expected Commit")
	}
}

func TestRunScoped_RollsBackOnFnError(t *testing.T) {
	tx := &fakeTx{}
	p := &fakePool{tx: tx}
	want := errors.New("boom")
	err := RunScoped(context.Background(), p, 7, func(pgx.Tx) error { return want })
	if !errors.Is(err, want) {
		t.Fatalf("expected fn error returned verbatim, got %v", err)
	}
	if tx.committed {
		t.Fatal("must not commit when fn errors")
	}
	if !tx.rolledBack {
		t.Fatal("expected Rollback (deferred) when fn errors")
	}
}

func TestRunScoped_BeginError(t *testing.T) {
	want := errors.New("no conn")
	p := &fakePool{beginErr: want}
	err := RunScoped(context.Background(), p, 1, func(pgx.Tx) error {
		t.Fatal("fn must not run when Begin fails")
		return nil
	})
	if !errors.Is(err, want) {
		t.Fatalf("expected Begin error, got %v", err)
	}
}

// ── RunUserScoped unit tests (fake pool, no DB) ───────────────────────────────

func TestRunUserScoped_SetsGUCThenCommits(t *testing.T) {
	tx := &fakeTx{}
	p := &fakePool{tx: tx}
	var ran bool
	err := RunUserScoped(context.Background(), p, 42, func(pgx.Tx) error { ran = true; return nil })
	if err != nil {
		t.Fatalf("RunUserScoped returned error: %v", err)
	}
	if !ran {
		t.Fatal("fn was not run")
	}
	if len(tx.execs) != 1 || tx.execs[0] != "SELECT set_config('app.current_user_id', $1, true)" {
		t.Fatalf("expected the transaction-scoped set_config Exec first, got %v", tx.execs)
	}
	if !tx.committed {
		t.Fatal("expected Commit")
	}
}

func TestRunUserScoped_RollsBackOnFnError(t *testing.T) {
	tx := &fakeTx{}
	p := &fakePool{tx: tx}
	want := errors.New("boom")
	err := RunUserScoped(context.Background(), p, 7, func(pgx.Tx) error { return want })
	if !errors.Is(err, want) {
		t.Fatalf("expected fn error returned verbatim, got %v", err)
	}
	if tx.committed {
		t.Fatal("must not commit when fn errors")
	}
	if !tx.rolledBack {
		t.Fatal("expected Rollback (deferred) when fn errors")
	}
}

func TestRunUserScoped_BeginError(t *testing.T) {
	want := errors.New("no conn")
	p := &fakePool{beginErr: want}
	err := RunUserScoped(context.Background(), p, 1, func(pgx.Tx) error {
		t.Fatal("fn must not run when Begin fails")
		return nil
	})
	if !errors.Is(err, want) {
		t.Fatalf("expected Begin error, got %v", err)
	}
}

// ── RLS leak test (DB-backed) ─────────────────────────────────────────────────
//
// This test proves that FORCE ROW LEVEL SECURITY on approval_requests is
// enforced for non-superuser roles. The test DB's mail role is a superuser
// (bypasses RLS), so we use SET LOCAL ROLE setjoin_app within a transaction
// to impersonate a non-superuser role and verify that only the rows authorized
// by app.current_user_id are visible.
//
// SPLIT PROOF MODEL:
//
//	handler_test.go  — tests the BZ error map (BZ106→409, BZ107→403, …) on the
//	                   superuser pool; RLS is bypassed but that is correct for
//	                   exercising the reducer's application-level logic.
//	THIS TEST         — proves that a stranger cannot see another user's requests
//	                   even when the application-level check passes; this is the
//	                   only way the database-level defense is actually exercised.
//
// Uses large explicit IDs (99980–99983) to avoid collision with pgTAP fixtures.
func TestRunUserScoped_RLSLeakProof(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	const (
		domainID = int64(99980)
		userA    = int64(99981) // requester of R1; approver of R2 → should see both
		userB    = int64(99982) // approver of R1; requester of R2 → should see both
		userC    = int64(99983) // totally unrelated → should see 0
	)

	// Insert fixtures as superuser (RLS bypassed on this pool).
	if _, err := pool.Exec(ctx,
		`INSERT INTO domains (id, name, is_local) VALUES ($1, 'rls-probe.test', true) ON CONFLICT DO NOTHING`,
		domainID,
	); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	for _, u := range []struct {
		id       int64
		username string
		email    string
	}{
		{userA, "rls_probe_a", "rls_a@rls-probe.test"},
		{userB, "rls_probe_b", "rls_b@rls-probe.test"},
		{userC, "rls_probe_c", "rls_c@rls-probe.test"},
	} {
		if _, err := pool.Exec(ctx,
			`INSERT INTO users (id, username, domain_id, email, display_name) VALUES ($1, $2, $3, $4, $2) ON CONFLICT DO NOTHING`,
			u.id, u.username, domainID, u.email,
		); err != nil {
			t.Fatalf("insert user %d: %v", u.id, err)
		}
	}

	// R1: userA requested, userB is the approver.
	// R2: userB requested, userA is the approver.
	var r1, r2 int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO approval_requests
		  (consumer_type, requester_user_id, subject, payload, approver_kind, approver_ref, expires_at)
		VALUES ('rbac.jit_activation', $1, 'r1', '{}', 'user', $2, now()+interval '1h')
		RETURNING id`, userA, userB,
	).Scan(&r1); err != nil {
		t.Fatalf("insert R1: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO approval_requests
		  (consumer_type, requester_user_id, subject, payload, approver_kind, approver_ref, expires_at)
		VALUES ('rbac.jit_activation', $1, 'r2', '{}', 'user', $2, now()+interval '1h')
		RETURNING id`, userB, userA,
	).Scan(&r2); err != nil {
		t.Fatalf("insert R2: %v", err)
	}

	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM approval_requests WHERE id IN ($1,$2)`, r1, r2)     //nolint:errcheck
		pool.Exec(ctx, `DELETE FROM users WHERE id IN ($1,$2,$3)`, userA, userB, userC) //nolint:errcheck
		pool.Exec(ctx, `DELETE FROM domains WHERE id = $1`, domainID)                   //nolint:errcheck
	})

	// ── Prove RLS via the REAL RunUserScoped ─────────────────────────────────
	// Calls RunUserScoped (the production code path) so the GUC constant in
	// dbscope.go drives the policy. Inside the callback we switch to the
	// non-superuser setjoin_app role (SET LOCAL — same tx) so FORCE RLS fires.
	// If the GUC name in RunUserScoped is wrong, the policy sees NULL and blocks
	// all rows for every user → the userA/userB assertions fail → test fails.
	check := func(userID int64, wantIDs []int64) {
		t.Helper()
		var got []int64
		err := RunUserScoped(ctx, pool, userID, func(tx pgx.Tx) error {
			// Role switch is LOCAL (same tx): GUC already set by RunUserScoped above.
			if _, err := tx.Exec(ctx, "SET LOCAL ROLE setjoin_app"); err != nil {
				return err
			}
			rows, err := tx.Query(ctx,
				`SELECT id FROM approval_requests WHERE id IN ($1,$2) ORDER BY id`, r1, r2)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var id int64
				if err := rows.Scan(&id); err != nil {
					return err
				}
				got = append(got, id)
			}
			return rows.Err()
		})
		if err != nil {
			t.Fatalf("RunUserScoped (user=%d): %v", userID, err)
		}
		if len(got) != len(wantIDs) {
			t.Errorf("user=%d: RLS returned %v, want IDs count=%d (ids=%v)",
				userID, got, len(wantIDs), wantIDs)
			return
		}
		for i, want := range wantIDs {
			if got[i] != want {
				t.Errorf("user=%d: got[%d]=%d, want %d", userID, i, got[i], want)
			}
		}
	}

	// userA: requester of R1, approver of R2 → sees both (order by id ascending).
	check(userA, []int64{r1, r2})
	// userB: approver of R1, requester of R2 → sees both.
	check(userB, []int64{r1, r2})
	// userC: no relation to either request → sees none.
	check(userC, nil)
}
