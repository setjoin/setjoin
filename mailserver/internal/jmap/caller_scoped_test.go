package jmap

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"setjoin.com/mailserver/internal/reducercall"
)

// caller_scoped_test.go — the PLUMBING PROOF for the native-RLS proof slice
// (ARCH-006, plan 2026-06-18-native-rls-backstop.md Phase 1). These tests prove
// the reducercall.PoolCaller.CallScoped tx-wrapper behaves correctly: it sets the
// transaction-scoped app.current_mailbox_id GUC to the authenticated mailbox
// inside one explicit BEGIN…COMMIT, the tx boundary commits on success and rolls
// back on error, the LOCAL setting does NOT leak past the transaction (PgBouncer
// transaction-mode safety), and the wrapped path returns the same JSON as the
// unwrapped Call (behaviour-preserving).
//
// They require a loaded DB (DB_DSN). They do NOT enable RLS — the 🔒 wrap≠enforce
// constraint. The runtime-deny mechanism is proven separately and isolated in
// mailserver/sql/tests/rls_mechanism.pg (pgTAP), without touching production
// tables.

// TestCallScoped_SetsGUCToAuthenticatedMailbox proves that inside the wrapped
// transaction BOTH current_setting('app.current_mailbox_id') AND the reducer's
// $1 (which the c5 seam prepends — the handler states the id once) equal the
// mailbox id the handler passed. GUC == $1 by construction, proven live here
// through jmap's reducercall.PoolCaller construction.
func TestCallScoped_SetsGUCToAuthenticatedMailbox(t *testing.T) {
	pool := testPoolDB(t)
	ctx := context.Background()

	// A one-shot probe function reporting both sides of the invariant (the GUC
	// and its $1), callable through the same SELECT fn($1) shape the real
	// reducers use. Created/dropped in this test only (never in production).
	const probe = "rls_proof_guc_probe"
	if _, err := pool.Exec(ctx,
		`CREATE OR REPLACE FUNCTION `+probe+`(p_mailbox_id BIGINT) RETURNS JSONB
		 LANGUAGE sql AS $$
		   SELECT jsonb_build_object(
		     'guc',  current_setting('app.current_mailbox_id', true),
		     'arg1', p_mailbox_id)
		 $$`,
	); err != nil {
		t.Fatalf("create probe fn: %v", err)
	}
	t.Cleanup(func() { pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS `+probe+`(BIGINT)`) })

	c := reducercall.PoolCaller{Pool: pool}

	const wantMailbox int64 = 4242
	raw, err := c.CallScoped(ctx, wantMailbox, probe) // id stated ONCE; seam supplies $1
	if err != nil {
		t.Fatalf("CallScoped: %v", err)
	}
	var got struct {
		GUC  string `json:"guc"`
		Arg1 int64  `json:"arg1"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal probe result %q: %v", raw, err)
	}
	if got.GUC != "4242" {
		t.Fatalf("GUC inside the wrapped tx = %q, want \"4242\" (the authenticated mailbox)", got.GUC)
	}
	if got.Arg1 != wantMailbox {
		t.Fatalf("reducer $1 = %d, want %d — GUC (%q) and $1 must be the same id (c5 invariant)", got.Arg1, wantMailbox, got.GUC)
	}
}

// TestCallScoped_GUCDoesNotLeakAcrossTransactions proves PgBouncer
// transaction-mode safety: because the set_config is is_local=TRUE, the GUC is
// reset at COMMIT. A subsequent NON-wrapped read on a pooled connection sees an
// empty GUC, NOT the previous request's mailbox id — the exact leak
// DATABASE_SECURITY.md:149 warns of with session scope. We make the probe leave
// no trace by reading the GUC directly after the wrapped call returns.
func TestCallScoped_GUCDoesNotLeakAcrossTransactions(t *testing.T) {
	pool := testPoolDB(t)
	ctx := context.Background()

	const probe = "rls_proof_guc_probe"
	if _, err := pool.Exec(ctx,
		`CREATE OR REPLACE FUNCTION `+probe+`(p_mailbox_id BIGINT) RETURNS JSONB
		 LANGUAGE sql AS $$ SELECT to_jsonb(current_setting('app.current_mailbox_id', true)) $$`,
	); err != nil {
		t.Fatalf("create probe fn: %v", err)
	}
	t.Cleanup(func() { pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS `+probe+`(BIGINT)`) })

	c := reducercall.PoolCaller{Pool: pool}
	if _, err := c.CallScoped(ctx, 999, probe); err != nil { // seam supplies $1
		t.Fatalf("CallScoped: %v", err)
	}

	// Now read the GUC on the SAME pool, OUTSIDE any wrapper. With is_local=TRUE
	// it must be reset (empty string when never set in this tx). If it returned
	// "999" the LOCAL setting had leaked — the transaction-mode trap.
	var leaked string
	if err := pool.QueryRow(ctx,
		`SELECT current_setting('app.current_mailbox_id', true)`,
	).Scan(&leaked); err != nil {
		t.Fatalf("post-tx GUC read: %v", err)
	}
	if leaked == "999" {
		t.Fatalf("app.current_mailbox_id leaked across transactions (got %q) — set_config must be is_local=TRUE", leaked)
	}
}

// TestCallScopedBatch_GUCOnceAcrossAllPhases_JMAPDelegation is the c3 ▲
// security invariant proven through jmap's reducercall.PoolCaller construction (the path
// dispatchSet actually takes): all legs of one batch share ONE transaction
// (identical txid), the GUC is set once and identical for every phase, and
// every leg's $1 is that same scope — GUC == $1 for create, update, AND
// destroy. The deep proof lives in reducercall_test.go; this pins the shim.
func TestCallScopedBatch_GUCOnceAcrossAllPhases_JMAPDelegation(t *testing.T) {
	pool := testPoolDB(t)
	ctx := context.Background()

	const probe = "rls_proof_batch_probe_jmap"
	if _, err := pool.Exec(ctx,
		`CREATE OR REPLACE FUNCTION `+probe+`(p_mailbox_id BIGINT, p_phase TEXT) RETURNS JSONB
		 LANGUAGE sql AS $$
		   SELECT jsonb_build_object(
		     'guc',  current_setting('app.current_mailbox_id', true),
		     'arg1', p_mailbox_id,
		     'txid', txid_current())
		 $$`,
	); err != nil {
		t.Fatalf("create probe fn: %v", err)
	}
	t.Cleanup(func() { pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS `+probe+`(BIGINT, TEXT)`) })

	c := reducercall.PoolCaller{Pool: pool}
	results, err := c.CallScopedBatch(ctx, 4242, // scope stated ONCE
		reducercall.ScopedCall{Fn: probe, Args: []any{"create"}},
		reducercall.ScopedCall{Fn: probe, Args: []any{"update"}},
		reducercall.ScopedCall{Fn: probe, Args: []any{"destroy"}},
	)
	if err != nil {
		t.Fatalf("CallScopedBatch: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}
	var firstTx int64
	for i, raw := range results {
		var got struct {
			GUC  string `json:"guc"`
			Arg1 int64  `json:"arg1"`
			TxID int64  `json:"txid"`
		}
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("unmarshal result[%d] %q: %v", i, raw, err)
		}
		if got.GUC != "4242" || got.Arg1 != 4242 {
			t.Fatalf("leg %d: GUC=%q $1=%d, want both 4242 — the GUC must hold, identical, for every phase", i, got.GUC, got.Arg1)
		}
		if i == 0 {
			firstTx = got.TxID
		} else if got.TxID != firstTx {
			t.Fatalf("leg %d: txid=%d, want %d — one /set must be ONE transaction", i, got.TxID, firstTx)
		}
	}
}

// TestCallScoped_RollsBackOnReducerError proves the tx boundary: when the reducer
// raises, CallScoped returns the raw pgx error (preserving the BZ→JMAP map) and
// the transaction is rolled back (no partial commit). We use a probe that always
// RAISEs and confirm the error surfaces AND no side effect persisted.
func TestCallScoped_RollsBackOnReducerError(t *testing.T) {
	pool := testPoolDB(t)
	ctx := context.Background()

	// A marker table the probe tries to write before raising; after rollback it
	// must be empty, proving the whole unit (write + raise) was atomic.
	if _, err := pool.Exec(ctx, `CREATE TEMP TABLE IF NOT EXISTS rls_proof_marker (n BIGINT)`); err != nil {
		// TEMP tables are connection-scoped under transaction-mode pooling, so a
		// persistent marker table is more reliable for the cross-call assertion.
		t.Logf("temp table note: %v", err)
	}
	const tbl = "rls_proof_marker_p"
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS `+tbl+` (n BIGINT)`); err != nil {
		t.Fatalf("create marker table: %v", err)
	}
	t.Cleanup(func() { pool.Exec(context.Background(), `DROP TABLE IF EXISTS `+tbl) })
	pool.Exec(ctx, `TRUNCATE `+tbl)

	const raiser = "rls_proof_raiser"
	if _, err := pool.Exec(ctx,
		`CREATE OR REPLACE FUNCTION `+raiser+`(p_n BIGINT) RETURNS JSONB
		 LANGUAGE plpgsql AS $$
		 BEGIN
		   INSERT INTO `+tbl+`(n) VALUES (p_n);
		   RAISE EXCEPTION 'proof-slice forced failure' USING ERRCODE='BZ099';
		 END $$`,
	); err != nil {
		t.Fatalf("create raiser fn: %v", err)
	}
	t.Cleanup(func() { pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS `+raiser+`(BIGINT)`) })

	c := reducercall.PoolCaller{Pool: pool}
	_, err := c.CallScoped(ctx, 7, raiser) // seam supplies p_n ($1) = 7
	if err == nil {
		t.Fatal("CallScoped returned nil error, want the reducer's BZ099 failure")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "BZ099" {
		t.Fatalf("error = %v, want a *pgconn.PgError with code BZ099 (BZ→JMAP map preserved)", err)
	}

	// The INSERT inside the failed tx must have been rolled back.
	var rows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+tbl).Scan(&rows); err != nil {
		t.Fatalf("marker count: %v", err)
	}
	if rows != 0 {
		t.Fatalf("marker table has %d rows after rollback, want 0 — tx was not rolled back", rows)
	}
}

// TestCallScoped_BehaviourPreserved proves the wrapped path returns the SAME
// JSON the unwrapped Call returns for the same reducer call (RLS is not enabled,
// so the GUC changes nothing observable). This is the behaviour-preservation
// half of the gate for routing Email/get through CallScoped.
func TestCallScoped_BehaviourPreserved(t *testing.T) {
	pool := testPoolDB(t)
	ctx := context.Background()

	const echo = "rls_proof_echo"
	if _, err := pool.Exec(ctx,
		`CREATE OR REPLACE FUNCTION `+echo+`(p_n BIGINT) RETURNS JSONB
		 LANGUAGE sql AS $$ SELECT jsonb_build_object('n', p_n, 'ok', true) $$`,
	); err != nil {
		t.Fatalf("create echo fn: %v", err)
	}
	t.Cleanup(func() { pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS `+echo+`(BIGINT)`) })

	c := reducercall.PoolCaller{Pool: pool}

	plain, err := c.Call(ctx, echo, int64(123))
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	// CallScoped states the id once; the seam prepends it as $1, so the reducer
	// receives exactly what the unwrapped Call passed explicitly.
	scoped, err := c.CallScoped(ctx, 123, echo)
	if err != nil {
		t.Fatalf("CallScoped: %v", err)
	}
	if string(plain) != string(scoped) {
		t.Fatalf("wrapped result %s != unwrapped result %s — behaviour not preserved", scoped, plain)
	}
}
