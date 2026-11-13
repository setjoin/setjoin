package reducercall

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/testsupport"
)

// TestBuildReducerSQLMatchesHandWritten guards the invariant that
// BuildReducerSQL — shared by PoolCaller and any fake — renders the exact SQL
// the routed sites used to hand-write, so routing through the seam is a no-op on
// the wire. (Lifted from internal/jmap/caller_test.go when the seam was shared.)
func TestBuildReducerSQLMatchesHandWritten(t *testing.T) {
	cases := []struct {
		fn   string
		n    int
		want string
	}{
		{"effective_capabilities", 1, "SELECT effective_capabilities($1)"},
		{"jmap_mailbox_get", 3, "SELECT jmap_mailbox_get($1, $2, $3)"},
		{"jmap_email_query", 5, "SELECT jmap_email_query($1, $2, $3, $4, $5)"},
		{"directory_tree", 1, "SELECT directory_tree($1)"},
		{"jmap_calendar_event_rsvp", 5, "SELECT jmap_calendar_event_rsvp($1, $2, $3, $4, $5)"},
		{"jmap_contact_set_create", 2, "SELECT jmap_contact_set_create($1, $2)"},
		{"calendar_free_busy", 4, "SELECT calendar_free_busy($1, $2, $3, $4)"},
		{"noargs", 0, "SELECT noargs()"},
	}
	for _, c := range cases {
		if got := BuildReducerSQL(c.fn, c.n); got != c.want {
			t.Errorf("BuildReducerSQL(%q,%d) = %q, want %q", c.fn, c.n, got, c.want)
		}
	}
}

// TestPoolCallerSatisfiesCaller is a compile-time assertion that the production
// adapter implements the seam interface.
func TestPoolCallerSatisfiesCaller(t *testing.T) {
	var _ Caller = PoolCaller{}
	var _ Caller = New(nil)
}

// TestScopedShape_PrependsScopeAsArg1 is the no-DB half of the c5 invariant:
// CallScoped states the mailbox ONCE and the seam makes it the reducer's $1, so
// the emitted SQL/arg-shape for every migrated site is byte-identical to the
// pre-c5 double-pass form — same fn name, same TOTAL placeholder count (the
// seam's prepended id replaces the arg the call site used to repeat), scope as
// allArgs[0], remaining args shifted by exactly one. scopedShape is the single
// code path CallScoped executes, so asserting on it covers every call through
// the seam.
func TestScopedShape_PrependsScopeAsArg1(t *testing.T) {
	cases := []struct {
		name    string
		mailbox int64
		fn      string
		args    []any
		wantSQL string // == the hand-written SQL the site emitted BEFORE c5
	}{
		// mail.go emailQuery: was CallScoped(ctx, id, fn, id, filter, sort, pos, limit)
		{"email_query", 7, "jmap_email_query", []any{json.RawMessage(`{}`), nil, 3, 50},
			"SELECT jmap_email_query($1, $2, $3, $4, $5)"},
		// savedsearches.go list: was CallScoped(ctx, id, fn, id) — scope was the ONLY arg
		{"saved_search_list", 42, "saved_search_list", nil,
			"SELECT saved_search_list($1)"},
		// handler.go effective capabilities: scope-only
		{"effective_capabilities", 9001, "effective_capabilities", nil,
			"SELECT effective_capabilities($1)"},
		// calendar.go event set_create: was CallScoped(ctx, id, fn, id, userID, email, create)
		{"calendar_event_set_create", 5, "jmap_calendar_event_set_create", []any{int64(11), "a@b.c", json.RawMessage(`{}`)},
			"SELECT jmap_calendar_event_set_create($1, $2, $3, $4)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sql, all := scopedShape(c.mailbox, c.fn, c.args)
			if sql != c.wantSQL {
				t.Errorf("scopedShape SQL = %q, want %q (byte-identical to the pre-c5 hand-written shape)", sql, c.wantSQL)
			}
			if len(all) != len(c.args)+1 {
				t.Fatalf("arg count = %d, want %d (scope + %d reducer args)", len(all), len(c.args)+1, len(c.args))
			}
			if got, ok := all[0].(int64); !ok || got != c.mailbox {
				t.Errorf("allArgs[0] = %v (%T), want the scope mailbox id %d — $1 must BE the GUC value", all[0], all[0], c.mailbox)
			}
			for i, a := range c.args {
				// reflect.DeepEqual: args may be non-comparable (json.RawMessage).
				if !reflect.DeepEqual(all[i+1], a) {
					t.Errorf("allArgs[%d] = %v, want %v (call-site args must shift by exactly one)", i+1, all[i+1], a)
				}
			}
		})
	}
}

// --- DB-backed CallScoped proof slice (lifted from jmap/caller_scoped_test.go) ---
//
// These prove the PoolCaller.CallScoped tx-wrapper behaves correctly: it sets
// the transaction-scoped app.current_mailbox_id GUC to the authenticated
// mailbox inside one explicit BEGIN…COMMIT, the tx boundary commits on success
// and rolls back on error, the LOCAL setting does NOT leak past the transaction
// (PgBouncer transaction-mode safety), and the wrapped path returns the same
// JSON as the unwrapped Call (behaviour-preserving). They require a loaded DB
// (DB_DSN). They do NOT enable RLS — the 🔒 wrap≠enforce constraint.

func testPoolDB(t *testing.T) *pgxpool.Pool {
	return testsupport.OpenTestPool(t)
}

// TestCallScoped_SetsGUCToAuthenticatedMailbox proves the c5 invariant against a
// live DB: inside the wrapped transaction, the GUC
// current_setting('app.current_mailbox_id') AND the reducer's $1 (which the seam
// prepends — the call site does not pass it) are BOTH the mailbox id the caller
// stated once. GUC == $1 for every call through the seam.
func TestCallScoped_SetsGUCToAuthenticatedMailbox(t *testing.T) {
	pool := testPoolDB(t)
	ctx := context.Background()

	// The probe reports both sides of the invariant: what the GUC says and what
	// arrived as $1 (p_mailbox_id).
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

	c := PoolCaller{Pool: pool}

	const wantMailbox int64 = 4242
	// NOTE: wantMailbox is stated ONCE — the seam supplies the reducer's $1.
	raw, err := c.CallScoped(ctx, wantMailbox, probe)
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
	// The invariant itself: the reducer's $1 must be the same id the GUC holds.
	if got.Arg1 != wantMailbox {
		t.Fatalf("reducer $1 = %d, want %d — GUC (%q) and $1 must be the same id (c5 invariant)", got.Arg1, wantMailbox, got.GUC)
	}
}

// TestCallScoped_GUCDoesNotLeakAcrossTransactions proves PgBouncer
// transaction-mode safety: because the set_config is is_local=TRUE, the GUC is
// reset at COMMIT.
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

	c := PoolCaller{Pool: pool}
	if _, err := c.CallScoped(ctx, 999, probe); err != nil { // seam supplies $1
		t.Fatalf("CallScoped: %v", err)
	}

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

// TestCallScoped_RollsBackOnReducerError proves the tx boundary: when the
// reducer raises, CallScoped returns the raw pgx error (preserving the
// BZ→protocol map) and the transaction is rolled back (no partial commit).
func TestCallScoped_RollsBackOnReducerError(t *testing.T) {
	pool := testPoolDB(t)
	ctx := context.Background()

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

	c := PoolCaller{Pool: pool}
	_, err := c.CallScoped(ctx, 7, raiser) // seam supplies p_n ($1) = 7
	if err == nil {
		t.Fatal("CallScoped returned nil error, want the reducer's BZ099 failure")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "BZ099" {
		t.Fatalf("error = %v, want a *pgconn.PgError with code BZ099 (BZ→protocol map preserved)", err)
	}

	var rows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+tbl).Scan(&rows); err != nil {
		t.Fatalf("marker count: %v", err)
	}
	if rows != 0 {
		t.Fatalf("marker table has %d rows after rollback, want 0 — tx was not rolled back", rows)
	}
}

// --- CallScopedBatch (c3: one JMAP /set = one transaction) ---

// TestCallScopedBatch_OneTxGUCOnceAcrossAllPhases is the ▲ c3 SECURITY
// INVARIANT (the c5 GUC==$1 test shape extended to the batch): every call in
// the batch runs inside ONE transaction (identical txid_current() across all
// legs), with the GUC set ONCE before the first leg and identical for every
// statement, and the scope prepended as each leg's $1 — GUC == $1 for every
// phase, the scope stated exactly once by the caller.
func TestCallScopedBatch_OneTxGUCOnceAcrossAllPhases(t *testing.T) {
	pool := testPoolDB(t)
	ctx := context.Background()

	const probe = "rls_proof_batch_probe"
	if _, err := pool.Exec(ctx,
		`CREATE OR REPLACE FUNCTION `+probe+`(p_mailbox_id BIGINT, p_phase TEXT) RETURNS JSONB
		 LANGUAGE sql AS $$
		   SELECT jsonb_build_object(
		     'guc',   current_setting('app.current_mailbox_id', true),
		     'arg1',  p_mailbox_id,
		     'phase', p_phase,
		     'txid',  txid_current())
		 $$`,
	); err != nil {
		t.Fatalf("create probe fn: %v", err)
	}
	t.Cleanup(func() { pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS `+probe+`(BIGINT, TEXT)`) })

	c := PoolCaller{Pool: pool}

	const wantMailbox int64 = 4242
	// Scope stated ONCE for the whole batch; the seam supplies every leg's $1.
	results, err := c.CallScopedBatch(ctx, wantMailbox,
		ScopedCall{Fn: probe, Args: []any{"create"}},
		ScopedCall{Fn: probe, Args: []any{"update"}},
		ScopedCall{Fn: probe, Args: []any{"destroy"}},
	)
	if err != nil {
		t.Fatalf("CallScopedBatch: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3 (one per call, in order)", len(results))
	}
	var first struct {
		TxID int64 `json:"txid"`
	}
	for i, raw := range results {
		var got struct {
			GUC   string `json:"guc"`
			Arg1  int64  `json:"arg1"`
			Phase string `json:"phase"`
			TxID  int64  `json:"txid"`
		}
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("unmarshal result[%d] %q: %v", i, raw, err)
		}
		if got.GUC != "4242" {
			t.Fatalf("phase %q: GUC = %q, want \"4242\" — the GUC must hold for EVERY statement in the tx", got.Phase, got.GUC)
		}
		if got.Arg1 != wantMailbox {
			t.Fatalf("phase %q: reducer $1 = %d, want %d — GUC and $1 must be the same id in every leg", got.Phase, got.Arg1, wantMailbox)
		}
		if i == 0 {
			first.TxID = got.TxID
		} else if got.TxID != first.TxID {
			t.Fatalf("phase %q: txid = %d, want %d — all legs must share ONE transaction", got.Phase, got.TxID, first.TxID)
		}
	}
}

// TestCallScopedBatch_AllOrNothing_RollsBackEarlierPhases is the c3 product
// semantics change (RFC 8620 §3.6.2): when a later phase raises, the WHOLE
// batch rolls back — an earlier phase's committed-looking write does NOT
// persist. The error surfaces as the raw pgx error (BZ map preserved through
// the fn-name wrap).
func TestCallScopedBatch_AllOrNothing_RollsBackEarlierPhases(t *testing.T) {
	pool := testPoolDB(t)
	ctx := context.Background()

	const tbl = "rls_proof_batch_marker"
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS `+tbl+` (n BIGINT)`); err != nil {
		t.Fatalf("create marker table: %v", err)
	}
	t.Cleanup(func() { pool.Exec(context.Background(), `DROP TABLE IF EXISTS `+tbl) })
	pool.Exec(ctx, `TRUNCATE `+tbl)

	const writer = "rls_proof_batch_writer"
	if _, err := pool.Exec(ctx,
		`CREATE OR REPLACE FUNCTION `+writer+`(p_n BIGINT) RETURNS JSONB
		 LANGUAGE plpgsql AS $$
		 BEGIN
		   INSERT INTO `+tbl+`(n) VALUES (p_n);
		   RETURN '{"created":true}'::JSONB;
		 END $$`,
	); err != nil {
		t.Fatalf("create writer fn: %v", err)
	}
	t.Cleanup(func() { pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS `+writer+`(BIGINT)`) })

	const raiser = "rls_proof_batch_raiser"
	if _, err := pool.Exec(ctx,
		`CREATE OR REPLACE FUNCTION `+raiser+`(p_n BIGINT) RETURNS JSONB
		 LANGUAGE plpgsql AS $$
		 BEGIN
		   RAISE EXCEPTION 'c3 forced destroy failure' USING ERRCODE='BZ099';
		 END $$`,
	); err != nil {
		t.Fatalf("create raiser fn: %v", err)
	}
	t.Cleanup(func() { pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS `+raiser+`(BIGINT)`) })

	c := PoolCaller{Pool: pool}
	_, err := c.CallScopedBatch(ctx, 7,
		ScopedCall{Fn: writer}, // "create" leg — succeeds, writes a row
		ScopedCall{Fn: raiser}, // "destroy" leg — raises
	)
	if err == nil {
		t.Fatal("CallScopedBatch returned nil error, want the raiser's BZ099 failure")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "BZ099" {
		t.Fatalf("error = %v, want a *pgconn.PgError with code BZ099 (BZ→protocol map preserved)", err)
	}

	var rows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+tbl).Scan(&rows); err != nil {
		t.Fatalf("marker count: %v", err)
	}
	if rows != 0 {
		t.Fatalf("marker table has %d rows after a failed batch, want 0 — the create leg must roll back with the destroy failure (RFC 8620 §3.6.2 all-or-nothing)", rows)
	}
}

// TestCallScopedBatch_ItemLevelFailureDoesNotAbortBatch pins the OTHER half of
// today's correct behavior: reducers catch per-ITEM failures internally
// (EXCEPTION WHEN OTHERS per item → notCreated/notUpdated JSON, an implicit
// PL/pgSQL savepoint), and that must keep working inside the batch's single
// explicit transaction — one bad item is reported item-level and does NOT
// poison the tx or later phases.
func TestCallScopedBatch_ItemLevelFailureDoesNotAbortBatch(t *testing.T) {
	pool := testPoolDB(t)
	ctx := context.Background()

	const tbl = "rls_proof_batch_items"
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS `+tbl+` (n BIGINT)`); err != nil {
		t.Fatalf("create marker table: %v", err)
	}
	t.Cleanup(func() { pool.Exec(context.Background(), `DROP TABLE IF EXISTS `+tbl) })
	pool.Exec(ctx, `TRUNCATE `+tbl)

	// Mirrors the real set reducers' per-item shape: item 1 inserts, item 2
	// fails and is caught internally (implicit savepoint), reported in JSON.
	const perItem = "rls_proof_batch_per_item"
	if _, err := pool.Exec(ctx,
		`CREATE OR REPLACE FUNCTION `+perItem+`(p_n BIGINT) RETURNS JSONB
		 LANGUAGE plpgsql AS $$
		 DECLARE v_not JSONB := '{}'::JSONB;
		 BEGIN
		   INSERT INTO `+tbl+`(n) VALUES (p_n); -- good item
		   BEGIN
		     RAISE EXCEPTION 'bad item';        -- bad item, caught below
		   EXCEPTION WHEN OTHERS THEN
		     v_not := v_not || jsonb_build_object('k2', jsonb_build_object('type', 'invalidProperties'));
		   END;
		   RETURN jsonb_build_object('created', jsonb_build_object('k1', p_n), 'notCreated', v_not);
		 END $$`,
	); err != nil {
		t.Fatalf("create per-item fn: %v", err)
	}
	t.Cleanup(func() { pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS `+perItem+`(BIGINT)`) })

	const writer = "rls_proof_batch_writer2"
	if _, err := pool.Exec(ctx,
		`CREATE OR REPLACE FUNCTION `+writer+`(p_n BIGINT) RETURNS JSONB
		 LANGUAGE plpgsql AS $$
		 BEGIN
		   INSERT INTO `+tbl+`(n) VALUES (p_n + 1);
		   RETURN '{"destroyed":true}'::JSONB;
		 END $$`,
	); err != nil {
		t.Fatalf("create writer fn: %v", err)
	}
	t.Cleanup(func() { pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS `+writer+`(BIGINT)`) })

	c := PoolCaller{Pool: pool}
	results, err := c.CallScopedBatch(ctx, 7,
		ScopedCall{Fn: perItem}, // create leg: 1 good + 1 bad item
		ScopedCall{Fn: writer},  // destroy leg: must still run and commit
	)
	if err != nil {
		t.Fatalf("CallScopedBatch: %v — one bad ITEM must not fail the batch", err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	var created struct {
		NotCreated map[string]json.RawMessage `json:"notCreated"`
	}
	if err := json.Unmarshal(results[0], &created); err != nil {
		t.Fatalf("unmarshal create result %q: %v", results[0], err)
	}
	if _, ok := created.NotCreated["k2"]; !ok {
		t.Fatalf("create result %s lacks notCreated[k2] — item-level failure must stay item-level", results[0])
	}
	var rows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+tbl).Scan(&rows); err != nil {
		t.Fatalf("marker count: %v", err)
	}
	if rows != 2 {
		t.Fatalf("marker table has %d rows, want 2 — the good item AND the later phase must both commit", rows)
	}
}

// TestCallScopedBatch_GUCDoesNotLeakAcrossTransactions proves PgBouncer
// transaction-mode safety for the batch: the whole batch is ONE BEGIN…COMMIT
// with an is_local=TRUE set_config, so the GUC dies with the transaction and
// never leaks to the next pooled request.
func TestCallScopedBatch_GUCDoesNotLeakAcrossTransactions(t *testing.T) {
	pool := testPoolDB(t)
	ctx := context.Background()

	const probe = "rls_proof_batch_leak_probe"
	if _, err := pool.Exec(ctx,
		`CREATE OR REPLACE FUNCTION `+probe+`(p_mailbox_id BIGINT) RETURNS JSONB
		 LANGUAGE sql AS $$ SELECT to_jsonb(current_setting('app.current_mailbox_id', true)) $$`,
	); err != nil {
		t.Fatalf("create probe fn: %v", err)
	}
	t.Cleanup(func() { pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS `+probe+`(BIGINT)`) })

	c := PoolCaller{Pool: pool}
	if _, err := c.CallScopedBatch(ctx, 999,
		ScopedCall{Fn: probe}, ScopedCall{Fn: probe},
	); err != nil {
		t.Fatalf("CallScopedBatch: %v", err)
	}

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

// TestCallScoped_BehaviourPreserved proves the wrapped path returns the SAME
// JSON the unwrapped Call returns for the same reducer call.
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

	c := PoolCaller{Pool: pool}

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
