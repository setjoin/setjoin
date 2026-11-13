package imap

// WP4 coverage follow-up: the batched MOVE/COPY statement sequences' ERROR
// arms. The happy paths (and the duplicate-COPY [CANNOT] arm) are pinned by
// imap_batch_test.go; what the CI changed-lines ratchet still saw uncovered
// were the error-propagation arms — the `return err` legs of the batch helper
// calls inside handleMove/handleCopy, the batch helpers' own Query/Scan/Err
// failure returns, copyConflictOrErr's non-conflict passthrough and
// destinationUIDs' misaligned-pairing guard.
//
// TWO fault-injection tiers, both production-code-free:
//
//  1. Helper-level unit faults (no DB needed, never skip): the helpers take
//     `tx pgx.Tx` — an interface — so a faultTx/faultRows pair drives each
//     failure return deterministically (Query error, Scan error, Err error,
//     Exec error) without touching the pool.
//
//  2. Handler-level DB faults through the real withScope path: handleMove/
//     handleCopy run against Server.pool (a concrete *pgxpool.Pool), so there
//     is no Go seam — the failure is injected at the DATABASE boundary, the
//     same place a real failure would come from, via session-scoped triggers
//     (a raising BEFORE DELETE on message_tags, a row-skipping BEFORE INSERT,
//     a raising BEFORE INSERT on jmap_changes_journal) and — for the one arm
//     no statement failure can reach (destinationUIDs' map-miss inside the
//     location branch, whose output rows are verbatim input echoes) — a
//     temporary replacement of imap_batch_move_location that omits one output
//     row. Every injected object is dropped in t.Cleanup; the replaced reducer
//     is restored from its pg_get_functiondef captured BEFORE the swap.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ─── Tier 1: helper-level fault fakes ────────────────────────────────────────

// errBatchFault is the injected failure every fake returns verbatim; each
// subtest asserts the helper propagated THIS error (not a wrapped variant),
// which is exactly what the production `return err` arms do.
var errBatchFault = errors.New("wp4 fault: injected batch failure")

// faultTx is a minimal pgx.Tx whose Exec/Query fail with the configured
// errors. The embedded nil pgx.Tx panics on any other method — the batch
// helpers only ever call Exec and Query.
type faultTx struct {
	pgx.Tx
	execErr  error
	queryErr error
	rows     pgx.Rows
}

func (t *faultTx) Exec(_ context.Context, _ string, _ ...any) (pgconn.CommandTag, error) {
	if t.execErr != nil {
		return pgconn.CommandTag{}, t.execErr
	}
	return pgconn.CommandTag{}, nil
}

func (t *faultTx) Query(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
	if t.queryErr != nil {
		return nil, t.queryErr
	}
	return t.rows, nil
}

// faultRows yields `yield` rows. Scan fails on the first row when scanErr is
// set; Err returns finalErr after the rows are drained. The embedded nil
// pgx.Rows panics on any method the helpers don't call.
type faultRows struct {
	pgx.Rows
	yield    int
	scanErr  error
	finalErr error
	i        int
}

func (r *faultRows) Next() bool {
	if r.i >= r.yield {
		return false
	}
	r.i++
	return true
}

func (r *faultRows) Scan(dest ...any) error {
	if r.scanErr != nil {
		return r.scanErr
	}
	if len(dest) == 3 {
		if p, ok := dest[0].(*int64); ok {
			*p = 1
		}
		if p, ok := dest[1].(*time.Time); ok {
			*p = time.Unix(0, 0).UTC()
		}
		if p, ok := dest[2].(*int64); ok {
			*p = 1
		}
	}
	return nil
}

func (r *faultRows) Err() error { return r.finalErr }
func (r *faultRows) Close()     {}

func faultBatchInput() imapBatchInput {
	recv := time.Unix(1700000000, 0).UTC()
	return imapBatchInput{
		ids:        []int64{42, 43},
		recvs:      []time.Time{recv, recv.Add(time.Second)},
		sourceUIDs: []int64{7, 8},
	}
}

// TestIMAPBatchFaults_CopyConflictOrErrPassthrough covers copyConflictOrErr's
// discrimination: only 23505 on the message_tags PK maps to
// errCopyAlreadyPresent (the duplicate-COPY signal); every other error —
// non-pg, non-23505, the allocator-ledger PK, or an unnamed 23505 — passes
// through untouched so the caller's generic NO/server-error reply fires.
func TestIMAPBatchFaults_CopyConflictOrErrPassthrough(t *testing.T) {
	plain := errors.New("connection reset")
	if got := copyConflictOrErr(plain); got != plain {
		t.Fatalf("non-pg error must pass through untouched, got %v", got)
	}
	otherConstraint := &pgconn.PgError{Code: "23503"} // foreign_key_violation, not the COPY arbiter
	if got := copyConflictOrErr(otherConstraint); got != error(otherConstraint) {
		t.Fatalf("non-23505 pg error must pass through untouched, got %v", got)
	}
	dup := &pgconn.PgError{Code: pgErrUniqueViolation, ConstraintName: "message_tags_pkey"}
	if got := copyConflictOrErr(dup); !errors.Is(got, errCopyAlreadyPresent) {
		t.Fatalf("23505 on the message_tags PK must map to errCopyAlreadyPresent, got %v", got)
	}
	// 23505 from the OTHER constraint reachable in the same statement — the
	// imap_membership_uid_ledger PK inside the allocator trigger — is an
	// allocator race, not a client duplicate: it passes through as the raw
	// error so the client sees a serverFail instead of a false [CANNOT].
	ledger := &pgconn.PgError{Code: pgErrUniqueViolation, ConstraintName: "imap_membership_uid_ledger_pkey"}
	if got := copyConflictOrErr(ledger); got != error(ledger) {
		t.Fatalf("23505 on the allocator ledger PK must pass through, got %v", got)
	}
	// An unnamed 23505 (defensive: constraint name absent) also passes
	// through rather than guessing "already present".
	unnamed := &pgconn.PgError{Code: pgErrUniqueViolation}
	if got := copyConflictOrErr(unnamed); got != error(unnamed) {
		t.Fatalf("unnamed 23505 must pass through, got %v", got)
	}
}

// TestIMAPBatchFaults_DestinationUIDsMissingMembership covers the
// misaligned-pairing guard directly: in membership mode a missing
// (message_id, received_at) key fails the command (a misaligned COPYUID must
// never be emitted), legacy mode keeps the source-UID rule and never errors.
func TestIMAPBatchFaults_DestinationUIDsMissingMembership(t *testing.T) {
	in := faultBatchInput()
	if _, err := in.destinationUIDs(true, map[imapMembershipKey]int64{}); err == nil {
		t.Fatal("membership mode with a missing pairing must fail")
	} else if !strings.Contains(err.Error(), "misalign") {
		t.Fatalf("guard error should name the COPYUID misalignment, got %v", err)
	}
	out, err := in.destinationUIDs(false, nil)
	if err != nil {
		t.Fatalf("legacy mode never consults the pairing map: %v", err)
	}
	if len(out) != 2 || out[0] != 7 || out[1] != 8 {
		t.Fatalf("legacy mode destination UIDs are the source UIDs, got %v", out)
	}
	if _, err := in.destinationUIDs(true, map[imapMembershipKey]int64{
		{messageID: 42, recvAt: in.recvs[0].UnixNano()}: 91,
		{messageID: 43, recvAt: in.recvs[1].UnixNano()}: 92,
	}); err != nil {
		t.Fatalf("complete pairing must succeed: %v", err)
	}
}

// TestIMAPBatchFaults_HelperFailureReturns drives each batch helper's failure
// return through the fault tx/rows: Query-time error, row Scan error, rows.Err
// after draining, and the per-message notify loop's Exec error.
func TestIMAPBatchFaults_HelperFailureReturns(t *testing.T) {
	ctx := context.Background()
	in := faultBatchInput()

	t.Run("AddDestMembershipsQueryFails", func(t *testing.T) {
		_, err := addDestMemberships(ctx, &faultTx{queryErr: errBatchFault}, in, 1, 2)
		if !errors.Is(err, errBatchFault) {
			t.Fatalf("Query error must propagate verbatim, got %v", err)
		}
	})
	t.Run("AddDestMembershipsScanFails", func(t *testing.T) {
		rows := &faultRows{yield: 1, scanErr: errBatchFault}
		_, err := addDestMemberships(ctx, &faultTx{rows: rows}, in, 1, 2)
		if !errors.Is(err, errBatchFault) {
			t.Fatalf("row Scan error must propagate verbatim, got %v", err)
		}
	})
	t.Run("MoveLocationBatchQueryFails", func(t *testing.T) {
		_, err := moveLocationBatch(ctx, &faultTx{queryErr: errBatchFault}, in, "FaultLocDest", 1)
		if !errors.Is(err, errBatchFault) {
			t.Fatalf("Query error must propagate verbatim, got %v", err)
		}
	})
	t.Run("MoveLocationBatchScanFails", func(t *testing.T) {
		rows := &faultRows{yield: 1, scanErr: errBatchFault}
		_, err := moveLocationBatch(ctx, &faultTx{rows: rows}, in, "FaultLocDest", 1)
		if !errors.Is(err, errBatchFault) {
			t.Fatalf("row Scan error must propagate verbatim, got %v", err)
		}
	})
	t.Run("MoveLocationBatchRowsErr", func(t *testing.T) {
		rows := &faultRows{yield: 1, finalErr: errBatchFault}
		_, err := moveLocationBatch(ctx, &faultTx{rows: rows}, in, "FaultLocDest", 1)
		if !errors.Is(err, errBatchFault) {
			t.Fatalf("rows.Err after draining must propagate verbatim, got %v", err)
		}
	})
	t.Run("NotifyUpdatedBatchExecFails", func(t *testing.T) {
		err := notifyUpdatedBatch(ctx, &faultTx{execErr: errBatchFault}, in, 1, nil)
		if !errors.Is(err, errBatchFault) {
			t.Fatalf("notify loop Exec error must propagate verbatim, got %v", err)
		}
	})
}

// ─── Tier 2: handler-level DB faults through withScope ──────────────────────

// wp4FaultRaiseInstalls creates (and registers cleanup to drop) a raising
// trigger function + trigger; any row event on the guarded statement aborts it.
func wp4FaultRaiseInstalls(t *testing.T, env *imapIsoEnv, table, trigger string) {
	t.Helper()
	ctx := context.Background()
	fn := "wp4_fault_raise_" + trigger
	if _, err := env.superPool.Exec(ctx,
		`CREATE OR REPLACE FUNCTION `+fn+`() RETURNS trigger AS $f$
		 BEGIN
		     RAISE EXCEPTION 'wp4 coverage fault injection on %', TG_TABLE_NAME;
		 END;
		 $f$ LANGUAGE plpgsql`); err != nil {
		t.Fatalf("create fault function %s: %v", fn, err)
	}
	if _, err := env.superPool.Exec(ctx,
		`CREATE TRIGGER `+trigger+` BEFORE INSERT OR DELETE ON `+table+`
		 FOR EACH ROW EXECUTE FUNCTION `+fn+`()`); err != nil {
		t.Fatalf("create fault trigger %s on %s: %v", trigger, table, err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = env.superPool.Exec(bg, `DROP TRIGGER IF EXISTS `+trigger+` ON `+table)
		_, _ = env.superPool.Exec(bg, `DROP FUNCTION IF EXISTS `+fn+`()`)
	})
}

// wp4SkipInsertInstalls creates (and registers cleanup to drop) a BEFORE INSERT
// trigger on message_tags whose function RETURNs NULL — the row is silently
// skipped, so the set-based dest INSERT succeeds while its RETURNING omits the
// input ordinal. Name sorts ahead of message_tags_exclusive /
// message_tags_imap_uid_allocate so the skip wins the alphabetical
// same-event trigger order and the row never reaches the other triggers.
func wp4SkipInsertInstalls(t *testing.T, env *imapIsoEnv) {
	t.Helper()
	ctx := context.Background()
	if _, err := env.superPool.Exec(ctx,
		`CREATE OR REPLACE FUNCTION wp4_fault_skip_dest_insert() RETURNS trigger AS $f$
		 BEGIN
		     RETURN NULL;
		 END;
		 $f$ LANGUAGE plpgsql`); err != nil {
		t.Fatalf("create skip function: %v", err)
	}
	if _, err := env.superPool.Exec(ctx,
		`CREATE TRIGGER aaa_wp4_skip_dest_insert BEFORE INSERT ON message_tags
		 FOR EACH ROW EXECUTE FUNCTION wp4_fault_skip_dest_insert()`); err != nil {
		t.Fatalf("create skip trigger: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = env.superPool.Exec(bg, `DROP TRIGGER IF EXISTS aaa_wp4_skip_dest_insert ON message_tags`)
		_, _ = env.superPool.Exec(bg, `DROP FUNCTION IF EXISTS wp4_fault_skip_dest_insert()`)
	})
}

// TestIMAPBatchFaults_MoveSourceDeleteFails drives handleMove with the batched
// source-membership DELETE aborted by a raising trigger: the helper's error
// must propagate out of withScope, the command must reply NO (never a COPYUID),
// and the tx rollback must leave the source folder untouched.
func TestIMAPBatchFaults_MoveSourceDeleteFails(t *testing.T) {
	env := setupIMAPIso(t)
	ctx := context.Background()

	dest := mkUserTag(t, env, env.mbA, "FaultDelDest")
	recv := time.Now().UTC().Truncate(time.Second)
	mkBatchMsg(t, env, env.mbA, env.tagA, 410, "imapA-fault-del-a", recv, nil)
	mkBatchMsg(t, env, env.mbA, env.tagA, 820, "imapA-fault-del-b", recv, nil)

	wp4FaultRaiseInstalls(t, env, "message_tags", "aaa_wp4_fault_src_delete")

	before := primaryTagCount(t, env, env.mbA, env.tagA)
	c, bc := env.connFor(env.mbA, env.tagA)
	c.useMembershipUID = true
	c.handleMove(ctx, "m1", "1:* FaultDelDest", true)
	out := bc.String()
	if !strings.Contains(out, "NO MOVE failed") {
		t.Fatalf("aborted source DELETE must reply NO; got:\n%s", out)
	}
	if strings.Contains(out, "COPYUID") {
		t.Fatalf("failed MOVE must NOT emit COPYUID; got:\n%s", out)
	}
	if got := primaryTagCount(t, env, env.mbA, env.tagA); got != before {
		t.Fatalf("rollback must leave the source intact (want %d, got %d)", before, got)
	}
	if got := primaryTagCount(t, env, env.mbA, dest); got != 0 {
		t.Fatalf("no dest primaries may survive a rolled-back MOVE (got %d)", got)
	}
}

// TestIMAPBatchFaults_MoveDestInsertSkipped drives handleMove with the set-based
// dest INSERT's rows silently skipped (BEFORE INSERT trigger RETURNs NULL): the
// statement SUCCEEDS but its RETURNING omits the input ordinals, so the
// (message_id, received_at) pairing map misses them and the membership-mode
// destinationUIDs guard fails the command — the non-location branch's
// misaligned-pairing NO, with the rollback leaving both folders untouched.
func TestIMAPBatchFaults_MoveDestInsertSkipped(t *testing.T) {
	env := setupIMAPIso(t)
	ctx := context.Background()

	dest := mkUserTag(t, env, env.mbA, "FaultSkipDest")
	recv := time.Now().UTC().Truncate(time.Second)
	mkBatchMsg(t, env, env.mbA, env.tagA, 410, "imapA-fault-skip-a", recv, nil)
	mkBatchMsg(t, env, env.mbA, env.tagA, 820, "imapA-fault-skip-b", recv, nil)

	wp4SkipInsertInstalls(t, env)

	before := primaryTagCount(t, env, env.mbA, env.tagA)
	c, bc := env.connFor(env.mbA, env.tagA)
	c.useMembershipUID = true
	c.handleMove(ctx, "m1", "1:* FaultSkipDest", true)
	out := bc.String()
	if !strings.Contains(out, "NO MOVE failed") {
		t.Fatalf("misaligned dest pairing must reply NO; got:\n%s", out)
	}
	if strings.Contains(out, "COPYUID") {
		t.Fatalf("failed MOVE must NOT emit COPYUID; got:\n%s", out)
	}
	if got := primaryTagCount(t, env, env.mbA, env.tagA); got != before {
		t.Fatalf("rollback must leave the source intact (want %d, got %d)", before, got)
	}
	if got := primaryTagCount(t, env, env.mbA, dest); got != 0 {
		t.Fatalf("no dest primaries may survive a rolled-back MOVE (got %d)", got)
	}
}

// TestIMAPBatchFaults_CopyDestInsertSkipped is the COPY twin of the MOVE skip
// fault: the same RETURNing-omits-the-ordinal failure surfaces as the COPY
// branch's dupErr propagation (NOT errCopyAlreadyPresent — the statement never
// conflicted), so the reply is the plain NO COPY failed.
func TestIMAPBatchFaults_CopyDestInsertSkipped(t *testing.T) {
	env := setupIMAPIso(t)
	ctx := context.Background()

	dest := mkUserTag(t, env, env.mbA, "FaultCopySkipDest")
	recv := time.Now().UTC().Truncate(time.Second)
	mkBatchMsg(t, env, env.mbA, env.tagA, 430, "imapA-fault-cskip-a", recv, nil)
	mkBatchMsg(t, env, env.mbA, env.tagA, 840, "imapA-fault-cskip-b", recv, nil)

	wp4SkipInsertInstalls(t, env)

	before := primaryTagCount(t, env, env.mbA, env.tagA)
	c, bc := env.connFor(env.mbA, env.tagA)
	c.useMembershipUID = true
	c.handleCopy(ctx, "c1", "1:* FaultCopySkipDest", true)
	out := bc.String()
	if !strings.Contains(out, "NO COPY failed") {
		t.Fatalf("misaligned dest pairing must reply plain NO (no [CANNOT] — no PK conflict happened); got:\n%s", out)
	}
	if strings.Contains(out, "[CANNOT]") || strings.Contains(out, "COPYUID") {
		t.Fatalf("misaligned COPY must NOT emit COPYUID or [CANNOT]; got:\n%s", out)
	}
	if got := primaryTagCount(t, env, env.mbA, env.tagA); got != before {
		t.Fatalf("rollback must leave the source intact (want %d, got %d)", before, got)
	}
	if got := primaryTagCount(t, env, env.mbA, dest); got != 0 {
		t.Fatalf("no dest primaries may survive a rolled-back COPY (got %d)", got)
	}
}

// TestIMAPBatchFaults_NotifyJournalFails aborts the per-message notify loop at
// its first journal row (a raising BEFORE INSERT on jmap_changes_journal): both
// the non-location MOVE and the COPY reach notifyUpdatedBatch AFTER their
// mutations succeeded, so this is the arm where a notify failure must still
// roll the whole command back — the reply is NO and neither folder nor state
// moves.
func TestIMAPBatchFaults_NotifyJournalFails(t *testing.T) {
	env := setupIMAPIso(t)
	ctx := context.Background()

	dest := mkUserTag(t, env, env.mbA, "FaultNotifyDest")
	recv := time.Now().UTC().Truncate(time.Second)
	mkBatchMsg(t, env, env.mbA, env.tagA, 450, "imapA-fault-notify-a", recv, nil)
	mkBatchMsg(t, env, env.mbA, env.tagA, 860, "imapA-fault-notify-b", recv, nil)

	wp4FaultRaiseInstalls(t, env, "jmap_changes_journal", "aaa_wp4_fault_journal")

	c, bc := env.connFor(env.mbA, env.tagA)
	c.useMembershipUID = true
	stateBefore := emailState(t, env, env.mbA)
	before := primaryTagCount(t, env, env.mbA, env.tagA)

	c.handleMove(ctx, "m1", "1:* FaultNotifyDest", true)
	if out := bc.String(); !strings.Contains(out, "NO MOVE failed") {
		t.Fatalf("failed notify must reply NO MOVE; got:\n%s", out)
	}

	c2, bc2 := env.connFor(env.mbA, env.tagA)
	c2.useMembershipUID = true
	c2.handleCopy(ctx, "c1", "1:* FaultNotifyDest", true)
	if out := bc2.String(); !strings.Contains(out, "NO COPY failed") {
		t.Fatalf("failed notify must reply NO COPY; got:\n%s", out)
	}

	if stateAfter := emailState(t, env, env.mbA); stateAfter != stateBefore {
		t.Fatalf("rolled-back commands must not bump email state (before %d after %d)", stateBefore, stateAfter)
	}
	if got := primaryTagCount(t, env, env.mbA, env.tagA); got != before {
		t.Fatalf("rollback must leave the source intact (want %d, got %d)", before, got)
	}
	if got := primaryTagCount(t, env, env.mbA, dest); got != 0 {
		t.Fatalf("no dest primaries may survive the rolled-back commands (got %d)", got)
	}
}

// TestIMAPBatchFaults_MoveLocationPairingMissing covers the one arm no
// statement failure can reach: the location branch's destinationUIDs guard.
// imap_batch_move_location emits one output row per input ordinal whose
// (out_message_id, out_received_at) pair ECHOES the input, so the pairing map
// can only miss an ordinal if the function itself omits a row. The test
// replaces the reducer — captured via pg_get_functiondef and restored in
// t.Cleanup — with a stub that performs every transition but drops the LAST
// ordinal's output row; the gateway must fail the command (misaligned pairing
// → NO) and roll back the transitions the stub did perform.
func TestIMAPBatchFaults_MoveLocationPairingMissing(t *testing.T) {
	env := setupIMAPIso(t)
	ctx := context.Background()

	mkLocationTag(t, env, env.mbA, "FaultLocDest")
	recv := time.Now().UTC().Truncate(time.Second)
	mkBatchMsg(t, env, env.mbA, env.tagA, 470, "imapA-fault-loc-a", recv, nil)
	mkBatchMsg(t, env, env.mbA, env.tagA, 880, "imapA-fault-loc-b", recv, nil)

	var origDef string
	if err := env.superPool.QueryRow(ctx,
		`SELECT pg_get_functiondef(oid) FROM pg_proc
		  WHERE proname = 'imap_batch_move_location' AND pronamespace = 'public'::regnamespace`,
	).Scan(&origDef); err != nil {
		t.Fatalf("capture imap_batch_move_location: %v", err)
	}
	t.Cleanup(func() {
		if _, err := env.superPool.Exec(context.Background(), origDef); err != nil {
			t.Errorf("restore imap_batch_move_location: %v", err)
		}
	})
	if _, err := env.superPool.Exec(ctx,
		`CREATE OR REPLACE FUNCTION imap_batch_move_location(
		    p_message_ids           BIGINT[],
		    p_received_ats          TIMESTAMPTZ[],
		    p_new_location_tag_name TEXT,
		    p_mailbox_id            BIGINT,
		    p_added_by              TEXT    DEFAULT 'imap'
		) RETURNS TABLE (out_message_id BIGINT, out_received_at TIMESTAMPTZ, out_imap_uid BIGINT) AS $f$
		DECLARE
		    v_dest_tag_id BIGINT;
		    v_i           INT;
		    v_count       INT;
		BEGIN
		    v_count := COALESCE(cardinality(p_message_ids), 0);
		    SELECT id INTO v_dest_tag_id FROM tags
		     WHERE mailbox_id = p_mailbox_id AND name = p_new_location_tag_name;
		    IF v_dest_tag_id IS NULL THEN
		        RAISE EXCEPTION 'wp4 fault stub: tag % not found', p_new_location_tag_name;
		    END IF;
		    FOR v_i IN 1..v_count LOOP
		        PERFORM transition_message_location(
		            p_message_ids[v_i], p_received_ats[v_i],
		            p_new_location_tag_name, p_mailbox_id, p_added_by);
		        -- THE FAULT: drop the LAST input ordinal's output row so the
		        -- gateway's pairing map misses it (test-only stub; restored from
		        -- pg_get_functiondef in t.Cleanup).
		        IF v_i = v_count THEN
		            CONTINUE;
		        END IF;
		        out_message_id  := p_message_ids[v_i];
		        out_received_at := p_received_ats[v_i];
		        SELECT mt.imap_uid INTO out_imap_uid
		        FROM message_tags mt
		        WHERE mt.message_id = p_message_ids[v_i]
		          AND mt.received_at = p_received_ats[v_i]
		          AND mt.tag_id = v_dest_tag_id;
		        RETURN NEXT;
		    END LOOP;
		END;
		$f$ LANGUAGE plpgsql`); err != nil {
		t.Fatalf("install pairing-miss stub: %v", err)
	}

	before := primaryTagCount(t, env, env.mbA, env.tagA)
	c, bc := env.connFor(env.mbA, env.tagA)
	c.useMembershipUID = true
	c.handleMove(ctx, "m1", "1:* FaultLocDest", true)
	out := bc.String()
	if !strings.Contains(out, "NO MOVE failed") {
		t.Fatalf("misaligned location pairing must reply NO; got:\n%s", out)
	}
	if strings.Contains(out, "COPYUID") {
		t.Fatalf("failed MOVE must NOT emit COPYUID; got:\n%s", out)
	}
	if got := primaryTagCount(t, env, env.mbA, env.tagA); got != before {
		t.Fatalf("rollback must leave the source intact (want %d, got %d)", before, got)
	}
}
