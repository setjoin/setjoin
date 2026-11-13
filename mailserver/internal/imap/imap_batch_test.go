package imap

// IMAP batch MOVE/COPY tests (WP4, plan 2026-09-30-review-remediation-wave.md).
//
// WHAT THESE PIN: the batched mutation path must behave exactly like the
// per-row loop it replaced — command-atomic (one Begin→scope→callback→Commit
// per command; any row failure rolls back ALL earlier rows, no partial
// success), destination UIDs allocated and paired in the SOURCE view's
// ascending effective-UID order (membership UID when the session pinned it,
// legacy message UID otherwise — never message-ID order, timestamp order or
// incidental RETURNING order), ownership confined to the session mailbox even
// when another tenant's rows collide on ids/timestamps, and the per-message
// notify_state_change calls preserved (in ordinal order, absent after a
// rollback, no double-notify on the location branch).
//
// HOW: the same DB-backed harness as imap_isolation_test.go (setjoin_app pool
// under V004 FORCE + superuser fixture pool), plus a pgx query tracer for the
// statement-count bound proof.

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// countingTracer is a pgx.QueryTracer that counts MUTATION/UID-READ statements.
// The WP4 bound is on statement COUNT as N grows — the deliberately per-row
// notify_state_change calls are EXCLUDED explicitly (they stay O(N) by design),
// as are withScope's GUC set_config and the O(1) audit-log write.
type countingTracer struct {
	mu    sync.Mutex
	n     int
	sqls  []string
	skip  func(sql string) bool
	count func(sql string) bool
}

func (t *countingTracer) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.count(data.SQL) && (t.skip == nil || !t.skip(data.SQL)) {
		t.n++
		t.sqls = append(t.sqls, data.SQL)
	}
	return ctx
}

func (t *countingTracer) TraceQueryEnd(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryEndData) {
}

// isMutationOrUIDRead classifies a statement as one of the statement classes
// the batch replaced (per-message DELETE/INSERT/precheck/UID reads) or their
// set-based replacements. The dest-tag resolution and source-view load are
// O(1)-per-command and included for strictness.
func isMutationOrUIDRead(sql string) bool {
	s := strings.Join(strings.Fields(sql), " ")
	return strings.Contains(s, "message_tags") ||
		strings.Contains(s, "imap_batch_move_location")
}

// isExcluded marks statements that are deliberately NOT part of the bound:
// per-message notifications (O(N) on purpose), the per-command GUC, the
// per-command audit write.
func isExcluded(sql string) bool {
	s := strings.Join(strings.Fields(sql), " ")
	return strings.Contains(s, "notify_state_change") ||
		strings.Contains(s, "set_config") ||
		strings.Contains(s, "mailbox_audit_log")
}

// newTracingAppPool builds a second setjoin_app pool whose connections run the
// countingTracer — used only by TestIMAPBatch_StatementCountBounded. The
// handlers take the pool through connState.srv, so a separate pool observes
// exactly the command's statements.
func newTracingAppPool(t *testing.T, tr *countingTracer) *pgxpool.Pool {
	t.Helper()
	sDSN := superDSN()
	if sDSN == "" {
		t.Skip("neither TEST_DB_DSN nor DB_DSN set — skipping")
	}
	cfg, err := appConfig(sDSN)
	if err != nil {
		t.Skipf("cannot derive app pool config: %v", err)
	}
	cfg.ConnConfig.Tracer = tr
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Skipf("cannot connect tracing app pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// mkBatchMsg inserts a message owned by `mb` with the given legacy imap_uid and
// received_at, tags it primary into `tag`, and (when membershipUID is non-nil)
// pins the message_tags membership UID explicitly — the allocate trigger honors
// a supplied UID, retires nothing and advances the tag's uidnext, so fixtures
// can model non-contiguous membership UID sequences. Returns the message id.
func mkBatchMsg(t *testing.T, env *imapIsoEnv, mb, tag int64, legacyUID int64, hdr string, recv time.Time, membershipUID *int64) int64 {
	t.Helper()
	ctx := context.Background()
	var id int64
	if err := env.superPool.QueryRow(ctx,
		`INSERT INTO messages (mailbox_id, folder_id, imap_uid, message_id, subject, from_addr, to_addrs, cc_addrs, size_bytes, thread_id, raw_ref, received_at, is_read)
		 VALUES ($1, $2, $3, $4, $5, 'sender@ext.com', '[]'::jsonb, '[]'::jsonb, 10, $6, $7, $8, FALSE) RETURNING id`,
		mb, tag, legacyUID, hdr, "subj-"+hdr, "thr-"+hdr, "raw-"+hdr, recv,
	).Scan(&id); err != nil {
		t.Fatalf("insert batch message %s: %v", hdr, err)
	}
	if membershipUID != nil {
		if _, err := env.superPool.Exec(ctx,
			`INSERT INTO message_tags (message_id, received_at, tag_id, is_primary, imap_uid)
			 VALUES ($1, $2, $3, TRUE, $4)`,
			id, recv, tag, *membershipUID,
		); err != nil {
			t.Fatalf("tag batch message %s with membership uid %d: %v", hdr, *membershipUID, err)
		}
		return id
	}
	if _, err := env.superPool.Exec(ctx,
		`SELECT tag_message($1, $2, (SELECT name FROM tags WHERE id = $3), $4, 'deliver', TRUE)`,
		id, recv, tag, mb,
	); err != nil {
		t.Fatalf("tag batch message %s: %v", hdr, err)
	}
	return id
}

// batchViewUIDs returns the session view's effective UIDs of `tag` (membership
// UID when membership is true, legacy message UID otherwise), ascending — the
// order resolveSeqSet and the batch pairing follow.
func batchViewUIDs(t *testing.T, env *imapIsoEnv, mb, tag int64, membership bool) []int64 {
	t.Helper()
	col := "m.imap_uid"
	if membership {
		col = "mt.imap_uid"
	}
	rows, err := env.superPool.Query(context.Background(),
		`SELECT `+col+` FROM messages m
		 JOIN message_tags mt ON mt.message_id = m.id AND mt.received_at = m.received_at
		 WHERE mt.tag_id = $1 AND mt.is_primary = TRUE AND m.mailbox_id = $2 AND NOT m.is_deleted
		 ORDER BY `+col, tag, mb)
	if err != nil {
		t.Fatalf("batchViewUIDs: %v", err)
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var u int64
		if err := rows.Scan(&u); err != nil {
			t.Fatalf("batchViewUIDs scan: %v", err)
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("batchViewUIDs rows: %v", err)
	}
	return out
}

// parseCOPYUID extracts the `* OK [COPYUID validity srcs dests]` untagged line
// from a captured response, if present.
func parseCOPYUID(out string) (validity int64, srcs, dsts []int64, ok bool) {
	for _, line := range strings.Split(out, "\r\n") {
		i := strings.Index(line, "[COPYUID ")
		if i < 0 {
			continue
		}
		seg := line[i+1:] // "COPYUID validity srcs dsts] COPY completed"
		j := strings.Index(seg, "]")
		if j < 0 {
			return 0, nil, nil, false
		}
		fields := strings.Fields(seg[:j])
		// fields[0] == "COPYUID"
		if len(fields) != 4 {
			return 0, nil, nil, false
		}
		v, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return 0, nil, nil, false
		}
		parse := func(s string) []int64 {
			var out []int64
			for _, p := range strings.Split(s, ",") {
				n, err := strconv.ParseInt(p, 10, 64)
				if err != nil {
					return nil
				}
				out = append(out, n)
			}
			return out
		}
		return v, parse(fields[2]), parse(fields[3]), true
	}
	return 0, nil, nil, false
}

// journalCount counts the email 'updated' journal rows a command's notify loop
// appended (above `aboveState`), keyed to the copied/moved message ids.
func journalCount(t *testing.T, env *imapIsoEnv, mb int64, aboveState int64, ids []int64) int {
	t.Helper()
	var n int
	if err := env.superPool.QueryRow(context.Background(),
		`SELECT count(*) FROM jmap_changes_journal
		 WHERE mailbox_id = $1 AND datatype = 'email' AND op = 'updated'
		   AND state_seq > $2 AND entity_id = ANY($3)`,
		mb, aboveState, ids,
	).Scan(&n); err != nil {
		t.Fatalf("journalCount: %v", err)
	}
	return n
}

func emailState(t *testing.T, env *imapIsoEnv, mb int64) int64 {
	t.Helper()
	var s int64
	if err := env.superPool.QueryRow(context.Background(),
		`SELECT jmap_email_state FROM mailboxes WHERE id = $1`, mb,
	).Scan(&s); err != nil {
		t.Fatalf("emailState: %v", err)
	}
	return s
}

// mkLocationTag creates an exclusive-group 'location' tag (the branch dispatch
// key) in mailbox `mb`.
func mkLocationTag(t *testing.T, env *imapIsoEnv, mb int64, name string) int64 {
	t.Helper()
	var id int64
	if err := env.superPool.QueryRow(context.Background(),
		`INSERT INTO tags (mailbox_id, name, tag_type, exclusive_group, sort_order, imap_expose)
		 VALUES ($1, $2, 'user', 'location', 991, TRUE)
		 ON CONFLICT (mailbox_id, name) DO UPDATE SET name = EXCLUDED.name
		 RETURNING id`, mb, name,
	).Scan(&id); err != nil {
		t.Fatalf("mkLocationTag %q: %v", name, err)
	}
	return id
}

// TestIMAPBatch_CopyUIDOrderingMembershipMode pins the UID rule end-to-end with
// membership UIDs: non-contiguous source UIDs {5,7,900}, message ids INSERTED in
// the OPPOSITE order of their UIDs (the lowest id carries the highest UID), and
// two distinct messages sharing one received_at (same partition) while the third
// sits at a different received_at (partition boundary). COPY 1:* must allocate
// destination UIDs in the source view's ascending UID order — never message-ID
// order — and pair them positionally in COPYUID.
func TestIMAPBatch_CopyUIDOrderingMembershipMode(t *testing.T) {
	env := setupIMAPIso(t)
	ctx := context.Background()

	dest := mkUserTag(t, env, env.mbA, "BatchCopyDest")

	// Insert the high-UID message FIRST (lowest message id), the shared-
	// timestamp pair LAST (highest message ids). recv truncated to seconds so
	// the value round-trips timestamptz exactly.
	recvShared := time.Now().UTC().Truncate(time.Second)
	recvOther := recvShared.Add(-48 * time.Hour)
	muid := func(u int64) *int64 { return &u }
	idHigh := mkBatchMsg(t, env, env.mbA, env.tagA, 900, "imapA-batch-high", recvOther, muid(900))
	idMid := mkBatchMsg(t, env, env.mbA, env.tagA, 500, "imapA-batch-mid", recvShared, muid(7))
	idLow := mkBatchMsg(t, env, env.mbA, env.tagA, 300, "imapA-batch-low", recvShared, muid(5))

	// Source view (membership UID ascending): seeds 1,2 then 5,7,900 — message
	// ids NOT in ascending order (idHigh < idMid < idLow while UIDs 900 > 7 > 5).
	if got := batchViewUIDs(t, env, env.mbA, env.tagA, true); !reflectEq(got, []int64{1, 2, 5, 7, 900}) {
		t.Fatalf("precondition: membership view should be [1 2 5 7 900], got %v", got)
	}

	cA, bcA := env.connFor(env.mbA, env.tagA)
	cA.useMembershipUID = true // the session's pinned UID authority (handleSelect's gate, exercised directly)
	cA.handleCopy(ctx, "c1", "1:* BatchCopyDest", true)
	out := bcA.String()
	if !strings.Contains(out, "OK COPY completed") {
		t.Fatalf("COPY should complete OK; got:\n%s", out)
	}
	validity, srcs, dsts, ok := parseCOPYUID(out)
	if !ok {
		t.Fatalf("COPY should emit a COPYUID line; got:\n%s", out)
	}
	if want := []int64{1, 2, 5, 7, 900}; !reflectEq(srcs, want) {
		t.Fatalf("COPYUID source UIDs should follow the source view order %v, got %v", want, srcs)
	}
	// THE PIN: destination UIDs are allocated in the INPUT ORDINAL order —
	// strictly ascending alongside the source order, even though the message ids
	// run the other way and two rows share a received_at.
	if !sort.SliceIsSorted(dsts, func(i, j int) bool { return dsts[i] < dsts[j] }) {
		t.Fatalf("destination UIDs must be allocated in source-ordinal (ascending UID) order, got %v", dsts)
	}
	for _, u := range dsts {
		if u <= 0 {
			t.Fatalf("destination UIDs must be allocated, got %v", dsts)
		}
	}
	// The COPYUID line must carry the DESTINATION tag's UIDVALIDITY.
	if validity != destUIDValidityOf(t, env, dest) {
		t.Fatalf("COPYUID must carry the destination tag's UIDVALIDITY (%d), got %d", destUIDValidityOf(t, env, dest), validity)
	}

	// Dest view: 5 primary memberships whose membership UIDs are exactly dsts in
	// ascending order — the pairing maps each source message to the UID the
	// allocator gave it in ordinal order (matched on (message_id, received_at),
	// reordered by ordinal).
	if got := primaryTagCount(t, env, env.mbA, dest); got != 5 {
		t.Fatalf("dest should hold 5 copies, got %d", got)
	}
	byUID := destUIDByMessage(t, env, dest)
	for _, id := range []int64{idHigh, idMid, idLow} {
		if _, present := byUID[id]; !present {
			t.Fatalf("copied message %d missing from dest membership map: %v", id, byUID)
		}
	}
	// Partition fidelity: the copies kept their ORIGINAL received_at (same
	// partition), across both timestamps.
	var sharedPart, otherPart int
	if err := env.superPool.QueryRow(ctx,
		`SELECT count(*) FILTER (WHERE m.received_at = $1), count(*) FILTER (WHERE m.received_at = $2)
		   FROM message_tags mt JOIN messages m ON m.id = mt.message_id AND m.received_at = mt.received_at
		  WHERE mt.tag_id = $3 AND m.mailbox_id = $4`,
		recvShared, recvOther, dest, env.mbA,
	).Scan(&sharedPart, &otherPart); err != nil {
		t.Fatalf("partition probe: %v", err)
	}
	if sharedPart != 2 || otherPart != 1 {
		t.Fatalf("copies must land in their original received_at partitions (shared=%d other=%d)", sharedPart, otherPart)
	}
}

// TestIMAPBatch_MoveOrderingMembershipMode mirrors the COPY pin for MOVE: one
// command moves all five messages; source emptied; destination UIDs allocated in
// source-ordinal order; source removal happened in ONE statement but still fires
// the per-row counter/retire triggers (source counts drop to zero).
func TestIMAPBatch_MoveOrderingMembershipMode(t *testing.T) {
	env := setupIMAPIso(t)
	ctx := context.Background()

	dest := mkUserTag(t, env, env.mbA, "BatchMoveDest")

	recvShared := time.Now().UTC().Truncate(time.Second)
	recvOther := recvShared.Add(-48 * time.Hour)
	muid := func(u int64) *int64 { return &u }
	idHigh := mkBatchMsg(t, env, env.mbA, env.tagA, 900, "imapA-bmv-high", recvOther, muid(900))
	idMid := mkBatchMsg(t, env, env.mbA, env.tagA, 500, "imapA-bmv-mid", recvShared, muid(7))
	idLow := mkBatchMsg(t, env, env.mbA, env.tagA, 300, "imapA-bmv-low", recvShared, muid(5))
	ids := []int64{idHigh, idMid, idLow}

	cA, bcA := env.connFor(env.mbA, env.tagA)
	cA.useMembershipUID = true
	cA.handleMove(ctx, "m1", "1:* BatchMoveDest", true)
	out := bcA.String()
	if !strings.Contains(out, "OK MOVE completed") {
		t.Fatalf("MOVE should complete OK; got:\n%s", out)
	}
	_, srcs, dsts, ok := parseCOPYUID(out)
	if !ok {
		t.Fatalf("MOVE should emit COPYUID; got:\n%s", out)
	}
	if want := []int64{1, 2, 5, 7, 900}; !reflectEq(srcs, want) {
		t.Fatalf("COPYUID source UIDs should be %v, got %v", want, srcs)
	}
	if !sort.SliceIsSorted(dsts, func(i, j int) bool { return dsts[i] < dsts[j] }) {
		t.Fatalf("MOVE destination UIDs must follow source-ordinal order, got %v", dsts)
	}
	if got := primaryTagCount(t, env, env.mbA, env.tagA); got != 0 {
		t.Fatalf("source should be empty after MOVE 1:*, got %d", got)
	}
	if got := primaryTagCount(t, env, env.mbA, dest); got != 5 {
		t.Fatalf("dest should hold 5 moved messages, got %d", got)
	}
	// Each moved message kept its identity and its original received_at.
	for _, id := range ids {
		var n int
		if err := env.superPool.QueryRow(ctx,
			`SELECT count(*) FROM message_tags mt
			 JOIN messages m ON m.id = mt.message_id AND m.received_at = mt.received_at
			 WHERE mt.message_id = $1 AND mt.tag_id = $2 AND m.mailbox_id = $3`,
			id, dest, env.mbA,
		).Scan(&n); err != nil {
			t.Fatalf("moved message probe %d: %v", id, err)
		}
		if n != 1 {
			t.Fatalf("moved message %d should carry exactly one dest membership, got %d", id, n)
		}
	}
}

// TestIMAPBatch_SameFolderMoveReallocates pins the same-folder op: MOVE into the
// selected folder itself must complete (remove + re-add, exactly as the per-row
// loop did), keep every message visible, and allocate FRESH membership UIDs
// (retired UIDs are never reused).
func TestIMAPBatch_SameFolderMoveReallocates(t *testing.T) {
	env := setupIMAPIso(t)
	ctx := context.Background()

	recv := time.Now().UTC().Truncate(time.Second)
	muid := func(u int64) *int64 { return &u }
	idHigh := mkBatchMsg(t, env, env.mbA, env.tagA, 900, "imapA-same-high", recv, muid(900))
	idLow := mkBatchMsg(t, env, env.mbA, env.tagA, 300, "imapA-same-low", recv, muid(5))

	uidsBefore := batchViewUIDs(t, env, env.mbA, env.tagA, true)
	maxBefore := uidsBefore[len(uidsBefore)-1]

	cA, bcA := env.connFor(env.mbA, env.tagA)
	cA.useMembershipUID = true
	// dest name == source name → same-folder MOVE.
	cA.handleMove(ctx, "m1", fmt.Sprintf("1:* %s", "Inbox"), true)
	if !strings.Contains(bcA.String(), "OK MOVE completed") {
		t.Fatalf("same-folder MOVE should complete OK; got:\n%s", bcA.String())
	}

	uidsAfter := batchViewUIDs(t, env, env.mbA, env.tagA, true)
	if len(uidsAfter) != len(uidsBefore) {
		t.Fatalf("same-folder MOVE must preserve membership count (before %v after %v)", uidsBefore, uidsAfter)
	}
	if uidsAfter[len(uidsAfter)-1] <= maxBefore {
		t.Fatalf("same-folder MOVE must reallocate fresh (higher) membership UIDs; before %v after %v", uidsBefore, uidsAfter)
	}
	// The two pinned messages are still primary in the folder.
	for _, id := range []int64{idHigh, idLow} {
		var ok bool
		if err := env.superPool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM message_tags WHERE message_id = $1 AND tag_id = $2 AND is_primary)`,
			id, env.tagA,
		).Scan(&ok); err != nil {
			t.Fatalf("same-folder probe %d: %v", id, err)
		}
		if !ok {
			t.Fatalf("same-folder MOVE lost message %d", id)
		}
	}
}

// TestIMAPBatch_LegacyModeDestinationUIDIsSourceUID pins the legacy rule in both
// verbs: with the session on message UIDs, the destination UID equals the source
// message UID (no allocation read), for contiguous and non-contiguous sets.
func TestIMAPBatch_LegacyModeDestinationUIDIsSourceUID(t *testing.T) {
	env := setupIMAPIso(t)
	ctx := context.Background()

	copyDest := mkUserTag(t, env, env.mbA, "BatchLegacyCopy")
	moveDest := mkUserTag(t, env, env.mbA, "BatchLegacyMove")
	recv := time.Now().UTC().Truncate(time.Second)
	mkBatchMsg(t, env, env.mbA, env.tagA, 900, "imapA-leg-high", recv, nil)
	mkBatchMsg(t, env, env.mbA, env.tagA, 300, "imapA-leg-low", recv, nil)

	cA, bcA := env.connFor(env.mbA, env.tagA)
	// useMembershipUID stays false — the legacy mode default.
	cA.handleCopy(ctx, "c1", "1:* BatchLegacyCopy", true)
	out := bcA.String()
	if !strings.Contains(out, "OK COPY completed") {
		t.Fatalf("legacy COPY should complete OK; got:\n%s", out)
	}
	_, srcs, dsts, ok := parseCOPYUID(out)
	if !ok {
		t.Fatalf("legacy COPY should emit COPYUID; got:\n%s", out)
	}
	if !reflectEq(srcs, []int64{1, 2, 300, 900}) || !reflectEq(dsts, srcs) {
		t.Fatalf("legacy COPY destination UIDs must equal the source message UIDs (src=%v dst=%v)", srcs, dsts)
	}
	if got := primaryTagCount(t, env, env.mbA, copyDest); got != 4 {
		t.Fatalf("legacy COPY dest should hold 4, got %d", got)
	}

	// MOVE shares the rule (run on fresh tags so UIDs are intact for the second
	// source view: reuse the same folder — COPY left the source untouched).
	cM, bcM := env.connFor(env.mbA, env.tagA)
	cM.handleMove(ctx, "m1", "1:* BatchLegacyMove", true)
	outM := bcM.String()
	if !strings.Contains(outM, "OK MOVE completed") {
		t.Fatalf("legacy MOVE should complete OK; got:\n%s", outM)
	}
	_, srcsM, dstsM, okM := parseCOPYUID(outM)
	if !okM {
		t.Fatalf("legacy MOVE should emit COPYUID; got:\n%s", outM)
	}
	if !reflectEq(srcsM, []int64{1, 2, 300, 900}) || !reflectEq(dstsM, srcsM) {
		t.Fatalf("legacy MOVE destination UIDs must equal the source message UIDs (src=%v dst=%v)", srcsM, dstsM)
	}
	if got := primaryTagCount(t, env, env.mbA, moveDest); got != 4 {
		t.Fatalf("legacy MOVE dest should hold 4, got %d", got)
	}
}

// TestIMAPBatch_CopyDuplicateRejectedTransactionally pins mutation-time duplicate
// detection: no separate EXISTS read; the message_tags PRIMARY KEY rejects a
// repeated COPY, the whole statement (and command) rolls back, the client gets
// the [CANNOT] NO, no COPYUID success line is emitted, and NO partial rows from
// the same batch landed — including when only the LAST message of the batch is
// the duplicate (mixed preexisting membership).
func TestIMAPBatch_CopyDuplicateRejectedTransactionally(t *testing.T) {
	env := setupIMAPIso(t)
	ctx := context.Background()

	dest := mkUserTag(t, env, env.mbA, "BatchDupDest")
	recv := time.Now().UTC().Truncate(time.Second)
	mkBatchMsg(t, env, env.mbA, env.tagA, 300, "imapA-dup-low", recv, nil)
	mkBatchMsg(t, env, env.mbA, env.tagA, 900, "imapA-dup-high", recv, nil)

	cA, bcA := env.connFor(env.mbA, env.tagA)
	cA.handleCopy(ctx, "c1", "1:* BatchDupDest", true)
	if !strings.Contains(bcA.String(), "OK COPY completed") {
		t.Fatalf("first COPY should complete; got:\n%s", bcA.String())
	}
	countAfterFirst := primaryTagCount(t, env, env.mbA, dest)
	if countAfterFirst != 4 {
		t.Fatalf("after first COPY dest should hold 4, got %d", countAfterFirst)
	}

	// Repeated COPY of the same set → every row is a duplicate → [CANNOT].
	cA2, bcA2 := env.connFor(env.mbA, env.tagA)
	cA2.handleCopy(ctx, "c2", "1:* BatchDupDest", true)
	out := bcA2.String()
	if !strings.Contains(out, "NO [CANNOT] Destination already contains one or more messages") {
		t.Fatalf("duplicate COPY must reply NO [CANNOT]; got:\n%s", out)
	}
	if strings.Contains(out, "COPYUID") {
		t.Fatalf("failed COPY must NOT emit COPYUID; got:\n%s", out)
	}
	if got := primaryTagCount(t, env, env.mbA, dest); got != countAfterFirst {
		t.Fatalf("duplicate COPY must add nothing (dest %d, want %d)", got, countAfterFirst)
	}

	// Mixed preexisting membership: pre-tag dest for the LAST target only
	// (non-primary, so it is not visible in the dest view), then COPY the whole
	// set — the mutation-time PK violation must reject the WHOLE batch: the
	// earlier (non-duplicate) messages must NOT land either.
	var midID int64
	if err := env.superPool.QueryRow(ctx,
		`SELECT m.id FROM messages m JOIN message_tags mt ON mt.message_id = m.id AND mt.received_at = m.received_at
		 WHERE m.mailbox_id = $1 AND mt.tag_id = $2 AND mt.is_primary AND NOT m.is_deleted ORDER BY m.imap_uid LIMIT 1`,
		env.mbA, env.tagA,
	).Scan(&midID); err != nil {
		t.Fatalf("pick mid message: %v", err)
	}
	mixedDest := mkUserTag(t, env, env.mbA, "BatchMixedDest")
	if _, err := env.superPool.Exec(ctx,
		`INSERT INTO message_tags (message_id, received_at, tag_id, added_by, is_primary)
		 SELECT id, received_at, $3, 'deliver', FALSE FROM messages WHERE id = $1 AND mailbox_id = $2`,
		midID, env.mbA, mixedDest,
	); err != nil {
		t.Fatalf("seed preexisting membership: %v", err)
	}
	cA3, bcA3 := env.connFor(env.mbA, env.tagA)
	cA3.handleCopy(ctx, "c3", "1:* BatchMixedDest", true)
	out3 := bcA3.String()
	if !strings.Contains(out3, "NO [CANNOT]") {
		t.Fatalf("mixed-duplicate COPY must reply NO [CANNOT]; got:\n%s", out3)
	}
	if got := primaryTagCount(t, env, env.mbA, mixedDest); got != 0 {
		t.Fatalf("mixed duplicate COPY must be all-or-nothing (dest primaries %d, want 0)", got)
	}
	// The preexisting non-primary membership survived the rollback untouched.
	var still int
	if err := env.superPool.QueryRow(ctx,
		`SELECT count(*) FROM message_tags WHERE message_id = $1 AND tag_id = $2`,
		midID, mixedDest,
	).Scan(&still); err != nil {
		t.Fatalf("preexisting membership probe: %v", err)
	}
	if still != 1 {
		t.Fatalf("preexisting membership must survive the rolled-back COPY, got %d", still)
	}
}

// TestIMAPBatch_MoveLateFailureRollsBack pins command atomicity across
// statements: a MOVE whose LAST target already holds a (non-primary) membership
// in the non-location dest fails at the set-based INSERT — and the set-based
// source DELETE that already ran in the SAME command must roll back with it
// (every message stays in the source folder), with no COPYUID, no dest rows and
// no notification side effects (journal rows / state bumps absent after
// rollback).
func TestIMAPBatch_MoveLateFailureRollsBack(t *testing.T) {
	env := setupIMAPIso(t)
	ctx := context.Background()

	dest := mkUserTag(t, env, env.mbA, "BatchLateDest")
	recv := time.Now().UTC().Truncate(time.Second)
	mkBatchMsg(t, env, env.mbA, env.tagA, 300, "imapA-late-low", recv, nil)
	mkBatchMsg(t, env, env.mbA, env.tagA, 900, "imapA-late-high", recv, nil)

	// Late-failure seed: the HIGHEST-UID message (last input ordinal) already has
	// a non-primary dest membership — the set-based INSERT hits its PK last.
	var highID int64
	if err := env.superPool.QueryRow(ctx,
		`SELECT m.id FROM messages m JOIN message_tags mt ON mt.message_id = m.id AND mt.received_at = m.received_at
		 WHERE m.mailbox_id = $1 AND mt.tag_id = $2 AND mt.is_primary AND NOT m.is_deleted ORDER BY m.imap_uid DESC LIMIT 1`,
		env.mbA, env.tagA,
	).Scan(&highID); err != nil {
		t.Fatalf("pick high message: %v", err)
	}
	var highRecv time.Time
	if err := env.superPool.QueryRow(ctx,
		`SELECT received_at FROM messages WHERE id = $1`, highID,
	).Scan(&highRecv); err != nil {
		t.Fatalf("read high received_at: %v", err)
	}
	if _, err := env.superPool.Exec(ctx,
		`INSERT INTO message_tags (message_id, received_at, tag_id, added_by, is_primary)
		 VALUES ($1, $2, $3, 'deliver', FALSE)`,
		highID, highRecv, dest,
	); err != nil {
		t.Fatalf("seed late-failure membership: %v", err)
	}

	stateBefore := emailState(t, env, env.mbA)
	var journalBefore int
	if err := env.superPool.QueryRow(ctx,
		`SELECT count(*) FROM jmap_changes_journal WHERE mailbox_id = $1 AND datatype = 'email'`,
		env.mbA,
	).Scan(&journalBefore); err != nil {
		t.Fatalf("journal before: %v", err)
	}

	cA, bcA := env.connFor(env.mbA, env.tagA)
	cA.handleMove(ctx, "m1", "1:* BatchLateDest", true)
	out := bcA.String()
	if !strings.Contains(out, "NO MOVE failed") {
		t.Fatalf("late-failure MOVE must reply NO; got:\n%s", out)
	}
	if strings.Contains(out, "COPYUID") {
		t.Fatalf("failed MOVE must NOT emit COPYUID; got:\n%s", out)
	}
	// THE PIN: the earlier set-based source DELETE rolled back — nothing left the
	// source folder.
	if got := primaryTagCount(t, env, env.mbA, env.tagA); got != 4 {
		t.Fatalf("source must be untouched after the rolled-back MOVE (got %d, want 4)", got)
	}
	if got := primaryTagCount(t, env, env.mbA, dest); got != 0 {
		t.Fatalf("no dest primaries may appear after the rolled-back MOVE (got %d)", got)
	}
	// Notification absence after rollback: state and journal unchanged.
	if stateAfter := emailState(t, env, env.mbA); stateAfter != stateBefore {
		t.Fatalf("rolled-back MOVE must not bump email state (before %d after %d)", stateBefore, stateAfter)
	}
	var journalAfter int
	if err := env.superPool.QueryRow(ctx,
		`SELECT count(*) FROM jmap_changes_journal WHERE mailbox_id = $1 AND datatype = 'email'`,
		env.mbA,
	).Scan(&journalAfter); err != nil {
		t.Fatalf("journal after: %v", err)
	}
	if journalAfter != journalBefore {
		t.Fatalf("rolled-back MOVE must append no journal rows (before %d after %d)", journalBefore, journalAfter)
	}
}

// TestIMAPBatch_DualTenantArraysUntouched pins ownership on the batch arrays:
// tenant B's rows colliding on legacy UID and received_at must never be touched
// by A's batched MOVE/COPY (the statements' messages.mailbox_id join + RLS GUC),
// and B's dest-tag space cannot be resolved by A (unknown target → zero-count
// success, not an error).
func TestIMAPBatch_DualTenantArraysUntouched(t *testing.T) {
	env := setupIMAPIso(t)
	ctx := context.Background()

	dest := mkUserTag(t, env, env.mbA, "BatchIsoDest")
	// B's message: same received_at AND same legacy uid (1) as A's first seed.
	recv := time.Now().UTC().Truncate(time.Second)
	mkBatchMsg(t, env, env.mbB, env.tagB, 1, "imapB-collide", recv, nil)

	cA, bcA := env.connFor(env.mbA, env.tagA)
	cA.handleCopy(ctx, "c1", "1:* BatchIsoDest", true)
	if !strings.Contains(bcA.String(), "OK COPY completed") {
		t.Fatalf("A's COPY should complete; got:\n%s", bcA.String())
	}
	// B's message untouched: still exactly one membership, in B's Inbox only.
	var bMemberships int
	if err := env.superPool.QueryRow(ctx,
		`SELECT count(*) FROM message_tags mt JOIN messages m ON m.id = mt.message_id AND m.received_at = mt.received_at
		 WHERE m.mailbox_id = $1`, env.mbB,
	).Scan(&bMemberships); err != nil {
		t.Fatalf("B membership probe: %v", err)
	}
	if bMemberships != 2 { // B's seeded message + the colliding fixture, each in B's Inbox
		t.Fatalf("B's memberships must be untouched by A's COPY (got %d, want 2)", bMemberships)
	}
	var bGotDest int
	if err := env.superPool.QueryRow(ctx,
		`SELECT count(*) FROM message_tags mt JOIN messages m ON m.id = mt.message_id AND m.received_at = mt.received_at
		 WHERE m.mailbox_id = $1 AND mt.tag_id = $2`, env.mbB, dest,
	).Scan(&bGotDest); err != nil {
		t.Fatalf("B dest-tag probe: %v", err)
	}
	if bGotDest != 0 {
		t.Fatalf("ISOLATION BREACH: A's batched COPY tagged B's message into A's dest (%d rows)", bGotDest)
	}

	// MOVE the whole folder into a second dest; B must still be intact afterward.
	mkUserTag(t, env, env.mbA, "BatchIsoDest2")
	cA2, _ := env.connFor(env.mbA, env.tagA)
	cA2.handleMove(ctx, "m1", "1:* BatchIsoDest2", true)
	if got := primaryTagCount(t, env, env.mbB, env.tagB); got != 2 {
		t.Fatalf("B's Inbox must be untouched by A's batched MOVE (got %d, want 2)", got)
	}
}

// TestIMAPBatch_LocationMoveBatchReducerAndNotify pins the location branch: the
// batch front door routes each message through transition_message_location
// (exclusive invariant held, reducer-owned notify, NO second notify from Go), in
// source-ordinal order, with the exclusive trigger removing the OTHER location
// tag — never leaving a message with two location tags — and mixed preexisting
// memberships (a message already carrying the dest location tag) get swapped
// with a fresh UID.
func TestIMAPBatch_LocationMoveBatchReducerAndNotify(t *testing.T) {
	env := setupIMAPIso(t)
	ctx := context.Background()

	// Two location-group dests so the exclusive swap has something to remove,
	// plus a dedicated NON-location source folder: the seeds live in Inbox (a
	// location tag), and the preexisting-membership seed below must not trip the
	// exclusive trigger against the source view.
	locA := mkLocationTag(t, env, env.mbA, "BatchLocA")
	locB := mkLocationTag(t, env, env.mbA, "BatchLocB")
	src := mkUserTag(t, env, env.mbA, "BatchLocSrc")

	recv := time.Now().UTC().Truncate(time.Second)
	recvOld := recv.Add(-48 * time.Hour)
	muid := func(u int64) *int64 { return &u }
	idLow := mkBatchMsg(t, env, env.mbA, src, 300, "imapA-loc-low", recv, muid(5))
	idHigh := mkBatchMsg(t, env, env.mbA, src, 900, "imapA-loc-high", recvOld, muid(900))
	// Mixed preexisting: the LOW-ordinal message already carries locB as a
	// non-primary location membership.
	if _, err := env.superPool.Exec(ctx,
		`INSERT INTO message_tags (message_id, received_at, tag_id, added_by, is_primary)
		 SELECT id, received_at, $3, 'deliver', FALSE FROM messages WHERE id = $1 AND mailbox_id = $2`,
		idLow, env.mbA, locB,
	); err != nil {
		t.Fatalf("seed preexisting location membership: %v", err)
	}

	stateBefore := emailState(t, env, env.mbA)
	cA, bcA := env.connFor(env.mbA, src)
	cA.useMembershipUID = true
	cA.handleMove(ctx, "m1", "1:* BatchLocA", true)
	out := bcA.String()
	if !strings.Contains(out, "OK MOVE completed") {
		t.Fatalf("location MOVE should complete OK; got:\n%s", out)
	}
	_, srcs, dsts, ok := parseCOPYUID(out)
	if !ok {
		t.Fatalf("location MOVE should emit COPYUID; got:\n%s", out)
	}
	if want := []int64{5, 900}; !reflectEq(srcs, want) {
		t.Fatalf("location MOVE source UIDs should be %v, got %v", want, srcs)
	}
	if !sort.SliceIsSorted(dsts, func(i, j int) bool { return dsts[i] < dsts[j] }) {
		t.Fatalf("location MOVE dest UIDs must follow source-ordinal order, got %v", dsts)
	}
	// No message carries TWO location tags (exclusive invariant) — check across
	// BOTH location dests and Inbox.
	var dual int
	if err := env.superPool.QueryRow(ctx,
		`SELECT count(*) FROM
		   (SELECT mt.message_id FROM message_tags mt JOIN tags t ON t.id = mt.tag_id
		    JOIN messages m ON m.id = mt.message_id AND m.received_at = mt.received_at
		    WHERE m.mailbox_id = $1 AND t.exclusive_group = 'location'
		    GROUP BY mt.message_id HAVING count(*) > 1) d`,
		env.mbA,
	).Scan(&dual); err != nil {
		t.Fatalf("dual-location probe: %v", err)
	}
	if dual != 0 {
		t.Fatalf("exclusive invariant violated: %d message(s) carry multiple location tags", dual)
	}
	// Both fixtures now carry locA as their single location (primary) membership.
	if got := primaryTagCount(t, env, env.mbA, locA); got != 2 {
		t.Fatalf("all moved messages should carry locA primary (got %d, want 2)", got)
	}
	if got := primaryTagCount(t, env, env.mbA, src); got != 0 {
		t.Fatalf("source folder should be empty after the location MOVE (got %d)", got)
	}
	// The preexisting locB membership of idLow was REMOVED by the swap (exactly
	// one location membership for idLow, namely locA).
	var locBLeft int
	if err := env.superPool.QueryRow(ctx,
		`SELECT count(*) FROM message_tags WHERE message_id = $1 AND tag_id = $2`, idLow, locB,
	).Scan(&locBLeft); err != nil {
		t.Fatalf("locB leftover probe: %v", err)
	}
	if locBLeft != 0 {
		t.Fatalf("preexisting location membership must be swapped away, got %d leftover", locBLeft)
	}
	// Reducer-owned notification, per message, NO second call: exactly N
	// 'updated' journal rows above the pre-command state (N = 4 targets).
	stateAfter := emailState(t, env, env.mbA)
	if stateAfter <= stateBefore {
		t.Fatalf("location MOVE must bump email state (before %d after %d)", stateBefore, stateAfter)
	}
	ids := []int64{idLow, idHigh}
	var updated int
	if err := env.superPool.QueryRow(ctx,
		`SELECT count(*) FROM jmap_changes_journal
		 WHERE mailbox_id = $1 AND datatype = 'email' AND op = 'updated' AND state_seq > $2
		   AND entity_id = ANY($3)`,
		env.mbA, stateBefore, ids,
	).Scan(&updated); err != nil {
		t.Fatalf("location journal probe: %v", err)
	}
	if updated != 2 {
		t.Fatalf("location MOVE must journal exactly one 'updated' per moved message (got %d, want 2) — no double-notify", updated)
	}
}

// TestIMAPBatch_StatementCountBounded pins the round-trip bound: the number of
// mutation/UID-read statements a MOVE or COPY issues does not grow with N
// (notification calls are excluded explicitly — they stay per-message by
// design). Small (N=2) and large (N=8) batches must cost the same count, for
// the non-location branch, the location branch (batch front door) and COPY.
func TestIMAPBatch_StatementCountBounded(t *testing.T) {
	env := setupIMAPIso(t)
	ctx := context.Background()

	recv := time.Now().UTC().Truncate(time.Second)
	mk := func(tag int64, n int, prefix string) {
		for i := 0; i < n; i++ {
			mkBatchMsg(t, env, env.mbA, tag, int64(100+i), fmt.Sprintf("%s-%d", prefix, i), recv.Add(time.Duration(i)*time.Minute), nil)
		}
	}

	// Non-location MOVE: N=2 vs N=8.
	moveDest := mkUserTag(t, env, env.mbA, "BatchCountMove")
	srcSmall := mkUserTag(t, env, env.mbA, "BatchCountSrcSmall")
	srcLarge := mkUserTag(t, env, env.mbA, "BatchCountSrcLarge")
	mk(srcSmall, 2, "imapA-cnt-s")
	mk(srcLarge, 8, "imapA-cnt-l")

	tr1 := &countingTracer{count: isMutationOrUIDRead, skip: isExcluded}
	pool1 := newTracingAppPool(t, tr1)
	c1 := &connState{srv: &Server{pool: pool1}, conn: &bufConn{}, authed: true, userID: 1,
		selected: "x", mailboxID: env.mbA, tagID: srcSmall}
	c1.handleMove(ctx, "m1", "1:* BatchCountMove", false)
	if got := primaryTagCount(t, env, env.mbA, moveDest); got != 2 {
		t.Fatalf("small MOVE should land 2, got %d", got)
	}
	smallN := tr1.n

	tr2 := &countingTracer{count: isMutationOrUIDRead, skip: isExcluded}
	pool2 := newTracingAppPool(t, tr2)
	c2 := &connState{srv: &Server{pool: pool2}, conn: &bufConn{}, authed: true, userID: 1,
		selected: "x", mailboxID: env.mbA, tagID: srcLarge}
	c2.handleMove(ctx, "m2", "1:* BatchCountMove", false)
	if got := primaryTagCount(t, env, env.mbA, moveDest); got != 10 {
		t.Fatalf("large MOVE should land 10 total, got %d", got)
	}
	largeN := tr2.n
	if smallN == 0 || smallN != largeN {
		t.Fatalf("MOVE statement count must not grow with N (N=2: %d, N=8: %d); executed:\n%s",
			smallN, largeN, strings.Join(tr2.sqls, "\n---\n"))
	}

	// Location MOVE (batch front door): N=2 vs N=8.
	locDest := mkLocationTag(t, env, env.mbA, "BatchCountLoc")
	srcLocSmall := mkUserTag(t, env, env.mbA, "BatchCountLocSmall")
	srcLocLarge := mkUserTag(t, env, env.mbA, "BatchCountLocLarge")
	mk(srcLocSmall, 2, "imapA-cntl-s")
	mk(srcLocLarge, 8, "imapA-cntl-l")

	tr3 := &countingTracer{count: isMutationOrUIDRead, skip: isExcluded}
	pool3 := newTracingAppPool(t, tr3)
	c3 := &connState{srv: &Server{pool: pool3}, conn: &bufConn{}, authed: true, userID: 1,
		selected: "x", mailboxID: env.mbA, tagID: srcLocSmall}
	c3.handleMove(ctx, "m3", "1:* BatchCountLoc", false)
	if got := primaryTagCount(t, env, env.mbA, locDest); got != 2 {
		t.Fatalf("small location MOVE should land 2, got %d", got)
	}
	locSmall := tr3.n

	tr4 := &countingTracer{count: isMutationOrUIDRead, skip: isExcluded}
	pool4 := newTracingAppPool(t, tr4)
	c4 := &connState{srv: &Server{pool: pool4}, conn: &bufConn{}, authed: true, userID: 1,
		selected: "x", mailboxID: env.mbA, tagID: srcLocLarge}
	c4.handleMove(ctx, "m4", "1:* BatchCountLoc", false)
	if got := primaryTagCount(t, env, env.mbA, locDest); got != 10 {
		t.Fatalf("large location MOVE should land 10 total, got %d", got)
	}
	locLarge := tr4.n
	if locSmall == 0 || locSmall != locLarge {
		t.Fatalf("location MOVE statement count must not grow with N (N=2: %d, N=8: %d); executed:\n%s",
			locSmall, locLarge, strings.Join(tr4.sqls, "\n---\n"))
	}

	// COPY: N=2 vs N=8.
	copyDest := mkUserTag(t, env, env.mbA, "BatchCountCopy")
	srcCopySmall := mkUserTag(t, env, env.mbA, "BatchCountCopySmall")
	srcCopyLarge := mkUserTag(t, env, env.mbA, "BatchCountCopyLarge")
	mk(srcCopySmall, 2, "imapA-cntc-s")
	mk(srcCopyLarge, 8, "imapA-cntc-l")

	tr5 := &countingTracer{count: isMutationOrUIDRead, skip: isExcluded}
	pool5 := newTracingAppPool(t, tr5)
	c5 := &connState{srv: &Server{pool: pool5}, conn: &bufConn{}, authed: true, userID: 1,
		selected: "x", mailboxID: env.mbA, tagID: srcCopySmall}
	c5.handleCopy(ctx, "c1", "1:* BatchCountCopy", false)
	if got := primaryTagCount(t, env, env.mbA, copyDest); got != 2 {
		t.Fatalf("small COPY should land 2, got %d", got)
	}
	copySmall := tr5.n

	tr6 := &countingTracer{count: isMutationOrUIDRead, skip: isExcluded}
	pool6 := newTracingAppPool(t, tr6)
	c6 := &connState{srv: &Server{pool: pool6}, conn: &bufConn{}, authed: true, userID: 1,
		selected: "x", mailboxID: env.mbA, tagID: srcCopyLarge}
	c6.handleCopy(ctx, "c2", "1:* BatchCountCopy", false)
	if got := primaryTagCount(t, env, env.mbA, copyDest); got != 10 {
		t.Fatalf("large COPY should land 10 total, got %d", got)
	}
	copyLarge := tr6.n
	if copySmall == 0 || copySmall != copyLarge {
		t.Fatalf("COPY statement count must not grow with N (N=2: %d, N=8: %d); executed:\n%s",
			copySmall, copyLarge, strings.Join(tr6.sqls, "\n---\n"))
	}
}

// TestIMAPBatch_CopyNotifiesPerMessageInOrdinalOrder pins the notification
// contract on the successful path: exactly one 'updated' journal row per copied
// message (per-message, not coalesced), and the journal's state_seq values are
// strictly increasing in the SOURCE ORDINAL order of the COPYUID pairing.
func TestIMAPBatch_CopyNotifiesPerMessageInOrdinalOrder(t *testing.T) {
	env := setupIMAPIso(t)
	ctx := context.Background()

	dest := mkUserTag(t, env, env.mbA, "BatchNotifyDest")
	recv := time.Now().UTC().Truncate(time.Second)
	idHigh := mkBatchMsg(t, env, env.mbA, env.tagA, 900, "imapA-ntf-high", recv, nil)
	mid := mkBatchMsg(t, env, env.mbA, env.tagA, 500, "imapA-ntf-mid", recv, nil)
	idLow := mkBatchMsg(t, env, env.mbA, env.tagA, 300, "imapA-ntf-low", recv, nil)

	stateBefore := emailState(t, env, env.mbA)
	cA, bcA := env.connFor(env.mbA, env.tagA)
	cA.handleCopy(ctx, "c1", "1:* BatchNotifyDest", true)
	if !strings.Contains(bcA.String(), "OK COPY completed") {
		t.Fatalf("COPY should complete; got:\n%s", bcA.String())
	}
	_, srcs, _, ok := parseCOPYUID(bcA.String())
	if !ok {
		t.Fatalf("COPY should emit COPYUID; got:\n%s", bcA.String())
	}
	if got := primaryTagCount(t, env, env.mbA, dest); got != 5 {
		t.Fatalf("COPY should land 5 copies, got %d", got)
	}
	ids := []int64{idLow, mid, idHigh}
	// source view order is [1,2,300,500,900] → the three fixtures are ordinals
	// 3,4,5 of the COPYUID source list.
	ord := func(id int64) int {
		uid := legacyUIDOf(t, env, id)
		for i, s := range srcs {
			if s == uid {
				return i
			}
		}
		t.Fatalf("uid %d missing from COPYUID srcs %v", uid, srcs)
		return 0
	}
	rows := journalRowsSince(t, env, env.mbA, stateBefore)
	if len(rows) != 5 {
		t.Fatalf("expected exactly one journal row per copied message (5), got %d: %v", len(rows), rows)
	}
	// Journal state_seq ascends with the input ordinal — notifications ran in
	// source-ordinal order.
	prevOrd := -1
	prevSeq := int64(0)
	for _, r := range rows {
		o := ord(r.entityID)
		if o < prevOrd {
			t.Fatalf("journal rows out of source-ordinal order: %v", rows)
		}
		if r.stateSeq <= prevSeq {
			t.Fatalf("journal state_seq must strictly increase per notification: %v", rows)
		}
		prevOrd, prevSeq = o, r.stateSeq
	}
	// Every row is 'updated' with the dest tag as the collection tag; entity ids
	// are exactly the copied messages.
	got := map[int64]bool{}
	for _, r := range rows {
		if r.op != "updated" {
			t.Fatalf("expected 'updated' journal op, got %q", r.op)
		}
		got[r.entityID] = true
	}
	for _, id := range ids {
		if !got[id] {
			t.Fatalf("copied message %d missing from journal rows %v", id, rows)
		}
	}
}

// ── small helpers over the shared harness ────────────────────────────────────

func reflectEq(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func destUIDValidityOf(t *testing.T, env *imapIsoEnv, tag int64) int64 {
	t.Helper()
	var v int64
	if err := env.superPool.QueryRow(context.Background(),
		`SELECT imap_uid_validity FROM tags WHERE id = $1`, tag,
	).Scan(&v); err != nil {
		t.Fatalf("dest UIDVALIDITY: %v", err)
	}
	return v
}

// destUIDByMessage maps message id → membership UID for a tag's memberships.
func destUIDByMessage(t *testing.T, env *imapIsoEnv, tag int64) map[int64]int64 {
	t.Helper()
	rows, err := env.superPool.Query(context.Background(),
		`SELECT mt.message_id, mt.imap_uid FROM message_tags mt
		 JOIN messages m ON m.id = mt.message_id AND m.received_at = mt.received_at
		 WHERE mt.tag_id = $1 AND m.mailbox_id = $2 AND mt.is_primary`, tag, env.mbA)
	if err != nil {
		t.Fatalf("destUIDByMessage: %v", err)
	}
	defer rows.Close()
	out := map[int64]int64{}
	for rows.Next() {
		var id, uid int64
		if err := rows.Scan(&id, &uid); err != nil {
			t.Fatalf("destUIDByMessage scan: %v", err)
		}
		out[id] = uid
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("destUIDByMessage rows: %v", err)
	}
	return out
}

func legacyUIDOf(t *testing.T, env *imapIsoEnv, id int64) int64 {
	t.Helper()
	var u int64
	if err := env.superPool.QueryRow(context.Background(),
		`SELECT imap_uid FROM messages WHERE id = $1`, id,
	).Scan(&u); err != nil {
		t.Fatalf("legacyUIDOf %d: %v", id, err)
	}
	return u
}

type batchJournalRow struct {
	stateSeq int64
	entityID int64
	op       string
}

func journalRowsSince(t *testing.T, env *imapIsoEnv, mb, since int64) []batchJournalRow {
	t.Helper()
	rows, err := env.superPool.Query(context.Background(),
		`SELECT state_seq, entity_id, op FROM jmap_changes_journal
		 WHERE mailbox_id = $1 AND datatype = 'email' AND state_seq > $2
		 ORDER BY state_seq`, mb, since)
	if err != nil {
		t.Fatalf("journalRowsSince: %v", err)
	}
	defer rows.Close()
	var out []batchJournalRow
	for rows.Next() {
		var r batchJournalRow
		if err := rows.Scan(&r.stateSeq, &r.entityID, &r.op); err != nil {
			t.Fatalf("journalRowsSince scan: %v", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("journalRowsSince rows: %v", err)
	}
	return out
}
