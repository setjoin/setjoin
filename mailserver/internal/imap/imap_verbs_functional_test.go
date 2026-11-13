package imap

// IMAP MOVE/COPY/APPEND/CLOSE functional tests (P1 IMAP fix, T1–T3).
//
// THE BUG THESE CLOSE: handleAppend/handleMove/handleCopy/handleClose used to
// resolve messages via the legacy `folders` table — a join of messages.folder_id
// against folders.id, or `folder_id = (SELECT id FROM folders WHERE name=…)`. But
// messages.folder_id holds a TAG id (the trg_message_tags_primary_sync trigger
// sets folder_id = NEW.tag_id), and folders/tags are independent id sequences, so
// those verbs silently no-op / orphan messages. APPEND additionally created NO
// message_tags row (the message was invisible to FETCH/SEARCH) AND omitted three
// NOT NULL columns (message_id/thread_id/raw_ref), so its INSERT failed outright.
//
// These tests drive the REAL handlers through the same DB-backed harness as
// imap_isolation_test.go (setupIMAPIso: pgxpool app+super pools, a connState bound
// to a mailbox, a buffer-backed net.Conn, fixtures via the superuser pool, full
// self-cleaning teardown). They run as setjoin_app under V004 FORCE — so they also
// confirm each verb's writes survive RLS (the GUC = the message's mailbox).
//
// GATING: DB_DSN (mail/superuser) + the derived/overridable setjoin_app DSN; skips
// cleanly with no DB. Fixtures are torn down by setupIMAPIso's t.Cleanup.

import (
	"bufio"
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

// feedAppendLiteral wires c.reader to deliver the APPEND literal (plus the
// trailing CRLF handleAppend consumes after the literal). handleAppend reads the
// literal off c.reader after writing the "+ " continuation to c.conn.
func feedAppendLiteral(c *connState, body string) {
	c.reader = bufio.NewReader(strings.NewReader(body + "\r\n"))
}

func itoa(n int) string { return strconv.Itoa(n) }

// countTagged returns how many messages in mailbox `mb` carry tag `tagID`
// (regardless of is_primary), read on the RLS-bypassing superuser pool.
func countTagged(t *testing.T, env *imapIsoEnv, mb, tagID int64) int {
	t.Helper()
	var n int
	if err := env.superPool.QueryRow(context.Background(),
		`SELECT count(*) FROM message_tags mt
		 JOIN messages m ON m.id = mt.message_id AND m.received_at = mt.received_at
		 WHERE mt.tag_id = $1 AND m.mailbox_id = $2`,
		tagID, mb,
	).Scan(&n); err != nil {
		t.Fatalf("countTagged: %v", err)
	}
	return n
}

// primaryTagCount returns how many PRIMARY message_tags rows in mailbox `mb`
// carry tag `tagID` — this is what FETCH/SEARCH select on (is_primary = TRUE).
func primaryTagCount(t *testing.T, env *imapIsoEnv, mb, tagID int64) int {
	t.Helper()
	var n int
	if err := env.superPool.QueryRow(context.Background(),
		`SELECT count(*) FROM message_tags mt
		 JOIN messages m ON m.id = mt.message_id AND m.received_at = mt.received_at
		 WHERE mt.tag_id = $1 AND mt.is_primary = TRUE AND m.mailbox_id = $2`,
		tagID, mb,
	).Scan(&n); err != nil {
		t.Fatalf("primaryTagCount: %v", err)
	}
	return n
}

// mkUserTag creates an IMAP-exposed user (non-location) tag in mailbox `mb`.
func mkUserTag(t *testing.T, env *imapIsoEnv, mb int64, name string) int64 {
	t.Helper()
	var id int64
	if err := env.superPool.QueryRow(context.Background(),
		`INSERT INTO tags (mailbox_id, name, tag_type, sort_order, imap_expose)
		 VALUES ($1, $2, 'user', 990, TRUE)
		 ON CONFLICT (mailbox_id, name) DO UPDATE SET name = EXCLUDED.name
		 RETURNING id`, mb, name,
	).Scan(&id); err != nil {
		t.Fatalf("mkUserTag %q: %v", name, err)
	}
	return id
}

// TestIMAPAppend_ThenFetch proves an APPENDed message becomes visible to FETCH —
// i.e. APPEND now creates the primary message_tags row (the silent-data-loss bug)
// and supplies the NOT NULL columns the old INSERT omitted.
func TestIMAPAppend_ThenFetch(t *testing.T) {
	env := setupIMAPIso(t)
	ctx := context.Background()

	// A's connState, selected on Inbox. APPEND a raw message into "Inbox".
	cA, bcA := env.connFor(env.mbA, env.tagA)
	body := "Subject: appended-one\r\n\r\nhello from APPEND\r\n"
	// Drive handleAppend with a connState whose reader is wired to deliver the
	// literal. handleAppend reads the literal off c.reader after writing the "+ "
	// continuation; the harness conn blocks on Read, so feed the literal via a
	// dedicated reader instead.
	feedAppendLiteral(cA, body)
	cA.handleAppend(ctx, "a1", `Inbox {`+itoa(len(body))+`}`)
	out := bcA.String()
	if !strings.Contains(out, "a1 OK ") || !strings.Contains(out, "APPEND completed") {
		t.Fatalf("APPEND should complete OK; got:\n%s", out)
	}

	// The message must now be tagged primary into A's Inbox (visible to FETCH).
	before := 2 // setupIMAPIso seeds A with 2 Inbox messages
	if got := primaryTagCount(t, env, env.mbA, env.tagA); got != before+1 {
		t.Fatalf("APPEND should add 1 primary Inbox tag (expected %d, got %d)", before+1, got)
	}

	// FETCH must surface the appended message (visible through the message_tags
	// JOIN that FETCH uses).
	cF, bcF := env.connFor(env.mbA, env.tagA)
	cF.handleFetch(ctx, "f1", "1:*", false)
	fout := bcF.String()
	if c := strings.Count(fout, "FETCH (UID "); c != before+1 {
		t.Fatalf("FETCH after APPEND should return %d messages, got %d:\n%s", before+1, c, fout)
	}
}

// TestIMAPMove_GoneFromSourcePresentInDest proves MOVE removes the message from
// the source folder and makes it visible in the destination — resolving the
// source via message_tags+tagID (not the broken folders join) and adding the dest
// with the message's ORIGINAL received_at.
func TestIMAPMove_GoneFromSourcePresentInDest(t *testing.T) {
	env := setupIMAPIso(t)
	ctx := context.Background()

	dest := mkUserTag(t, env, env.mbA, "MoveDest")

	if got := primaryTagCount(t, env, env.mbA, env.tagA); got != 2 {
		t.Fatalf("precondition: A's Inbox should have 2 primary, got %d", got)
	}

	// MOVE message at sequence 1 from Inbox → MoveDest.
	cA, bcA := env.connFor(env.mbA, env.tagA)
	cA.handleMove(ctx, "m1", "1 MoveDest", false)
	out := bcA.String()
	if !strings.Contains(out, "OK MOVE completed") {
		t.Fatalf("MOVE should complete OK; got:\n%s", out)
	}

	// Gone from source: Inbox primary count drops by 1.
	if got := primaryTagCount(t, env, env.mbA, env.tagA); got != 1 {
		t.Fatalf("after MOVE source Inbox should have 1 primary, got %d", got)
	}
	// Present in dest: MoveDest has exactly 1 primary membership.
	if got := primaryTagCount(t, env, env.mbA, dest); got != 1 {
		t.Fatalf("after MOVE dest MoveDest should have 1 primary, got %d", got)
	}
	// FETCH on the dest folder surfaces the moved message.
	cF, bcF := env.connFor(env.mbA, dest)
	cF.handleFetch(ctx, "f1", "1:*", false)
	if c := strings.Count(bcF.String(), "FETCH (UID "); c != 1 {
		t.Fatalf("FETCH on dest after MOVE should return 1 message, got %d:\n%s", c, bcF.String())
	}
}

// TestIMAPMove_ToLocationGroupRespectsInvariant proves a MOVE into a location-group
// folder (Trash) routes through transition_message_location: the source location
// tag is removed and the dest is added as the single location tag (exclusive
// invariant) with the SAME received_at.
func TestIMAPMove_ToLocationGroupRespectsInvariant(t *testing.T) {
	env := setupIMAPIso(t)
	ctx := context.Background()

	var trashTag int64
	if err := env.superPool.QueryRow(ctx, `SELECT get_tag_id('Trash', $1)`, env.mbA).Scan(&trashTag); err != nil {
		t.Fatalf("get Trash tag: %v", err)
	}

	cA, bcA := env.connFor(env.mbA, env.tagA)
	cA.handleMove(ctx, "m1", "1 Trash", false)
	if !strings.Contains(bcA.String(), "OK MOVE completed") {
		t.Fatalf("MOVE to Trash should complete OK; got:\n%s", bcA.String())
	}

	// Source Inbox loses one; Trash gains exactly one. The exclusive-group
	// invariant must hold: the moved message has exactly ONE location tag (Trash).
	if got := primaryTagCount(t, env, env.mbA, env.tagA); got != 1 {
		t.Fatalf("after MOVE→Trash, Inbox should have 1, got %d", got)
	}
	if got := primaryTagCount(t, env, env.mbA, trashTag); got != 1 {
		t.Fatalf("after MOVE→Trash, Trash should have 1, got %d", got)
	}
	// No message in A carries BOTH a Trash and an Inbox location tag.
	var dualLoc int
	if err := env.superPool.QueryRow(ctx,
		`SELECT count(*) FROM message_tags mt1
		 JOIN message_tags mt2 ON mt1.message_id = mt2.message_id AND mt1.received_at = mt2.received_at
		 WHERE mt1.tag_id = $1 AND mt2.tag_id = $2`,
		env.tagA, trashTag,
	).Scan(&dualLoc); err != nil {
		t.Fatalf("dual-location probe: %v", err)
	}
	if dualLoc != 0 {
		t.Fatalf("exclusive-group invariant violated: %d message(s) carry both Inbox and Trash", dualLoc)
	}
}

// TestIMAPMove_UIDNotPositional is the regression test for codebase-review
// finding C3 (2026-07-11): UID MOVE resolved the sequence-set positionally
// (parseSeqRange → array index into the UID-ordered view) instead of against
// imap_uid values — unlike every other UID verb (FETCH/STORE, closed by the
// BUG-2/TestIMAPFetch_UIDNotPositional fix). With Inbox messages at UIDs
// {1, 2, 1000} (non-contiguous), "UID MOVE 3" names a UID that does NOT
// exist, so the fixed handler must move ZERO messages. The old code read "3"
// as sequence position 3 in the 3-message UID-ordered list and wrongly moved
// the position-3 message (imap_uid=1000) — a real message, just the wrong one.
func TestIMAPMove_UIDNotPositional(t *testing.T) {
	env := setupIMAPIso(t)
	ctx := context.Background()

	// Third message with a large, non-contiguous imap_uid — same technique as
	// TestIMAPFetch_UIDNotPositional.
	recv := time.Now()
	var highID int64
	if err := env.superPool.QueryRow(ctx,
		`INSERT INTO messages (mailbox_id, folder_id, imap_uid, message_id, subject, from_addr, to_addrs, cc_addrs, size_bytes, thread_id, raw_ref, received_at, is_read)
		 VALUES ($1, $2, 1000, 'imapA-move-uid1000', 'high-uid msg', 'sender@ext.com', '[]'::jsonb, '[]'::jsonb, 10, 'thr-move-uid1000', 'raw-move-uid1000', $3, FALSE) RETURNING id`,
		env.mbA, env.tagA, recv,
	).Scan(&highID); err != nil {
		t.Fatalf("insert high-uid message: %v", err)
	}
	if _, err := env.superPool.Exec(ctx,
		`SELECT tag_message($1, $2, 'Inbox', $3, 'deliver', TRUE)`,
		highID, recv, env.mbA,
	); err != nil {
		t.Fatalf("tag high-uid message: %v", err)
	}

	dest := mkUserTag(t, env, env.mbA, "UIDMoveDest")

	// UID MOVE 3 — no message has imap_uid=3 (the live set is {1, 2, 1000}) —
	// must move ZERO messages.
	cA, bcA := env.connFor(env.mbA, env.tagA)
	cA.handleMove(ctx, "m1", "3 UIDMoveDest", true)
	out := bcA.String()
	if !strings.Contains(out, "OK MOVE completed") {
		t.Fatalf("MOVE should complete OK; got:\n%s", out)
	}

	if got := primaryTagCount(t, env, env.mbA, dest); got != 0 {
		t.Fatalf("UID MOVE 3 (nonexistent UID) should move 0 messages, got %d in dest", got)
	}
	// The high-uid message (imap_uid=1000, folder position 3) must still be in
	// Inbox — the positional bug would have wrongly moved exactly this message.
	var stillInInbox bool
	if err := env.superPool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM message_tags WHERE message_id = $1 AND tag_id = $2 AND is_primary)`,
		highID, env.tagA,
	).Scan(&stillInInbox); err != nil {
		t.Fatalf("check high-uid message still in inbox: %v", err)
	}
	if !stillInInbox {
		t.Fatalf("UID MOVE 3 wrongly moved the position-3 message (imap_uid=1000) out of Inbox")
	}
}

// TestIMAPCopy_UIDNotPositional mirrors TestIMAPMove_UIDNotPositional for the
// other verb named in codebase-review finding C3: UID COPY must resolve
// against imap_uid values, not array position. With Inbox at non-contiguous
// UIDs {1, 2, 1000}, "UID COPY 3" names a UID that does NOT exist, so it must
// copy ZERO messages — the old positional code would have wrongly copied the
// position-3 message (imap_uid=1000) into the dest folder.
func TestIMAPCopy_UIDNotPositional(t *testing.T) {
	env := setupIMAPIso(t)
	ctx := context.Background()

	recv := time.Now()
	var highID int64
	if err := env.superPool.QueryRow(ctx,
		`INSERT INTO messages (mailbox_id, folder_id, imap_uid, message_id, subject, from_addr, to_addrs, cc_addrs, size_bytes, thread_id, raw_ref, received_at, is_read)
		 VALUES ($1, $2, 1000, 'imapA-copy-uid1000', 'high-uid msg', 'sender@ext.com', '[]'::jsonb, '[]'::jsonb, 10, 'thr-copy-uid1000', 'raw-copy-uid1000', $3, FALSE) RETURNING id`,
		env.mbA, env.tagA, recv,
	).Scan(&highID); err != nil {
		t.Fatalf("insert high-uid message: %v", err)
	}
	if _, err := env.superPool.Exec(ctx,
		`SELECT tag_message($1, $2, 'Inbox', $3, 'deliver', TRUE)`,
		highID, recv, env.mbA,
	); err != nil {
		t.Fatalf("tag high-uid message: %v", err)
	}

	dest := mkUserTag(t, env, env.mbA, "UIDCopyDest")

	// UID COPY 3 — no message has imap_uid=3 (the live set is {1, 2, 1000}) —
	// must copy ZERO messages.
	cA, bcA := env.connFor(env.mbA, env.tagA)
	cA.handleCopy(ctx, "c1", "3 UIDCopyDest", true)
	out := bcA.String()
	if !strings.Contains(out, "OK COPY completed") {
		t.Fatalf("COPY should complete OK; got:\n%s", out)
	}

	if got := primaryTagCount(t, env, env.mbA, dest); got != 0 {
		t.Fatalf("UID COPY 3 (nonexistent UID) should copy 0 messages, got %d in dest", got)
	}
	// The high-uid message (imap_uid=1000, folder position 3) must not have
	// gained the dest tag — the positional bug would have wrongly copied
	// exactly this message.
	var gotDestTag bool
	if err := env.superPool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM message_tags WHERE message_id = $1 AND tag_id = $2)`,
		highID, dest,
	).Scan(&gotDestTag); err != nil {
		t.Fatalf("check high-uid message dest tag: %v", err)
	}
	if gotDestTag {
		t.Fatalf("UID COPY 3 wrongly copied the position-3 message (imap_uid=1000) into dest")
	}
}

// TestIMAPCopy_Duplicates proves COPY adds the dest tag WITHOUT removing the
// source — the message is present in BOTH folders afterward (and visible to FETCH
// in each, since the copy is is_primary = TRUE).
func TestIMAPCopy_Duplicates(t *testing.T) {
	env := setupIMAPIso(t)
	ctx := context.Background()

	dest := mkUserTag(t, env, env.mbA, "CopyDest")

	cA, bcA := env.connFor(env.mbA, env.tagA)
	cA.handleCopy(ctx, "c1", "1 CopyDest", false)
	out := bcA.String()
	if !strings.Contains(out, "OK COPY completed") {
		t.Fatalf("COPY should complete OK; got:\n%s", out)
	}

	// WP4 (batch SQL): the COPYUID line must still carry the destination tag's
	// UIDVALIDITY and the legacy pairing destination UID = source message UID,
	// formatted by formatUIDSet as comma-joined ascending UID lists.
	var destValidity int64
	if err := env.superPool.QueryRow(ctx,
		`SELECT imap_uid_validity FROM tags WHERE id = $1`, dest,
	).Scan(&destValidity); err != nil {
		t.Fatalf("dest UIDVALIDITY: %v", err)
	}
	if !strings.Contains(out, fmt.Sprintf("* OK [COPYUID %d 1 1] COPY completed", destValidity)) {
		t.Fatalf("COPY should emit [COPYUID %d 1 1] (dest UID = source message UID in legacy mode); got:\n%s", destValidity, out)
	}

	// Source unchanged (still 2 primary in Inbox).
	if got := primaryTagCount(t, env, env.mbA, env.tagA); got != 2 {
		t.Fatalf("after COPY source Inbox should be unchanged at 2, got %d", got)
	}
	// Dest gains exactly 1 (the copy), visible to FETCH (is_primary = TRUE).
	if got := primaryTagCount(t, env, env.mbA, dest); got != 1 {
		t.Fatalf("after COPY dest CopyDest should have 1 primary, got %d", got)
	}
	cF, bcF := env.connFor(env.mbA, dest)
	cF.handleFetch(ctx, "f1", "1:*", false)
	if c := strings.Count(bcF.String(), "FETCH (UID "); c != 1 {
		t.Fatalf("FETCH on dest after COPY should return 1 message, got %d:\n%s", c, bcF.String())
	}
}

// TestIMAPClose_Expunges proves CLOSE expunges \Deleted messages in the selected
// folder, resolved via message_tags+tagID (the old folders join matched nothing,
// so CLOSE silently expunged nothing).
func TestIMAPClose_Expunges(t *testing.T) {
	env := setupIMAPIso(t)
	ctx := context.Background()

	// Mark A's first Inbox message \Deleted (superuser pool, prior state).
	if _, err := env.superPool.Exec(ctx, `UPDATE messages SET is_deleted = TRUE WHERE id = $1`, env.msgA1); err != nil {
		t.Fatalf("mark A1 deleted: %v", err)
	}

	cA, bcA := env.connFor(env.mbA, env.tagA)
	cA.handleClose(ctx, "cl1")
	if !strings.Contains(bcA.String(), "OK CLOSE completed") {
		t.Fatalf("CLOSE should complete OK; got:\n%s", bcA.String())
	}

	// The \Deleted message must be gone; the non-deleted one survives.
	var a1Exists, a2Exists bool
	if err := env.superPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM messages WHERE id = $1)`, env.msgA1).Scan(&a1Exists); err != nil {
		t.Fatalf("probe A1: %v", err)
	}
	if err := env.superPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM messages WHERE id = $1)`, env.msgA2).Scan(&a2Exists); err != nil {
		t.Fatalf("probe A2: %v", err)
	}
	if a1Exists {
		t.Fatalf("CLOSE should have expunged the \\Deleted message A1, but it survives")
	}
	if !a2Exists {
		t.Fatalf("CLOSE expunged the non-deleted message A2 — should only remove \\Deleted")
	}
}
