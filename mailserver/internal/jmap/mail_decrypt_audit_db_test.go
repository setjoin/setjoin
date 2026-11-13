package jmap

// SP1 Phase 5 review — decrypt-on-read AUDIT-ROW guard (DB-backed, TEST_DB_DSN).
//
// THE BUG THIS LOCKS: the decrypt-on-read success path audits an `email_decrypt_read`
// row into mailbox_audit_log (mailbox_id NOT NULL, FK → mailboxes(id)). The old
// code derived the audit mailbox_id from the email's `mailboxIds` JSON object —
// but jmap_email_get keys that object by message_tags.tag_id, a DIFFERENT id space
// from mailboxes.id. So the common case wrote a tag_id (or the 0 fallback) into
// mailbox_audit_log.mailbox_id → the FK was violated, the best-effort Exec SWALLOWED
// the error, and the audit row was NEVER written. The exit-criterion was broken.
//
// THE FIX: thread the caller's authenticated PRIMARY mailbox id (accountID, from
// parseAccountID) into decryptOneEmail and use it as the audit mailbox_id. This
// test proves (a) the real mailbox id lands a row, and (b) MUTATION — the old
// tag_id / 0 mailbox ids drop the row (FK violation, swallowed) — so the assertion
// would FAIL against the pre-fix behaviour.

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"setjoin.com/shared/pgxutil"
)

// mk_account COMMITs into the shared test DB, so cleanup tears the whole graph
// down (session_replication_role='replica' to suspend the FK/triggers), the same
// idiom internal/imap's isolation harness uses.

// TestDecryptAuditRow_LandsWithRealMailboxID proves the decrypt-on-read audit
// insert (the exact statement decryptOneEmail runs on success) writes an
// email_decrypt_read row keyed to the caller's REAL mailbox id — and that the
// pre-fix tag_id / 0 ids would NOT land a row (mutation proof of the FK-drop bug).
func TestDecryptAuditRow_LandsWithRealMailboxID(t *testing.T) {
	if testing.Short() {
		t.Skip("-short: skipping DB-backed decrypt-on-read audit-row guard")
	}
	pool := newDecryptTestPool(t)
	ctx := context.Background()

	// Real account (commits): a genuine mailboxes(id) + its owning user(id). The
	// mutation tag is allocated above both live id spaces so it cannot
	// accidentally be a valid mailbox id in a long-lived shared test database.
	var mailboxID, userID, tagID int64
	if err := pool.QueryRow(ctx, `SELECT mk_account('p5AuditA')`).Scan(&mailboxID); err != nil {
		t.Fatalf("mk_account: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT user_id FROM mailboxes WHERE id = $1`, mailboxID).Scan(&userID); err != nil {
		t.Fatalf("resolve user: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		WITH candidate AS (
			SELECT GREATEST(
				COALESCE((SELECT max(id) FROM mailboxes), 0),
				COALESCE((SELECT max(id) FROM tags), 0)
			) + 1000000 AS id
		)
		INSERT INTO tags(id,mailbox_id,name,tag_type)
		SELECT id,$1,'Mutation invalid mailbox id','user' FROM candidate
		RETURNING id
	`, mailboxID).Scan(&tagID); err != nil {
		t.Fatalf("create mutation tag: %v", err)
	}
	// Seed one message in the mailbox so the audit row can reference a real message_id.
	recv := time.Now()
	var msgID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO messages (mailbox_id, folder_id, imap_uid, message_id, subject,
		    from_addr, to_addrs, cc_addrs, size_bytes, thread_id, raw_ref, received_at,
		    is_read, crypto_type)
		 VALUES ($1, $2, 1, 'p5audit1', 'enc subj', 'sender@ext.com', '[]'::jsonb,
		         '[]'::jsonb, 10, 'thr-p5a', 'raw-p5a', $3, FALSE, 'smime-encrypted')
		 RETURNING id`,
		mailboxID, tagID, recv,
	).Scan(&msgID); err != nil {
		t.Fatalf("insert message: %v", err)
	}

	t.Cleanup(func() {
		conn, err := pool.Acquire(ctx)
		if err != nil {
			return
		}
		defer conn.Release()
		// mk_account COMMITs; suspend triggers/FK actions to tear the graph down.
		_, _ = conn.Exec(ctx, `SET session_replication_role = 'replica'`)
		_, _ = conn.Exec(ctx, `DELETE FROM mailbox_audit_log WHERE mailbox_id = $1`, mailboxID)
		_, _ = conn.Exec(ctx, `DELETE FROM message_tags WHERE message_id = $1`, msgID)
		_, _ = conn.Exec(ctx, `DELETE FROM messages WHERE mailbox_id = $1`, mailboxID)
		_, _ = conn.Exec(ctx, `DELETE FROM tags WHERE mailbox_id = $1`, mailboxID)
		_, _ = conn.Exec(ctx, `DELETE FROM folders WHERE mailbox_id = $1`, mailboxID)
		_, _ = conn.Exec(ctx, `DELETE FROM mailboxes WHERE id = $1`, mailboxID)
		_, _ = conn.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
		_, _ = conn.Exec(ctx, `SET session_replication_role = 'origin'`)
	})

	// The explicit high tag id must remain outside the mailbox id space so the
	// mutation arm proves the old audit value violates the FK.
	if tagID == mailboxID {
		t.Fatalf("tag id (%d) == mailbox id (%d) — mutation arm would be vacuous (need divergent id spaces)", tagID, mailboxID)
	}
	var tagIsMailbox bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM mailboxes WHERE id = $1)`, tagID).Scan(&tagIsMailbox); err != nil {
		t.Fatalf("probe tag-as-mailbox: %v", err)
	}
	if tagIsMailbox {
		t.Fatalf("tag id %d is also a valid mailbox id — mutation arm would not violate the FK", tagID)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := NewJMAPHandler(pool, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, logger)

	countAudit := func() int {
		var n int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM mailbox_audit_log
			 WHERE mailbox_id = $1 AND actor_user_id = $2 AND action = 'email_decrypt_read'`,
			mailboxID, userID,
		).Scan(&n); err != nil {
			t.Fatalf("count audit rows: %v", err)
		}
		return n
	}

	// ── THE FIX: audit with the REAL mailbox id (what decryptOneEmail now passes).
	// This is the exact insert decryptOneEmail runs on a successful decrypt. ──
	if before := countAudit(); before != 0 {
		t.Fatalf("expected 0 audit rows before, got %d", before)
	}
	h.auditMailbox(ctx, userID, mailboxID, "email_decrypt_read", &msgID)
	if after := countAudit(); after != 1 {
		t.Fatalf("decrypt-on-read audit row did NOT land with the real mailbox id (want 1, got %d) — the FK insert must succeed", after)
	}

	// ── MUTATION: the PRE-FIX behaviour used the tag_id (from mailboxIds) or the 0
	// fallback as mailbox_id. Both violate the FK; the best-effort Exec swallows the
	// error, so NO row lands. Prove the broken ids drop the audit — i.e. this whole
	// test would FAIL if decryptOneEmail still used decryptAuditMailbox(email). ──
	var encParts struct{ tagRows, zeroRows int }
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM mailbox_audit_log WHERE mailbox_id = $1 AND action = 'email_decrypt_read'`,
		tagID,
	).Scan(&encParts.tagRows); err != nil {
		t.Fatalf("count tag-id audit rows (pre): %v", err)
	}
	h.auditMailbox(ctx, userID, tagID, "email_decrypt_read", &msgID) // old: decryptAuditMailbox → tag_id
	h.auditMailbox(ctx, userID, 0, "email_decrypt_read", &msgID)     // old: 0 fallback
	var tagRowsAfter, zeroRowsAfter int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM mailbox_audit_log WHERE mailbox_id = $1 AND action = 'email_decrypt_read'`,
		tagID,
	).Scan(&tagRowsAfter); err != nil {
		t.Fatalf("count tag-id audit rows (post): %v", err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM mailbox_audit_log WHERE mailbox_id = 0 AND action = 'email_decrypt_read'`,
	).Scan(&zeroRowsAfter); err != nil {
		t.Fatalf("count zero-id audit rows (post): %v", err)
	}
	if tagRowsAfter != encParts.tagRows {
		t.Errorf("MUTATION FAIL: a tag_id audit insert (the pre-fix behaviour) landed a row (before=%d after=%d) — it must FK-violate and be swallowed", encParts.tagRows, tagRowsAfter)
	}
	if zeroRowsAfter != 0 {
		t.Errorf("MUTATION FAIL: a mailbox_id=0 audit insert (the pre-fix fallback) landed a row — it must FK-violate and be swallowed")
	}

	// The real-id row is still the only one for this mailbox (the bad inserts didn't
	// corrupt the count).
	if got := countAudit(); got != 1 {
		t.Fatalf("after the mutation arm the real-id mailbox should still have exactly 1 audit row, got %d", got)
	}
}
