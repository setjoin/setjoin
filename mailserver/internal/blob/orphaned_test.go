package blob

import (
	"context"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/testsupport"
)

// randomOrphanedRef returns a unique, non-inline, non-existent-object raw_ref
// so parallel test runs never collide on the orphaned_message_blobs PK.
func randomOrphanedRef(t *testing.T, prefix string) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return fmt.Sprintf("%s-%x", prefix, b)
}

func insertOrphanedRef(t *testing.T, pool *pgxpool.Pool, ref string) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx,
		`INSERT INTO orphaned_message_blobs (raw_ref) VALUES ($1)`, ref,
	); err != nil {
		t.Fatalf("insert orphaned_message_blobs: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM orphaned_message_blobs WHERE raw_ref = $1`, ref) //nolint:errcheck
	})
}

func orphanedRefExists(t *testing.T, pool *pgxpool.Pool, ref string) bool {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(context.Background(),
		`SELECT EXISTS(SELECT 1 FROM orphaned_message_blobs WHERE raw_ref = $1)`, ref,
	).Scan(&exists); err != nil {
		t.Fatalf("check orphaned_message_blobs: %v", err)
	}
	return exists
}

// insertOrphanTestMessage creates a minimal domain→mailbox→folder→message
// chain whose raw_ref is the given ref, so a drain re-check finds it "still
// referenced". Returns the message id for cleanup.
func insertOrphanTestMessage(t *testing.T, pool *pgxpool.Pool, ref string) int64 {
	t.Helper()
	ctx := context.Background()
	suffix := randomOrphanedRef(t, "orphtest")

	var domainID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name) VALUES ($1)
		 ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
		 RETURNING id`, suffix+".test",
	).Scan(&domainID); err != nil {
		t.Skipf("domains insert failed (incomplete test schema?): %v", err)
	}

	var userID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, password_hash, domain_id)
		 VALUES ($1, $2, 'Orphan Test', '$2a$10$placeholder', $3)
		 RETURNING id`,
		suffix, suffix+"@"+suffix+".test", domainID,
	).Scan(&userID); err != nil {
		t.Fatalf("users insert: %v", err)
	}

	var mailboxID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO mailboxes (user_id, domain_id, email, display_name, is_primary)
		 VALUES ($1, $2, $3, 'Orphan Test', TRUE)
		 RETURNING id`,
		userID, domainID, suffix+"@"+suffix+".test",
	).Scan(&mailboxID); err != nil {
		t.Fatalf("mailboxes insert: %v", err)
	}

	var folderID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO folders (mailbox_id, name, role, path)
		 VALUES ($1, 'Inbox', 'inbox', 'Inbox')
		 RETURNING id`, mailboxID,
	).Scan(&folderID); err != nil {
		t.Fatalf("folders insert: %v", err)
	}

	var msgID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO messages (mailbox_id, folder_id, message_id, from_addr, thread_id, raw_ref)
		 VALUES ($1, $2, $3, 'from@'||$4, $5, $6)
		 RETURNING id`,
		mailboxID, folderID, "<"+suffix+"@test>", suffix, "thread-"+suffix, ref,
	).Scan(&msgID); err != nil {
		t.Fatalf("messages insert: %v", err)
	}

	t.Cleanup(func() {
		bg := context.Background()
		pool.Exec(bg, `DELETE FROM messages WHERE id = $1`, msgID)   //nolint:errcheck
		pool.Exec(bg, `DELETE FROM folders WHERE id = $1`, folderID) //nolint:errcheck
		// mailboxes and users must be deleted in ONE transaction: V085's
		// deferred (AFTER DELETE ... INITIALLY DEFERRED) trigger checks, at
		// COMMIT, whether the mailbox's user still exists without a primary —
		// deleting them as two separate autocommit statements commits the
		// mailbox delete first, while the user row still exists, and the
		// trigger raises BZ013 (silently swallowed here, leaking the row).
		// One transaction means both are gone by the time the deferred check
		// runs.
		tx, err := pool.Begin(bg)
		if err == nil {
			tx.Exec(bg, `DELETE FROM mailboxes WHERE id = $1`, mailboxID) //nolint:errcheck
			tx.Exec(bg, `DELETE FROM users WHERE id = $1`, userID)        //nolint:errcheck
			tx.Commit(bg)                                                 //nolint:errcheck
		}
		// Unlike ensureTestDomain's shared "setjoin.test" row, this domain is
		// unique per test run (randomOrphanedRef suffix) — safe, and necessary,
		// to delete outright: org-wide reducers (e.g. gal_search) enumerate ALL
		// domains, so a leaked row here inflates unrelated pgTAP/Go assertions
		// that count "every enabled user across every domain" in the shared
		// mailserver_test database.
		pool.Exec(bg, `DELETE FROM domains WHERE id = $1`, domainID) //nolint:errcheck
	})

	return msgID
}

// TestProcessOrphanedBlobs_DrainsUnreferencedBlob is the red-first case for
// the leak: a purge path queued an unshared raw_ref, nothing ever drained it.
// After processOrphanedBlobs, the object must be removed from storage AND the
// queue row gone.
func TestProcessOrphanedBlobs_DrainsUnreferencedBlob(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ref := randomOrphanedRef(t, "blobs/orphaned")
	insertOrphanedRef(t, pool, ref)

	fake := newFakeStore()
	h := &Handler{minio: fake, workerPool: pool, bucket: "blobs", logger: discardLogger()}
	h.processOrphanedBlobs(context.Background())

	found := false
	for _, k := range fake.removeKeys {
		if k == ref {
			found = true
		}
	}
	if !found {
		t.Errorf("RemoveObject was not called for unreferenced raw_ref %q (removeKeys=%v)", ref, fake.removeKeys)
	}
	if orphanedRefExists(t, pool, ref) {
		t.Error("orphaned_message_blobs row still present after drain")
	}
}

// TestProcessOrphanedBlobs_NeverDeletesInlineRef is the critical safety
// invariant: an inline RFC 5322 message text (a reducer-built draft raw_ref,
// which purge paths can queue verbatim — see jmap_email_submission.sql's
// swap-seam orphan enqueue) must NEVER be handed to RemoveObject. The queue
// row is still cleaned up (it's junk, not a leak).
func TestProcessOrphanedBlobs_NeverDeletesInlineRef(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	inlineRef := "Message-ID: <inline-test@setjoin.local>\r\nFrom: a@b.test\r\nTo: c@d.test\r\n\r\nbody\r\n"
	insertOrphanedRef(t, pool, inlineRef)

	fake := newFakeStore()
	h := &Handler{minio: fake, workerPool: pool, bucket: "blobs", logger: discardLogger()}
	h.processOrphanedBlobs(context.Background())

	if len(fake.removeKeys) != 0 {
		t.Errorf("RemoveObject must never be called for an inline raw_ref, got removeKeys=%v", fake.removeKeys)
	}
	if orphanedRefExists(t, pool, inlineRef) {
		t.Error("inline junk row should still be removed from orphaned_message_blobs")
	}
}

// TestProcessOrphanedBlobs_SkipsStillReferencedBlob is the double-delete
// safety case: raw_ref is content-addressed for some producers, so a new
// message can legitimately recreate a key that is sitting in the orphan
// queue from an older, already-purged message. The drain must re-check
// against the live messages table and skip the S3 delete when the key is
// still in use — otherwise a live message's raw body gets deleted out from
// under it.
func TestProcessOrphanedBlobs_SkipsStillReferencedBlob(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ref := randomOrphanedRef(t, "blobs/reused")
	insertOrphanedRef(t, pool, ref)
	insertOrphanTestMessage(t, pool, ref) // a live message now points at the same key

	fake := newFakeStore()
	h := &Handler{minio: fake, workerPool: pool, bucket: "blobs", logger: discardLogger()}
	h.processOrphanedBlobs(context.Background())

	for _, k := range fake.removeKeys {
		if k == ref {
			t.Fatalf("RemoveObject must NOT be called for a raw_ref still referenced by a live message (ref=%q)", ref)
		}
	}
	if orphanedRefExists(t, pool, ref) {
		t.Error("stale orphaned_message_blobs row (now referenced) should still be cleared from the queue")
	}
}
