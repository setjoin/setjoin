package jmap

// blob_download_test.go — the #13 shared-mailbox USE-surface Download proof:
// blobDownloadAuthorized (blob.go) admits a delegate holding ANY mail grant
// (read|send_as|send_on_behalf|full_access) to download an attachment stored
// in the SHARED mailbox, mirrors Upload's gateRead check (a33c315c), stays
// fail-closed on revocation, and never widens the caller's OWN-mailbox check.
//
// Needs DB_DSN (skipped otherwise), like the other _db tests — it exercises
// insertTestSharedMailbox/grantDelegate/revokeDelegate from
// handler_delegate_test.go plus a real message+attachment+blob row.

import (
	"context"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/pgxutil"
)

// insertTestMessageWithAttachment inserts one message into mailboxID (folder_id
// is a legacy, unconstrained column — any placeholder value satisfies NOT NULL)
// plus a blobs row and a message_attachments row linking them. Returns the
// blob's sha256 (a random hex stand-in — content bytes are irrelevant to the
// authorization check under test).
func insertTestMessageWithAttachment(t *testing.T, pool *pgxpool.Pool, mailboxID int64) string {
	t.Helper()
	ctx := context.Background()
	suffix := randomSuffixDB(t)

	var msgID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO messages
		   (mailbox_id, folder_id, message_id, subject, from_addr, to_addrs,
		    cc_addrs, bcc_addrs, thread_id, raw_ref, received_at)
		 VALUES
		   ($1, 1, $2, 'Attachment test', 'sender@example.com', '[]'::jsonb,
		    '[]'::jsonb, '[]'::jsonb, $3, $4, now())
		 RETURNING id`,
		mailboxID,
		"<blob-dl-"+suffix+"@example.com>",
		"thread-blob-dl-"+suffix,
		"raw/blob-dl/"+suffix,
	).Scan(&msgID); err != nil {
		t.Fatalf("insert test message: %v", err)
	}

	blobSha := "deadbeef" + suffix + "00000000000000000000000000000000000000000000000000"
	blobSha = blobSha[:64]
	if _, err := pool.Exec(ctx,
		`INSERT INTO blobs (sha256, minio_ref, size_bytes, content_type, ref_count)
		 VALUES ($1, $2, 10, 'text/plain', 1)`,
		blobSha, "test-bucket/"+blobSha,
	); err != nil {
		t.Fatalf("insert test blob: %v", err)
	}

	if _, err := pool.Exec(ctx,
		`INSERT INTO message_attachments (message_id, received_at, blob_sha256, filename, content_type, size_bytes)
		 SELECT $1, received_at, $2, 'file.txt', 'text/plain', 10 FROM messages WHERE id = $1`,
		msgID, blobSha,
	); err != nil {
		t.Fatalf("insert test attachment: %v", err)
	}

	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM message_attachments WHERE blob_sha256 = $1`, blobSha) //nolint:errcheck
		pool.Exec(context.Background(), `DELETE FROM messages WHERE id = $1`, msgID)                       //nolint:errcheck
		pool.Exec(context.Background(), `DELETE FROM blobs WHERE sha256 = $1`, blobSha)                    //nolint:errcheck
	})
	return blobSha
}

// TestBlobDownloadAuthorized_OwnMailbox pins the pre-existing behavior
// unchanged by the #13 widening: a user downloads their OWN mail's attachment
// with no accountId at all (mirrors the historical Download call shape).
func TestBlobDownloadAuthorized_OwnMailbox(t *testing.T) {
	pool := testPoolDB(t)
	h := NewJMAPHandler(pool, pgxutil.WorkerPool{Pool: pool}, "localhost", nil, "test-bucket", 10_000_000, testLoggerDB(t))
	ctx := context.Background()

	_, userID, mailboxID := insertTestUserWithMailbox(t, pool, false)
	blobSha := insertTestMessageWithAttachment(t, pool, mailboxID)

	if !h.blobDownloadAuthorized(ctx, "", blobSha, userID) {
		t.Error("own mailbox, no accountId: denied, want authorized")
	}
	if !h.blobDownloadAuthorized(ctx, "not-a-number", blobSha, userID) {
		t.Error("own mailbox, garbage accountId: denied, want authorized (degrades to own-mailbox-only)")
	}
}

// TestBlobDownloadAuthorized_DelegateArm is the (d) W2 proof the a33c315c
// commit flagged as deferred: EVERY mail grant level admits download of the
// SHARED mailbox's attachments, a grant-less caller is denied, and revocation
// is effective on the very next check (per-request/uncached, like parseAccountID).
func TestBlobDownloadAuthorized_DelegateArm(t *testing.T) {
	pool := testPoolDB(t)
	h := NewJMAPHandler(pool, pgxutil.WorkerPool{Pool: pool}, "localhost", nil, "test-bucket", 10_000_000, testLoggerDB(t))
	ctx := context.Background()

	_, userID, _ := insertTestUserWithMailbox(t, pool, false)
	sharedID, _ := insertTestSharedMailbox(t, pool)
	blobSha := insertTestMessageWithAttachment(t, pool, sharedID)
	acctStr := strconv.FormatInt(sharedID, 10)

	// No grant at all: denied.
	if h.blobDownloadAuthorized(ctx, acctStr, blobSha, userID) {
		t.Fatal("no delegate grant: authorized, want denied")
	}

	for _, grant := range []string{"read", "send_as", "send_on_behalf", "full_access"} {
		t.Run(grant, func(t *testing.T) {
			revokeDelegate(t, pool, sharedID, userID)
			grantDelegate(t, pool, sharedID, userID, grant)
			if !h.blobDownloadAuthorized(ctx, acctStr, blobSha, userID) {
				t.Errorf("grant=%s: denied, want authorized (any mail grant admits download)", grant)
			}
		})
	}

	// manage_calendar is NOT a mail grant (mirrors the gate-matrix invariant) — denied.
	revokeDelegate(t, pool, sharedID, userID)
	grantDelegate(t, pool, sharedID, userID, "manage_calendar")
	if h.blobDownloadAuthorized(ctx, acctStr, blobSha, userID) {
		t.Error("manage_calendar-only grant: authorized, want denied (not a mail grant)")
	}

	// Revoked mid-session: the very next check denies (per-request, uncached).
	revokeDelegate(t, pool, sharedID, userID)
	grantDelegate(t, pool, sharedID, userID, "full_access")
	if !h.blobDownloadAuthorized(ctx, acctStr, blobSha, userID) {
		t.Fatal("granted full_access: denied, want authorized")
	}
	revokeDelegate(t, pool, sharedID, userID)
	if h.blobDownloadAuthorized(ctx, acctStr, blobSha, userID) {
		t.Error("revoked mid-session: still authorized on the next check, want denied")
	}
}

// TestBlobDownloadAuthorized_NoCrossTenantLeak pins the negative: a bystander
// with no grant AND no ownership of the message's mailbox is denied even when
// they DO own some other unrelated mailbox (delegatedMailboxID only ever
// widens access to the ONE accountId the caller actually validated for).
func TestBlobDownloadAuthorized_NoCrossTenantLeak(t *testing.T) {
	pool := testPoolDB(t)
	h := NewJMAPHandler(pool, pgxutil.WorkerPool{Pool: pool}, "localhost", nil, "test-bucket", 10_000_000, testLoggerDB(t))
	ctx := context.Background()

	_, bystanderID, _ := insertTestUserWithMailbox(t, pool, false)
	sharedID, _ := insertTestSharedMailbox(t, pool)
	blobSha := insertTestMessageWithAttachment(t, pool, sharedID)

	if h.blobDownloadAuthorized(ctx, strconv.FormatInt(sharedID, 10), blobSha, bystanderID) {
		t.Error("bystander with no grant: authorized, want denied")
	}
}
