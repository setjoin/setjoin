package jmap

import (
	"context"
	"crypto/x509"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/smime"
)

// mail_encrypt_size_db_test.go — SP1 Phase 7 (Task 7.5): quota counts the ENCRYPTED
// artifact size. The submission handler's poolEncryptOps.SignAndEncrypt stores the
// CMS EnvelopedData blob, then updates the draft's size_bytes to len(enc) IN PLACE
// (R3-scoped) so jmap_email_submission_set's fresh v_msg.size_bytes SELECT — which
// runs AFTER the Go pass — charges quota and records size_bytes on the Sent /
// recipient copies against the (larger) ciphertext, never the cleartext draft.
//
// SignAndEncrypt's blob store needs MinIO (no fake in this package), so this test
// exercises the EXACT size-update SQL statement SignAndEncrypt runs against a real
// draft row, proving (a) the cleartext size is replaced by the encrypted-artifact
// size, and (b) R3 ownership scoping (a wrong mailbox_id does NOT update the row).
// Runs in a rolled-back tx (zero residue).

func TestEncryptedDraftSize_UpdatedToCiphertextLength(t *testing.T) {
	if testing.Short() {
		t.Skip("-short: skipping DB-backed encrypted-size update guard")
	}
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set; skipping database-dependent test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect test DB: %v", err)
	}
	t.Cleanup(pool.Close)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	// Seed a domain → user → mailbox → folder → draft message.
	var domainID, userID, mailboxID, folderID int64
	if err := tx.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ('encsize.test', TRUE) RETURNING id`,
	).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	if err := tx.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name, password_hash)
		 VALUES ('encsize', $1, 'encsize@encsize.test', 'Enc Size', 'x') RETURNING id`,
		domainID,
	).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if err := tx.QueryRow(ctx,
		`INSERT INTO mailboxes (user_id, domain_id, email, type, display_name, is_primary)
		 VALUES ($1, $2, 'encsize@encsize.test', 'personal', 'Enc Size', TRUE) RETURNING id`,
		userID, domainID,
	).Scan(&mailboxID); err != nil {
		t.Fatalf("insert mailbox: %v", err)
	}
	if err := tx.QueryRow(ctx,
		`INSERT INTO folders (mailbox_id, name, path, role) VALUES ($1, 'Drafts', 'Drafts', 'drafts') RETURNING id`,
		mailboxID,
	).Scan(&folderID); err != nil {
		t.Fatalf("insert folder: %v", err)
	}

	// Cleartext draft: size_bytes is the CLEARTEXT size (the bug we fix charges this).
	const cleartextSize = int64(120)
	recv := time.Now()
	var draftID int64
	if err := tx.QueryRow(ctx,
		`INSERT INTO messages (mailbox_id, folder_id, imap_uid, message_id, subject,
		    from_addr, to_addrs, cc_addrs, bcc_addrs, body_text, size_bytes, thread_id,
		    raw_ref, received_at, is_read)
		 VALUES ($1, $2, 1, 'encsize-draft', 'Quota subj', 'encsize@encsize.test',
		         '[]'::jsonb, '[]'::jsonb, '[]'::jsonb, 'cleartext body', $3, 'thr-encsize',
		         'cleartext-ref', $4, TRUE)
		 RETURNING id`,
		mailboxID, folderID, cleartextSize, recv,
	).Scan(&draftID); err != nil {
		t.Fatalf("insert draft: %v", err)
	}

	// Compute a REAL encrypted-artifact length for an actual recipient cert, so the
	// asserted size is the genuine CMS-blob size, not an arbitrary constant.
	cand := genCapableCertPEM(t, "rcpt@ext.test")
	cert, err := smime.ParseCert([]byte(cand))
	if err != nil {
		t.Fatalf("ParseCert: %v", err)
	}
	enc, err := smime.Encrypt([]byte("From: encsize@encsize.test\r\nSubject: Quota subj\r\n\r\ncleartext body\r\n"),
		[]*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	encSize := int64(len(enc))
	if encSize <= cleartextSize {
		t.Fatalf("test invariant broken: encrypted size %d not > cleartext size %d", encSize, cleartextSize)
	}

	// R3 negative arm: a WRONG mailbox_id must NOT touch the row (ownership in WHERE).
	if _, err := tx.Exec(ctx,
		`UPDATE messages SET size_bytes = $1 WHERE id = $2 AND mailbox_id = $3`,
		encSize, draftID, mailboxID+999999,
	); err != nil {
		t.Fatalf("R3 negative UPDATE errored: %v", err)
	}
	assertSize(t, ctx, tx, draftID, cleartextSize, "R3: wrong mailbox_id must NOT update size")

	// The EXACT statement poolEncryptOps.SignAndEncrypt runs after storing the blob.
	if _, err := tx.Exec(ctx,
		`UPDATE messages SET size_bytes = $1 WHERE id = $2 AND mailbox_id = $3`,
		encSize, draftID, mailboxID,
	); err != nil {
		t.Fatalf("size UPDATE errored: %v", err)
	}
	assertSize(t, ctx, tx, draftID, encSize,
		"encrypted draft size_bytes must be the ciphertext length (not the cleartext)")
}

func assertSize(t *testing.T, ctx context.Context, tx pgx.Tx, draftID, want int64, msg string) {
	t.Helper()
	var got int64
	if err := tx.QueryRow(ctx,
		`SELECT size_bytes FROM messages WHERE id = $1`, draftID,
	).Scan(&got); err != nil {
		t.Fatalf("read size_bytes: %v", err)
	}
	if got != want {
		t.Errorf("%s: got size_bytes=%d, want %d", msg, got, want)
	}
}
