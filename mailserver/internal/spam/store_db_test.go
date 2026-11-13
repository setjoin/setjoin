package spam

// store_db_test.go — regression guard for PGModelStore.FetchMessage's
// cross-tenant scoping. FetchMessage runs on the BYPASSRLS worker pool (the
// spam trainer is a cross-tenant background job), so the ONLY thing standing
// between "read your own mail" and "read anyone's mail" is the
// `mb.user_id = $2` predicate in its query — there is no RLS backstop here.
// This test proves that predicate actually holds: tenant A's userID cannot
// fetch tenant B's message, even though the message row itself is fully
// visible on this pool.
//
// Needs DB_DSN (testsupport.OpenTestPool skips locally / fails in CI per the
// fail-closed policy — see shared/testsupport/pool.go).

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

// insertSpamTestUserWithMailbox creates a fresh domain+user+primary-mailbox
// and returns (userID, mailboxID). Mirrors jmap's insertTestUserWithMailbox
// but kept local — the spam package has no existing DB test helpers to share.
//
// Cleanup deletes the mailbox and user in ONE transaction (mailbox row first,
// user row second, matching V085's own comment: "mailboxes go before the
// users row for FK reasons"). mailboxes.user_id is ON DELETE SET NULL, which
// immediately trips the mailboxes_shared_not_primary CHECK constraint on a
// primary mailbox if the user row goes first; and mailbox_primary_enforce_delete
// is a DEFERRED constraint trigger that requires the user to already be gone
// by COMMIT. Two separate autocommit statements satisfy neither ordering —
// only one transaction with mailbox-then-user does.
func insertSpamTestUserWithMailbox(t *testing.T, pool *pgxpool.Pool, label string) (userID, mailboxID int64) {
	t.Helper()
	ctx := context.Background()

	var domainID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name) VALUES ($1) RETURNING id`,
		"spam-test-"+label+".example.com",
	).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}

	email := label + "@spam-test-" + label + ".example.com"
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name, password_hash)
		 VALUES ($1, $2, $3, 'Test User', 'x') RETURNING id`,
		label, domainID, email,
	).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	if err := pool.QueryRow(ctx,
		`INSERT INTO mailboxes (user_id, domain_id, email, type, display_name, is_primary)
		 VALUES ($1, $2, $3, 'personal', 'Test User', TRUE) RETURNING id`,
		userID, domainID, email,
	).Scan(&mailboxID); err != nil {
		t.Fatalf("insert mailbox: %v", err)
	}

	t.Cleanup(func() {
		cctx := context.Background()
		tx, err := pool.Begin(cctx)
		if err != nil {
			t.Errorf("cleanup begin tx: %v", err)
			return
		}
		defer tx.Rollback(cctx) //nolint:errcheck
		// mailbox_lifecycle rows bind the user (bound_user_id FK) and the
		// mailbox; delete them first or the deletes below fail and strand
		// the whole fixture (blocking the fixed-name domain on the next run).
		if _, err := tx.Exec(cctx, `DELETE FROM mailbox_lifecycle WHERE mailbox_id = $1`, mailboxID); err != nil {
			t.Errorf("cleanup delete mailbox_lifecycle: %v", err)
			return
		}
		if _, err := tx.Exec(cctx, `DELETE FROM user_spam_model WHERE user_id = $1`, userID); err != nil {
			t.Errorf("cleanup delete user_spam_model: %v", err)
			return
		}
		if _, err := tx.Exec(cctx, `DELETE FROM mailboxes WHERE id = $1`, mailboxID); err != nil {
			t.Errorf("cleanup delete mailbox: %v", err)
			return
		}
		if _, err := tx.Exec(cctx, `DELETE FROM users WHERE id = $1`, userID); err != nil {
			t.Errorf("cleanup delete user: %v", err)
			return
		}
		if _, err := tx.Exec(cctx, `DELETE FROM domains WHERE id = $1`, domainID); err != nil {
			t.Errorf("cleanup delete domain: %v", err)
			return
		}
		if err := tx.Commit(cctx); err != nil {
			t.Errorf("cleanup commit: %v", err)
		}
	})
	return userID, mailboxID
}

// TestFetchMessage_NoCrossTenantRead pins the security-relevant behavior of
// the mb.user_id = $2 predicate: tenant A cannot fetch a message that lives in
// tenant B's mailbox. A positive control (tenant B fetching its own message)
// proves the denial is the ownership check firing, not a broken query.
func TestFetchMessage_NoCrossTenantRead(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	tenantAUserID, _ := insertSpamTestUserWithMailbox(t, pool, "tenanta")
	tenantBUserID, tenantBMailboxID := insertSpamTestUserWithMailbox(t, pool, "tenantb")

	// raw_ref carries a newline so blob.IsInlineMessage treats it as the
	// inline RFC 5322 text itself — FetchMessage returns it directly with no
	// object-store round trip, so this test needs no minio client.
	const rawContent = "From: bob@tenantb.example.com\r\nSubject: secret\r\n\r\nbody"
	var messageID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO messages
		   (mailbox_id, folder_id, message_id, subject, from_addr, to_addrs,
		    cc_addrs, bcc_addrs, thread_id, raw_ref, received_at)
		 VALUES
		   ($1, 1, 'tenant-b-msg@example.com', 'secret', 'bob@tenantb.example.com',
		    '[]'::jsonb, '[]'::jsonb, '[]'::jsonb, 'thread-tenant-b', $2, now())
		 RETURNING id`,
		tenantBMailboxID, rawContent,
	).Scan(&messageID); err != nil {
		t.Fatalf("insert test message: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM messages WHERE id = $1`, messageID) //nolint:errcheck
	})

	store := NewPGModelStore(pgxutil.WorkerPool{Pool: pool}, nil, "unused-bucket")

	// Negative: tenant A's userID against tenant B's message → no cross-tenant read.
	if data, err := store.FetchMessage(ctx, tenantAUserID, messageID); err == nil {
		t.Fatalf("tenant A fetched tenant B's message: got %d bytes, want not-found error", len(data))
	}

	// Positive control: tenant B fetching its own message succeeds and
	// returns the exact bytes — proves the above denial is the ownership
	// predicate, not a query/schema mistake.
	data, err := store.FetchMessage(ctx, tenantBUserID, messageID)
	if err != nil {
		t.Fatalf("tenant B fetch own message: %v", err)
	}
	if !strings.Contains(string(data), "secret") {
		t.Errorf("fetched content = %q, want to contain original raw message", data)
	}
}
