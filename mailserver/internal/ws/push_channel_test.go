package ws

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestPushChannelMatchesMailboxNotProducer is the regression guard for the
// real-time-push contract (the user_id-vs-mailbox_id channel-mismatch bug
// class). Every reducer emits its push on "tag:{mailbox_id}"
// (notify_state_change.sql) — the MAILBOX id. The WS handler historically
// subscribed to "tag:{user_id}" — the USER id. Per ADR-003, users.id and
// mailboxes.id are independent BIGSERIAL sequences, so in production
// (user_id != mailbox_id) the channels never matched and the webmail received
// NO state-change pushes. This test pins the contract:
//
//   - It provisions an account with DIVERGENT ids (user_id != mailbox_id),
//     the ADR-003 discipline that de-masks this entire bug class.
//   - It resolves the subscribe channel EXACTLY as ws/handler.go now does
//     (SELECT id FROM mailboxes WHERE user_id=$1 AND is_primary — i.e. the
//     primary MAILBOX id, the parseAccountID/GetAccountID currency).
//   - It calls the producer (notify_state_change, the single owner of the
//     bump+push side-effect) and asserts the mailbox-keyed channel RECEIVES
//     the notification while the user-keyed channel (the OLD buggy
//     subscription) receives NOTHING.
//
// Against the old `tag:{user_id}` handler this asserts a notification on a
// channel nothing was emitting to → the receive would time out → FAIL.
// Against the fixed `tag:{mailbox_id}` handler it PASSES.
//
// DB-gated on DB_DSN (e.g.
// postgres://mail@127.0.0.1:5432/mailserver_test?sslmode=disable).
func TestPushChannelMatchesMailboxNotProducer(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN not set — skipping DB-gated push-channel regression test")
	}
	ctx := context.Background()

	// A separate raw connection for LISTEN (transaction-pool connections cannot
	// LISTEN; a dedicated pgx.Conn is the same model as internal/db/listen.go).
	listenConn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("pgx.Connect (listen): %v", err)
	}
	defer listenConn.Close(ctx)

	// A second connection issues the NOTIFY-producing call (a LISTEN-ing
	// session does not deliver its own NOTIFY synchronously via
	// WaitForNotification in all drivers; use a distinct session to be safe).
	emitConn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("pgx.Connect (emit): %v", err)
	}
	defer emitConn.Close(ctx)

	// --- Force DIVERGENT ids (user_id != mailbox_id) by construction ----------
	// users.id and mailboxes.id are independent BIGSERIAL sequences (ADR-003),
	// but on a freshly loaded DB they can be coincidentally aligned (both low) —
	// which is exactly the masking condition this bug class hides behind. Push
	// the mailbox-id sequence well ahead of the users sequence BEFORE
	// provisioning so the next mailbox gets an id ~500000 above the user id,
	// guaranteeing divergence regardless of prior sequence state. (Same
	// discipline as tests/provision_account.pg.)
	if _, err := emitConn.Exec(ctx,
		`SELECT setval('mailboxes_id_seq',
		                GREATEST(nextval('mailboxes_id_seq'),
		                         nextval('users_id_seq') + 500000))`,
	); err != nil {
		t.Fatalf("force divergent sequences: %v", err)
	}

	// --- Provision a DIVERGENT-id account (user_id != mailbox_id) -------------
	// provision_account is the canonical provisioning seam.
	email := fmt.Sprintf("ws-push-regression-%d@example.com", time.Now().UnixNano())
	var userID, mailboxID int64
	if err := emitConn.QueryRow(ctx,
		`SELECT (r->>'user_id')::BIGINT, (r->>'mailbox_id')::BIGINT
		   FROM provision_account($1) r`,
		email,
	).Scan(&userID, &mailboxID); err != nil {
		t.Fatalf("provision_account: %v", err)
	}
	if userID == 0 || mailboxID == 0 {
		t.Fatalf("provision_account returned zero ids: user_id=%d mailbox_id=%d", userID, mailboxID)
	}

	// Clean up the provisioned rows so this test leaves the shared
	// mailserver_test DB exactly as it found it. The pgTAP suite has
	// count/union-based assertions (gal_search, directory, domains) that share
	// this DB; leaving residue would make a subsequent `pg_prove` run flap.
	t.Cleanup(func() {
		// Use a fresh short-lived connection: the test's emitConn/listenConn are
		// torn down by their own defers before t.Cleanup runs (defers run LIFO
		// at function return, t.Cleanup runs after), so they cannot be relied on
		// here.
		cctx := context.Background()
		cc, err := pgx.Connect(cctx, dsn)
		if err != nil {
			return
		}
		defer cc.Close(cctx)
		var domainID int64
		_ = cc.QueryRow(cctx, `SELECT domain_id FROM mailboxes WHERE id = $1`, mailboxID).Scan(&domainID)
		// Teardown order matters: a primary mailbox can't be deleted while its
		// user still exists (trg_mailbox_primary_enforce), and a NULL-user
		// mailbox can't stay is_primary (CHECK mailboxes_shared_not_primary).
		// So in one txn: detach (is_primary=FALSE, user_id=NULL) → drop mailbox
		// → drop user → drop the auto-created domain if now empty.
		tx, err := cc.Begin(cctx)
		if err != nil {
			return
		}
		defer tx.Rollback(cctx)
		if _, err := tx.Exec(cctx,
			`UPDATE mailboxes SET is_primary = FALSE, user_id = NULL WHERE id = $1`, mailboxID); err != nil {
			return
		}
		if _, err := tx.Exec(cctx, `DELETE FROM mailboxes WHERE id = $1`, mailboxID); err != nil {
			return
		}
		if _, err := tx.Exec(cctx, `DELETE FROM users WHERE id = $1`, userID); err != nil {
			return
		}
		if domainID != 0 {
			// Only remove the domain if nothing else references it (don't touch
			// a domain that pre-existed and is shared by other fixtures).
			_, _ = tx.Exec(cctx,
				`DELETE FROM domains d
				   WHERE d.id = $1
				     AND NOT EXISTS (SELECT 1 FROM mailboxes m WHERE m.domain_id = d.id)
				     AND NOT EXISTS (SELECT 1 FROM users u WHERE u.domain_id = d.id)`,
				domainID)
		}
		_ = tx.Commit(cctx)
	})

	// De-masking precondition: this whole bug class is invisible when ids
	// coincide. If they ever coincided here the test would not be exercising
	// the bug, so assert divergence explicitly.
	if userID == mailboxID {
		t.Fatalf("fixture not divergent: user_id == mailbox_id == %d (cannot exercise the bug)", userID)
	}

	// --- Resolve the subscribe channel EXACTLY as ws/handler.go now does ------
	// (GetAccountID: SELECT id FROM mailboxes WHERE user_id=$1 AND is_primary)
	var resolvedMailboxID int64
	if err := emitConn.QueryRow(ctx,
		`SELECT id FROM mailboxes WHERE user_id = $1 AND is_primary = TRUE LIMIT 1`,
		userID,
	).Scan(&resolvedMailboxID); err != nil {
		t.Fatalf("resolve primary mailbox: %v", err)
	}
	if resolvedMailboxID != mailboxID {
		t.Fatalf("resolved primary mailbox %d != provisioned mailbox %d", resolvedMailboxID, mailboxID)
	}

	correctChannel := fmt.Sprintf("tag:%d", resolvedMailboxID) // what the handler now subscribes to
	buggyChannel := fmt.Sprintf("tag:%d", userID)              // the OLD (user-keyed) subscription

	// LISTEN on both the correct (mailbox-keyed) and the old (user-keyed) channels.
	if _, err := listenConn.Exec(ctx, `LISTEN "`+correctChannel+`"`); err != nil {
		t.Fatalf("LISTEN %s: %v", correctChannel, err)
	}
	if _, err := listenConn.Exec(ctx, `LISTEN "`+buggyChannel+`"`); err != nil {
		t.Fatalf("LISTEN %s: %v", buggyChannel, err)
	}

	// --- Fire the producer: notify_state_change emits on tag:{mailbox_id} -----
	if _, err := emitConn.Exec(ctx, `SELECT notify_state_change($1, NULL)`, mailboxID); err != nil {
		t.Fatalf("notify_state_change: %v", err)
	}

	// --- Assert the notification arrives on the MAILBOX-keyed channel ---------
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	notif, err := listenConn.WaitForNotification(waitCtx)
	if err != nil {
		t.Fatalf("did NOT receive a notification on the subscribed channel within 5s "+
			"(this is the bug: producer emits on %q, consumer subscribed to that channel): %v",
			correctChannel, err)
	}
	if notif.Channel != correctChannel {
		t.Fatalf("notification on %q, want %q — producer and consumer disagree on the channel id",
			notif.Channel, correctChannel)
	}

	// --- Assert NOTHING further arrives on the user-keyed channel -------------
	// The producer must NOT emit on tag:{user_id}; with divergent ids the old
	// subscription would be silent. Drain briefly to prove no stray delivery.
	drainCtx, drainCancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer drainCancel()
	if extra, derr := listenConn.WaitForNotification(drainCtx); derr == nil {
		t.Fatalf("unexpected extra notification on channel %q (producer should only emit on the mailbox-keyed channel)",
			extra.Channel)
	}
}
