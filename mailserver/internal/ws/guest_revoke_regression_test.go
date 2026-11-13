package ws

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"setjoin.com/shared/testsupport"
)

// TestGuestLifecycleStillRevokesSessions is the regression guard the deep-run
// package binds: guest lifecycle transitions keep revoking sessions via
// revoke_user_sessions (guest_account.sql — the guest_set_status
// disable/expire/reinvite arm, scope "all"). Withdrawn guests therefore do NOT
// retain the push rail through the pre-existing teardown, and the ws package's
// new periodic re-validation must never be read as covering (or duplicating)
// that path — it covers only claims.exp expiry and entitlement/permission
// changes that lack any teardown. This test proves the existing teardown is
// intact: a system guest expiry emits a session_revoke NOTIFY covering all
// pre-action sessions of that guest (the payload the ProtocolSessionRegistry
// and shouldPushSessionRevoked consume on the WS/SSE transports).
//
// DB-gated on DB_DSN (e.g.
// postgres://mail@127.0.0.1:5432/mailserver_test?sslmode=disable).
func TestGuestLifecycleStillRevokesSessions(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN not set — skipping DB-gated guest revocation regression test")
	}
	ctx := context.Background()
	pool := testsupport.OpenTestPool(t)

	// Dedicated LISTEN connection (transaction-pool connections cannot LISTEN
	// — same model as internal/db/listen.go and push_channel_test.go).
	listenConn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("pgx.Connect (listen): %v", err)
	}
	defer listenConn.Close(ctx)
	if _, err := listenConn.Exec(ctx, `LISTEN "session_revoke"`); err != nil {
		t.Fatalf(`LISTEN "session_revoke": %v`, err)
	}

	// Host member (the guest's ownership axis) — a distinct test domain keeps
	// the fixture isolated.
	hostEmail := fmt.Sprintf("ws-guest-host-%d@wsreval.example", time.Now().UnixNano())
	var hostID int64
	if err := pool.QueryRow(ctx,
		`SELECT (r->>'user_id')::BIGINT FROM provision_account($1) r`, hostEmail,
	).Scan(&hostID); err != nil {
		t.Fatalf("provision host: %v", err)
	}

	// Guest provisioned ACTIVE with an ALREADY-DUE expiry so the system-expiry
	// actor (guest_set_status(NULL, …, 'expire')) is eligible: it is the one
	// actor-less entrance and lands in the same revoke_user_sessions arm the
	// admin disable action uses (guest_account.sql:522).
	guestEmail := fmt.Sprintf("ws-guest-%d@guest.invalid", time.Now().UnixNano())
	var guestID int64
	if err := pool.QueryRow(ctx,
		`SELECT (r->>'user_id')::BIGINT FROM provision_account(
			$1,
			p_password_hash    => 'starter-hash-not-a-real-credential',
			p_guest            => TRUE,
			p_invited_by       => $2,
			p_guest_expires_at => clock_timestamp() - interval '1 second'
		) r`, guestEmail, hostID,
	).Scan(&guestID); err != nil {
		t.Fatalf("provision guest: %v", err)
	}

	// Fixture teardown: guests are mailbox-less; the guest satellite and both
	// users are plain deletes (chat memberships carry no users FK).
	t.Cleanup(func() {
		cctx := context.Background()
		_, _ = pool.Exec(cctx, `DELETE FROM guest_accounts WHERE user_id = $1`, guestID)
		_, _ = pool.Exec(cctx, `DELETE FROM users WHERE id = $1`, guestID)
		var hostMailboxID, hostDomainID int64
		_ = pool.QueryRow(cctx,
			`SELECT id, domain_id FROM mailboxes WHERE user_id = $1`, hostID).Scan(&hostMailboxID, &hostDomainID)
		// Login-bound satellite rows are trigger-created for the host mailbox
		// and block mailbox/user deletes until removed.
		_, _ = pool.Exec(cctx, `DELETE FROM mailbox_address_claims WHERE mailbox_id = $1`, hostMailboxID)
		_, _ = pool.Exec(cctx, `DELETE FROM mailbox_lifecycle WHERE mailbox_id = $1`, hostMailboxID)
		// Host mailbox teardown: DISABLE-TRIGGER pattern (primary-mailbox
		// triggers block plain deletes — admin_users_test.go).
		_, _ = pool.Exec(cctx, `ALTER TABLE mailboxes DISABLE TRIGGER ALL`)
		_, _ = pool.Exec(cctx, `DELETE FROM mailboxes WHERE user_id = $1`, hostID)
		_, _ = pool.Exec(cctx, `ALTER TABLE mailboxes ENABLE TRIGGER ALL`)
		_, _ = pool.Exec(cctx, `DELETE FROM users WHERE id = $1`, hostID)
		if hostDomainID != 0 {
			_, _ = pool.Exec(cctx,
				`DELETE FROM domains d
				   WHERE d.id = $1
				     AND NOT EXISTS (SELECT 1 FROM mailboxes m WHERE m.domain_id = d.id)
				     AND NOT EXISTS (SELECT 1 FROM users u WHERE u.domain_id = d.id)`,
				hostDomainID)
		}
	})

	// Fire the guest lifecycle transition: system expiry of the due guest.
	if _, err := pool.Exec(ctx,
		`SELECT guest_set_status(NULL, $1, 'expire')`, guestID,
	); err != nil {
		t.Fatalf("guest_set_status(expire): %v", err)
	}

	// The revocation must surface as a scope=all session_revoke NOTIFY — the
	// payload that tears WS/SSE rails down for every pre-action guest session.
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var payload []byte
	for {
		notif, err := listenConn.WaitForNotification(waitCtx)
		if err != nil {
			t.Fatalf("no session_revoke notification within 5s — guest lifecycle teardown regressed: %v", err)
		}
		if notif.Channel != "session_revoke" {
			continue
		}
		payload = []byte(notif.Payload)
		break
	}

	var rev struct {
		UserID int64  `json:"user_id"`
		Scope  string `json:"scope"`
	}
	if err := json.Unmarshal(payload, &rev); err != nil {
		t.Fatalf("decode session_revoke payload %q: %v", payload, err)
	}
	if rev.UserID != guestID || rev.Scope != "all" {
		t.Fatalf("session_revoke payload = {user_id:%d scope:%q}, want {user_id:%d scope:\"all\"} — "+
			"withdrawn-guest teardown must cover all pre-action sessions",
			rev.UserID, rev.Scope, guestID)
	}
}
