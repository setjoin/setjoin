package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

// fakeLegalHold captures SetLegalHold calls.
type fakeLegalHold struct {
	calls []struct {
		key string
		on  bool
	}
}

func (f *fakeLegalHold) SetLegalHold(_ context.Context, key string, on bool) error {
	f.calls = append(f.calls, struct {
		key string
		on  bool
	}{key, on})
	return nil
}

// TestHoldSelected_SetsObjectLegalHold: holding a message with an attachment
// extends the DB litigation hold to the storage layer via SetLegalHold(hash,true).
func TestHoldSelected_SetsObjectLegalHold(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	const hash = "cafef00d00000000000000000000000000000000000000000000000000000000"

	// 95xxx id range (96xxx owned by admin_ediscovery_test.go).
	exec := func(sql string, args ...any) {
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed %q: %v", sql, err)
		}
	}
	exec(`INSERT INTO domains (id, name, is_local) OVERRIDING SYSTEM VALUE VALUES (95000,'lh.test',TRUE) ON CONFLICT DO NOTHING`)
	exec(`INSERT INTO users (id, username, domain_id, email, display_name, enabled) OVERRIDING SYSTEM VALUE VALUES
		(95001,'lh_u',95000,'u@lh.test','U',TRUE) ON CONFLICT DO NOTHING`)
	exec(`INSERT INTO mailboxes (id, user_id, domain_id, email, display_name, type, is_primary) OVERRIDING SYSTEM VALUE VALUES
		(9500,95001,95000,'u@lh.test','U','personal',TRUE) ON CONFLICT DO NOTHING`)
	t.Cleanup(func() {
		c := context.Background()
		// HoldSelected sets the per-message held flag; release it FIRST or
		// trg_messages_hold_check (BZ015, checks OLD.held) blocks the message
		// DELETE and this fixture leaks into the shared test DB (its hardcoded
		// user id then collides with other suites' fixtures — seen live in
		// chat_ediscovery_read.pg). Then detach the mailbox from the user
		// (user_id NULL + is_primary FALSE, together — else either the
		// mailboxes_shared_not_primary CHECK or trg_mailbox_primary_enforce
		// rejects) so the primary-mailbox trigger doesn't block the deletes.
		pool.Exec(c, `UPDATE messages SET held = FALSE WHERE mailbox_id = 9500`)                                              //nolint:errcheck
		pool.Exec(c, `UPDATE mailboxes SET user_id = NULL, is_primary = FALSE WHERE id = 9500`)                               //nolint:errcheck
		pool.Exec(c, `DELETE FROM message_attachments WHERE message_id IN (SELECT id FROM messages WHERE mailbox_id = 9500)`) //nolint:errcheck
		pool.Exec(c, `DELETE FROM blobs WHERE sha256 = $1`, hash)                                                             //nolint:errcheck
		pool.Exec(c, `DELETE FROM messages WHERE mailbox_id = 9500`)                                                          //nolint:errcheck
		pool.Exec(c, `DELETE FROM users WHERE id = 95001`)                                                                    //nolint:errcheck
		pool.Exec(c, `DELETE FROM mailboxes WHERE id = 9500`)                                                                 //nolint:errcheck
		pool.Exec(c, `DELETE FROM domains WHERE id = 95000`)                                                                  //nolint:errcheck
	})

	var folderID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO folders (mailbox_id, name, role, path) VALUES (9500, 'Inbox', 'inbox', 'Inbox') RETURNING id`,
	).Scan(&folderID); err != nil {
		t.Fatalf("insert folder: %v", err)
	}
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM folders WHERE id = $1`, folderID) }) //nolint:errcheck

	var msgID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO messages (mailbox_id, folder_id, message_id, subject, from_addr, from_name,
		 to_addrs, cc_addrs, bcc_addrs, thread_id, raw_ref, received_at, is_read)
		 VALUES (9500, $1, '<lh-1@lh.test>', 'lh', 'ext@outside.example', 'Ext',
		 '[]'::JSONB, '[]'::JSONB, '[]'::JSONB, 'thread-lh-1', 'inbound/lh-test-raw', '2026-07-06 00:00:00+00', TRUE) RETURNING id`, folderID,
	).Scan(&msgID); err != nil {
		t.Fatalf("insert message: %v", err)
	}

	exec(`INSERT INTO blobs (sha256, minio_ref, size_bytes, content_type, ref_count)
		VALUES ($1, 'ref', 10, 'text/plain', 1) ON CONFLICT DO NOTHING`, hash)
	exec(`INSERT INTO message_attachments (message_id, received_at, blob_sha256, content_type, size_bytes)
		VALUES ($1, '2026-07-06 00:00:00+00', $2, 'text/plain', 10)`, msgID, hash)

	fake := &fakeLegalHold{}
	h := NewEDiscoveryHandler(pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger(), nil, "bucket", fake)

	body, _ := json.Marshal(map[string]any{"ids": []int64{msgID}})
	req := httptest.NewRequest(http.MethodPost, "/admin/ediscovery/hold", strings.NewReader(string(body)))
	req = req.WithContext(auth.ContextWithUser(ctx, &auth.Claims{UserID: 95001}))
	rec := httptest.NewRecorder()
	h.HoldSelected(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("HoldSelected status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if len(fake.calls) != 1 {
		t.Fatalf("expected 1 SetLegalHold call, got %v", fake.calls)
	}
	if fake.calls[0].key != hash || !fake.calls[0].on {
		t.Errorf("SetLegalHold = %v, want {%s true}", fake.calls[0], hash)
	}
}
