package admin

// Regression tests for the admin quarantine Release/Reject handlers.
//
// Two defects fixed here (both from copy-pasting the user self-service handler
// into what the W7 note documents as a CROSS-TENANT admin surface):
//
//  1. False-success: Release routed through a helper that swallowed the
//     UPDATE...RETURNING no-match error and the handler then ALWAYS wrote
//     200 {"status":"released"} — a wrong or already-processed id reported
//     success while nothing happened.
//  2. Wrong scope: both Release and Reject carried a
//     `mailbox_id IN (SELECT id FROM mailboxes WHERE user_id = <admin>)`
//     self-predicate, so an admin could only act on quarantined messages in
//     their OWN mailboxes — never another user's — contradicting the org-wide
//     requireMailPerm cross-tenant contract. Combined with (1), an admin
//     "releasing" any other user's message got a silent 200 no-op.
//
// Both are covered: TestAdminQuarantine_BogusID_404 locks the affected-row
// check; TestAdminQuarantine_CrossTenantRelease locks the cross-tenant scope.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

// TestAdminQuarantine_BogusID_404 proves Release and Reject 404 on a
// non-existent id instead of falsely reporting success. Before the fix Release
// returned 200 {"status":"released"} for ANY id.
func TestAdminQuarantine_BogusID_404(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewQuarantineHandler(pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())

	adminCtx := auth.ContextWithUser(context.Background(), &auth.Claims{UserID: 1, IsAdmin: true})
	const bogus = "999999999"

	for _, tc := range []struct {
		name string
		fn   http.HandlerFunc
	}{
		{"release", h.Release},
		{"reject", h.Reject},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/admin/quarantine/"+bogus+"/"+tc.name, nil).
				WithContext(adminCtx)
			req.SetPathValue("id", bogus)
			rec := httptest.NewRecorder()
			tc.fn(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("%s of a non-existent quarantine id: want 404, got %d (%s)",
					tc.name, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestAdminQuarantine_CrossTenantRelease proves an admin can release a message
// quarantined in ANOTHER user's mailbox, and that the row is actually marked
// released (affected-row check). Before the fix the self-scope predicate matched
// 0 rows for a foreign mailbox, so released_at stayed NULL while Release still
// returned 200.
func TestAdminQuarantine_CrossTenantRelease(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewQuarantineHandler(pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())
	ctx := context.Background()

	// Victim mailbox/user (owns the quarantined message) and a DISTINCT admin user.
	var victimMB, adminMB, adminUser int64
	if err := pool.QueryRow(ctx, `SELECT mk_account('adminq_victim')`).Scan(&victimMB); err != nil {
		t.Fatalf("seed victim mailbox: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT mk_account('adminq_admin')`).Scan(&adminMB); err != nil {
		t.Fatalf("seed admin mailbox: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT user_id FROM mailboxes WHERE id = $1`, adminMB).Scan(&adminUser); err != nil {
		t.Fatalf("resolve admin user: %v", err)
	}

	// Quarantined tag (quarantine group) + an Inbox message, then quarantine it.
	if _, err := pool.Exec(ctx,
		`INSERT INTO tags (mailbox_id, name, tag_type, exclusive_group)
		   VALUES ($1, 'Quarantined', 'system', 'quarantine')`, victimMB); err != nil {
		t.Fatalf("seed Quarantined tag: %v", err)
	}
	var msgID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO messages (mailbox_id, folder_id, message_id, subject, from_addr,
		     size_bytes, thread_id, raw_ref, received_at, is_read)
		 VALUES ($1, get_tag_id('Inbox', $1), '<aq1@mk.test>', 'Msg', 'x@ext.com',
		     100, 'thr-aq1', 'raw-aq1', now(), FALSE)
		 RETURNING id`, victimMB).Scan(&msgID); err != nil {
		t.Fatalf("seed message: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`SELECT tag_message($1, (SELECT received_at FROM messages WHERE id = $1),
		     'Inbox', $2, 'deliver', TRUE)`, msgID, victimMB); err != nil {
		t.Fatalf("tag message Inbox: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`SELECT quarantine_message($1, $2, 'test', 'virus', NULL, FALSE)`, msgID, victimMB); err != nil {
		t.Fatalf("quarantine message: %v", err)
	}
	var qid int64
	if err := pool.QueryRow(ctx,
		`SELECT id FROM quarantined_messages WHERE message_id = $1`, msgID).Scan(&qid); err != nil {
		t.Fatalf("resolve quarantine id: %v", err)
	}

	// Admin (a DIFFERENT user from the victim) releases the message.
	adminCtx := auth.ContextWithUser(ctx, &auth.Claims{UserID: adminUser, IsAdmin: true})
	req := httptest.NewRequest(http.MethodPost, "/admin/quarantine/"+strconv.FormatInt(qid, 10)+"/release", nil).
		WithContext(adminCtx)
	req.SetPathValue("id", strconv.FormatInt(qid, 10))
	rec := httptest.NewRecorder()
	h.Release(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("cross-tenant release: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var resp map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["status"] != "released" {
		t.Fatalf("want status released, got %v", resp)
	}

	// The row must actually be marked released BY THE ADMIN — not a 200 no-op.
	var releasedBy *int64
	if err := pool.QueryRow(ctx,
		`SELECT released_by FROM quarantined_messages WHERE id = $1 AND released_at IS NOT NULL`,
		qid).Scan(&releasedBy); err != nil {
		t.Fatalf("quarantine row not marked released (false-success/scope bug): %v", err)
	}
	if releasedBy == nil || *releasedBy != adminUser {
		t.Fatalf("released_by: want admin %d, got %v", adminUser, releasedBy)
	}
}
