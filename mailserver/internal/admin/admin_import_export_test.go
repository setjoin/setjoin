package admin

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http/httptest"
	"strconv"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

// TestImportWritesAudit verifies the admin mailbox-import handler records an audit
// row for the action (mailbox id, file, count) via the audit_write choke point.
// An empty .mbox imports 0 messages without ever touching MinIO, so minio can be
// nil — the audit still fires (the action happened regardless of count).
func TestImportWritesAudit(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	domainID := ensureMailboxTestDomain(t, pool)
	userID := createMailboxTestUser(t, pool, domainID) // also the actor
	mbID := createPersonalMailbox(t, pool, userID, domainID)
	// Round 2: the seam resolves authority from admin_role_assignments — a
	// caller with no assignment is no longer waved through by an absent
	// context scope. Grant the actor a genuinely global assignment so the
	// audit assertion (this test's subject) is exercised on the allowed path.
	var helpDeskID int64
	if err := pool.QueryRow(context.Background(),
		`SELECT id FROM admin_role_groups WHERE name = 'Help Desk' LIMIT 1`,
	).Scan(&helpDeskID); err != nil {
		t.Fatalf("lookup Help Desk role: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by)
		 VALUES ($1, $2, $1)
		 ON CONFLICT (user_id, role_group_id) DO NOTHING`, userID, helpDeskID); err != nil {
		t.Fatalf("seed actor assignment: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(),
			`DELETE FROM admin_role_assignments WHERE user_id = $1 AND role_group_id = $2`, userID, helpDeskID) // nolint:errcheck
		pool.Exec(context.Background(),
			`DELETE FROM admin_audit_log WHERE action = 'mailbox.import' AND target_id = $1`, mbID) // nolint:errcheck
	})

	// Multipart body with an empty .mbox (whitespace only → 0 messages, no MinIO).
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreateFormFile("file", "empty.mbox")
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	fw.Write([]byte("   \n  \n"))
	mw.Close()

	req := httptest.NewRequest("POST", "/admin/mailboxes/0/import", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.SetPathValue("id", strconv.FormatInt(mbID, 10))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	w := httptest.NewRecorder()

	h := NewImportExportHandler(nil, pgxutil.WorkerPool{Pool: pool}, "", testsupport.TestLogger())
	h.Import(w, req)

	if w.Code != 200 {
		t.Fatalf("Import status = %d, want 200; body=%s", w.Code, w.Body.String())
	}

	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_audit_log
		  WHERE action = 'mailbox.import' AND target_id = $1 AND user_id = $2`,
		mbID, userID).Scan(&n); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if n != 1 {
		t.Fatalf("mailbox.import audit rows = %d, want 1", n)
	}
}
