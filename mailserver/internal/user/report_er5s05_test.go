package user

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
)

// seedOwnedMessage inserts a message row owned by the mailbox and returns its
// id (mirrors insertTestMessage from recall_test.go, with cleanup).
func seedOwnedMessage(t *testing.T, pool *pgxpool.Pool, mailboxID int64) int64 {
	t.Helper()
	ctx := context.Background()
	var id int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO messages (mailbox_id, folder_id, message_id, subject, from_addr, received_at, raw_ref, thread_id)
		 VALUES ($1, 1, $2, 'Test Subject', 'sender@setjoin.test', now(), '', $2)
		 RETURNING id`,
		mailboxID, fmt.Sprintf("report-er5s05-%d", time.Now().UnixNano()),
	).Scan(&id); err != nil {
		t.Fatalf("seedOwnedMessage: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM messages WHERE id = $1`, id)
	})
	return id
}

func postReportE5(t *testing.T, h *ReportHandler, userID int64, emailID, reportType string) *httptest.ResponseRecorder {
	t.Helper()
	body := reportRequest{EmailID: emailID, Type: reportType}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/report", bytes.NewReader(b))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID: userID, Email: "report-test@setjoin.test", Type: auth.TypeAccess,
	}))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.Report(rec, req)
	return rec
}

// TestReportHandler_RejectsForeignMessage pins the legacy-report ownership
// bound (occ_14a2cc946fd2f175bbb779e9): a caller can no longer attach ANOTHER
// user's message ID to a report — the audit row and the spam-training signal
// are both refused, and the foreign id reads as a plain 404 (no existence
// oracle).
func TestReportHandler_RejectsForeignMessage(t *testing.T) {
	pool := testPool(t)
	trainer := &fakeSpamEnqueuer{}
	h := NewReportHandler(pool, testLogger(), trainer)

	ownerID, ownerMB := seedUserWithMailbox(t, pool)
	reporterID, _ := seedUserWithMailbox(t, pool)
	foreignID := seedOwnedMessage(t, pool, ownerMB)

	before := auditReportCount(t, pool, reporterID, foreignID)
	rec := postReportE5(t, h, reporterID, fmt.Sprintf("%d", foreignID), "spam")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("foreign-message report returned %d, want 404: %s", rec.Code, rec.Body.String())
	}
	if after := auditReportCount(t, pool, reporterID, foreignID); after != before {
		t.Errorf("audit rows written for a foreign message: before=%d after=%d", before, after)
	}
	if len(trainer.calls) != 0 {
		t.Errorf("trainer enqueued %d samples from a foreign-message report, want 0", len(trainer.calls))
	}

	// The owner still can report the same message.
	rec = postReportE5(t, h, ownerID, fmt.Sprintf("%d", foreignID), "spam")
	if rec.Code != http.StatusCreated {
		t.Fatalf("owner report of own message returned %d, want 201: %s", rec.Code, rec.Body.String())
	}
}

// TestReportHandler_RejectsUnknownMessageID: a nonexistent id reads identically
// to a foreign id — 404, nothing written.
func TestReportHandler_RejectsUnknownMessageID(t *testing.T) {
	pool := testPool(t)
	h := NewReportHandler(pool, testLogger(), nil)
	userID, _ := seedUserWithMailbox(t, pool)

	rec := postReportE5(t, h, userID, "987654321987", "phishing")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown-message report returned %d, want 404: %s", rec.Code, rec.Body.String())
	}
	if n := auditReportCount(t, pool, userID, 987654321987); n != 0 {
		t.Errorf("audit rows written for an unknown message: %d", n)
	}
}

// TestReportHandler_ResolverFailureFailsClosed: an infrastructure failure in
// the ownership resolve (not a no-rows verdict) must fail CLOSED — the report
// is refused and no training signal is produced.
func TestReportHandler_ResolverFailureFailsClosed(t *testing.T) {
	pool := testPool(t)
	trainer := &fakeSpamEnqueuer{}
	h := NewReportHandler(pool, testLogger(), trainer)
	userID, mailboxID := seedUserWithMailbox(t, pool)
	msgID := seedOwnedMessage(t, pool, mailboxID)

	// Kill the pool so the ownership resolve fails with an infrastructure
	// error rather than a row verdict.
	pool.Close()

	rec := postReportE5(t, h, userID, fmt.Sprintf("%d", msgID), "spam")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("resolver-failure report returned %d, want 404 (fail-closed): %s", rec.Code, rec.Body.String())
	}
	if len(trainer.calls) != 0 {
		t.Errorf("trainer enqueued %d samples despite a failed ownership resolve, want 0", len(trainer.calls))
	}
}

// auditReportCount counts report audit rows by (actor, target message id) in
// admin_audit_log — the table the audit_write choke point feeds.
func auditReportCount(t *testing.T, pool *pgxpool.Pool, userID, messageID int64) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM admin_audit_log
		  WHERE user_id = $1 AND action LIKE 'report_%'
		    AND target_type = 'message' AND target_id = $2`,
		userID, messageID,
	).Scan(&n); err != nil {
		t.Fatalf("auditReportCount: %v", err)
	}
	return n
}
