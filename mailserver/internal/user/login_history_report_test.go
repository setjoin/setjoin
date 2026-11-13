package user

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"setjoin.com/mailserver/internal/auth"
)

// postReport calls ReportSuspiciousLogin as the given user against the given
// path event id.
func postReport(h *LoginHistoryHandler, userID int64, eventID string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/user/login-history/"+eventID+"/report", nil)
	req.SetPathValue("id", eventID)
	ctx := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.ReportSuspiciousLogin(w, req)
	return w
}

// ownEventID returns the id of the user's most recent login event.
func ownEventID(t *testing.T, h *LoginHistoryHandler, userID int64) int64 {
	t.Helper()
	var id int64
	if err := h.pool.QueryRow(context.Background(),
		`SELECT id FROM login_events WHERE user_id=$1 ORDER BY id DESC LIMIT 1`,
		userID).Scan(&id); err != nil {
		t.Fatalf("read seeded login event: %v", err)
	}
	return id
}

// TestReportSuspiciousLogin_ReportsOwnedEvent covers the ownership-check seam
// inside dbscope.RunUserScoped (R1): an event the authenticated user owns
// passes the EXISTS check, and the report lands in the admin audit log for
// administrator review. The report is routine-tier, so the audit write is
// suppressed at the lean policy level — flip to full for the assertion and
// restore afterwards.
func TestReportSuspiciousLogin_ReportsOwnedEvent(t *testing.T) {
	pool := testPool(t)
	h := NewLoginHistoryHandler(pool)
	u := createTestUser(t, pool)
	seedLoginEvent(t, h, u, true, "", "Report City, XX")
	eventID := ownEventID(t, h, u)

	restoreAuditFullLevel(t, pool)
	w := postReport(h, u, strconv.FormatInt(eventID, 10))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["status"] != "reported" {
		t.Errorf("status = %q, want %q", resp["status"], "reported")
	}

	// The security report is durable: one admin-audit entry naming the event.
	var reports int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM admin_audit_log
		  WHERE user_id=$1 AND action='login_reported_suspicious' AND target_type='login_event' AND target_id=$2`,
		u, eventID).Scan(&reports); err != nil {
		t.Fatalf("count audit reports: %v", err)
	}
	if reports != 1 {
		t.Errorf("audit reports = %d, want 1", reports)
	}
}

// TestReportSuspiciousLogin_ForeignEventNotFound pins the R1 isolation arm of
// the same seam: another user's event id never matches the ownership-scoped
// EXISTS and yields 404 — and writes no audit entry.
func TestReportSuspiciousLogin_ForeignEventNotFound(t *testing.T) {
	pool := testPool(t)
	h := NewLoginHistoryHandler(pool)
	owner := createTestUser(t, pool)
	attacker := createTestUser(t, pool)
	seedLoginEvent(t, h, owner, false, "", "Owner City, YY")
	eventID := ownEventID(t, h, owner)

	w := postReport(h, attacker, strconv.FormatInt(eventID, 10))
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}

	var reports int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM admin_audit_log
		  WHERE action='login_reported_suspicious' AND target_id=$1`,
		eventID).Scan(&reports); err != nil {
		t.Fatalf("count audit reports: %v", err)
	}
	if reports != 0 {
		t.Errorf("audit reports for a foreign event = %d, want 0", reports)
	}
}

// TestReportSuspiciousLogin_InvalidEventID covers the request-shape arm: a
// non-numeric path id is a 400 before any database work.
func TestReportSuspiciousLogin_InvalidEventID(t *testing.T) {
	pool := testPool(t)
	h := NewLoginHistoryHandler(pool)
	u := createTestUser(t, pool)

	w := postReport(h, u, "not-a-number")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}
