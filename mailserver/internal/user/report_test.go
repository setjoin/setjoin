package user

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/mailserver/internal/auth"
)

// TestReportHandler_ValidSpamReport verifies that a valid spam report for a
// message the caller OWNS returns 201.
func TestReportHandler_ValidSpamReport(t *testing.T) {
	pool := testPool(t)
	h := NewReportHandler(pool, testLogger(), nil)
	userID, mailboxID := seedUserWithMailbox(t, pool)
	msgID := seedOwnedMessage(t, pool, mailboxID)

	body := reportRequest{
		EmailID: fmt.Sprintf("%d", msgID),
		Type:    "spam",
		Note:    "looks like a scam",
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/report", bytes.NewReader(b))
	claims := &auth.Claims{
		UserID: userID,
		Email:  "report-test@setjoin.test",
		Type:   auth.TypeAccess,
	}
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	h.Report(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("expected 201 Created, got %d. body: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["status"] != "reported" {
		t.Errorf("expected status 'reported', got %q", resp["status"])
	}
	if resp["type"] != "spam" {
		t.Errorf("expected type 'spam', got %q", resp["type"])
	}
}

// fakeSpamEnqueuer captures Enqueue calls so tests can assert the report-spam
// action actually feeds the trainer, without needing the real batch/NOTIFY
// pipeline.
type fakeSpamEnqueuer struct {
	calls []struct {
		userID, messageID int64
		isSpam            bool
	}
}

func (f *fakeSpamEnqueuer) Enqueue(userID, messageID int64, isSpam bool) {
	f.calls = append(f.calls, struct {
		userID, messageID int64
		isSpam            bool
	}{userID, messageID, isSpam})
}

// TestReportHandler_SpamReport_EnqueuesTrainingSample verifies that a "spam"
// report for an OWNED message feeds the spam trainer (report-spam must not be
// audit-log-only).
func TestReportHandler_SpamReport_EnqueuesTrainingSample(t *testing.T) {
	pool := testPool(t)
	trainer := &fakeSpamEnqueuer{}
	h := NewReportHandler(pool, testLogger(), trainer)
	userID, mailboxID := seedUserWithMailbox(t, pool)
	msgID := seedOwnedMessage(t, pool, mailboxID)

	body := reportRequest{EmailID: fmt.Sprintf("%d", msgID), Type: "spam"}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/report", bytes.NewReader(b))
	claims := &auth.Claims{UserID: userID, Email: "report-test@setjoin.test", Type: auth.TypeAccess}
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	h.Report(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d. body: %s", rec.Code, rec.Body.String())
	}
	if len(trainer.calls) != 1 {
		t.Fatalf("expected 1 Enqueue call, got %d", len(trainer.calls))
	}
	call := trainer.calls[0]
	if call.userID != userID || call.messageID != msgID || !call.isSpam {
		t.Errorf("unexpected Enqueue call: %+v, want userID=%d messageID=%d isSpam=true", call, userID, msgID)
	}
}

// TestReportHandler_PhishingReport_DoesNotEnqueueTraining verifies that a
// "phishing" report (not a spam/ham signal) for an OWNED message leaves the
// trainer untouched.
func TestReportHandler_PhishingReport_DoesNotEnqueueTraining(t *testing.T) {
	pool := testPool(t)
	trainer := &fakeSpamEnqueuer{}
	h := NewReportHandler(pool, testLogger(), trainer)
	userID, mailboxID := seedUserWithMailbox(t, pool)
	msgID := seedOwnedMessage(t, pool, mailboxID)

	body := reportRequest{EmailID: fmt.Sprintf("%d", msgID), Type: "phishing"}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/report", bytes.NewReader(b))
	claims := &auth.Claims{UserID: userID, Email: "report-test@setjoin.test", Type: auth.TypeAccess}
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	h.Report(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d. body: %s", rec.Code, rec.Body.String())
	}
	if len(trainer.calls) != 0 {
		t.Errorf("expected 0 Enqueue calls for a phishing report, got %d", len(trainer.calls))
	}
}

// TestReportHandler_MissingEmailId verifies that omitting emailId returns 400.
func TestReportHandler_MissingEmailId(t *testing.T) {
	h := NewReportHandler(nil, nil, nil)

	body := map[string]string{"type": "spam"}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/report", bytes.NewReader(b))
	claims := &auth.Claims{
		UserID: 1,
		Email:  "test@setjoin.test",
		Type:   auth.TypeAccess,
	}
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	h.Report(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for missing emailId, got %d. body: %s",
			rec.Code, rec.Body.String())
	}
}

// TestReportHandler_InvalidType verifies that an invalid report type returns 400.
func TestReportHandler_InvalidType(t *testing.T) {
	h := NewReportHandler(nil, nil, nil)

	body := reportRequest{
		EmailID: "123",
		Type:    "not_a_valid_type",
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/report", bytes.NewReader(b))
	claims := &auth.Claims{
		UserID: 1,
		Email:  "test@setjoin.test",
		Type:   auth.TypeAccess,
	}
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	h.Report(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for invalid type, got %d. body: %s",
			rec.Code, rec.Body.String())
	}
}

// TestReportHandler_Unauthenticated verifies that missing auth returns 401.
func TestReportHandler_Unauthenticated(t *testing.T) {
	h := NewReportHandler(nil, nil, nil)

	body := reportRequest{
		EmailID: "123",
		Type:    "spam",
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/report", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	// No auth context set — unauthenticated.

	rec := httptest.NewRecorder()
	h.Report(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d. body: %s",
			rec.Code, rec.Body.String())
	}
}
