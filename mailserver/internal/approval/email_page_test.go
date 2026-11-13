package approval

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

// testSecret is the HMAC key used across all email_page tests.
var testSecret = []byte("test-approval-email-secret")

// ── Token unit tests (no DB) ──────────────────────────────────────────────────

func TestApprovalToken_RoundTrip(t *testing.T) {
	claims := ApprovalEmailClaims{
		RequestID:      42,
		ApproverUserID: 7,
		Decision:       "approve",
		ExpiresAt:      time.Now().Add(time.Hour).Unix(),
	}
	tok, err := SignApprovalToken(claims, testSecret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got, err := VerifyApprovalToken(tok, testSecret)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.RequestID != 42 || got.ApproverUserID != 7 || got.Decision != "approve" {
		t.Errorf("claims mismatch: %+v", got)
	}
}

func TestApprovalToken_Tampered(t *testing.T) {
	claims := ApprovalEmailClaims{
		RequestID: 1, ApproverUserID: 2, Decision: "approve",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	tok, _ := SignApprovalToken(claims, testSecret)

	// Flip a char in the payload segment.
	parts := strings.SplitN(tok, ".", 2)
	tampered := "X" + parts[0][1:] + "." + parts[1]

	if _, err := VerifyApprovalToken(tampered, testSecret); err == nil {
		t.Error("tampered token should not verify")
	}
}

func TestApprovalToken_Expired(t *testing.T) {
	claims := ApprovalEmailClaims{
		RequestID: 1, ApproverUserID: 2, Decision: "approve",
		ExpiresAt: time.Now().Add(-time.Second).Unix(), // already expired
	}
	tok, _ := SignApprovalToken(claims, testSecret)
	if _, err := VerifyApprovalToken(tok, testSecret); err == nil {
		t.Error("expired token should not verify")
	}
}

// ── DB-backed tests ───────────────────────────────────────────────────────────
//
// These run against the superuser pool (BYPASSRLS) so RLS is not enforced.
// We reuse the existing insertFixtures / insertRequest helpers from handler_test.go.

// insertMailExternalRequest inserts a mail.external_send approval request.
// Returns the request ID. Note: uses approver_kind='user' and approver_ref=approverID.
func insertMailExternalRequest(t *testing.T, requesterID, approverID int64) int64 {
	t.Helper()
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	var id int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO approval_requests
		  (consumer_type, requester_user_id, subject, payload, approver_kind, approver_ref, expires_at)
		VALUES (
		  'mail.external_send', $1, 'Send to external.test',
		  '{"p_user_id":1}'::jsonb,
		  'user', $2, now()+interval '1h'
		)
		RETURNING id`,
		requesterID, approverID,
	).Scan(&id); err != nil {
		t.Fatalf("insertMailExternalRequest: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM approval_requests WHERE id = $1`, id) //nolint:errcheck
	})
	return id
}

// approvalStatus reads the status column of an approval_requests row.
func approvalStatus(t *testing.T, id int64) string {
	t.Helper()
	pool := testsupport.OpenTestPool(t)
	var status string
	if err := pool.QueryRow(context.Background(),
		`SELECT status FROM approval_requests WHERE id = $1`, id,
	).Scan(&status); err != nil {
		t.Fatalf("approvalStatus(%d): %v", id, err)
	}
	return status
}

// makeEmailPageHandler returns an EmailPageHandler wired to the test pool.
func makeEmailPageHandler(t *testing.T) *EmailPageHandler {
	t.Helper()
	pool := testsupport.OpenTestPool(t)
	return NewEmailPageHandler(pool, pgxutil.WorkerPool{Pool: pool}, testSecret, testsupport.TestLogger())
}

// ── TestEmailPage_GET_DoesNotMutate — PREFETCH-SAFETY PROOF ──────────────────
//
// A GET with a valid token MUST return 200 HTML AND the request MUST remain
// 'pending'. Email clients and security scanners prefetch URLs; a one-click GET
// that decided would be auto-triggered by a bot.
func TestEmailPage_GET_DoesNotMutate(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	insertFixtures(t, pool)
	// Use a mail.external_send request so the "approve" decision is decider-agnostic
	// (rbac_approval_decide has an eligible-assignment prerequisite we skip here).
	reqID := insertMailExternalRequest(t, testRequesterID, testApproverID)

	tok, err := SignApprovalToken(ApprovalEmailClaims{
		RequestID:      reqID,
		ApproverUserID: testApproverID,
		Decision:       "approve",
		ExpiresAt:      time.Now().Add(time.Hour).Unix(),
	}, testSecret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	h := makeEmailPageHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/approvals/email/"+tok, nil)
	req.SetPathValue("token", tok)
	w := httptest.NewRecorder()
	h.ServeGET(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET valid token: want 200, got %d — %s", w.Code, w.Body.String())
	}

	// The response must be HTML containing the confirm form.
	body := w.Body.String()
	if !strings.Contains(body, "<form") {
		t.Errorf("GET: expected HTML form, got: %.200s", body)
	}

	// KEY ASSERTION: the request MUST still be pending — GET must not decide.
	if s := approvalStatus(t, reqID); s != "pending" {
		t.Errorf("GET mutated the request: status is %q, want 'pending'", s)
	}
}

// ── TestEmailPage_GET_TamperedToken ──────────────────────────────────────────

func TestEmailPage_GET_TamperedToken(t *testing.T) {
	h := makeEmailPageHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/approvals/email/not.avalidtoken", nil)
	req.SetPathValue("token", "not.avalidtoken")
	w := httptest.NewRecorder()
	h.ServeGET(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("tampered GET: want 400, got %d — %s", w.Code, w.Body.String())
	}
}

// ── TestEmailPage_POST_Decides ─────────────────────────────────────────────

func TestEmailPage_POST_Decides(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	insertFixtures(t, pool)
	reqID := insertMailExternalRequest(t, testRequesterID, testApproverID)

	tok, _ := SignApprovalToken(ApprovalEmailClaims{
		RequestID:      reqID,
		ApproverUserID: testApproverID,
		Decision:       "deny", // deny doesn't need an eligible assignment
		ExpiresAt:      time.Now().Add(time.Hour).Unix(),
	}, testSecret)

	h := makeEmailPageHandler(t)
	form := url.Values{}
	req := httptest.NewRequest(http.MethodPost, "/approvals/email/"+tok,
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("token", tok)
	w := httptest.NewRecorder()
	h.ServePOST(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("POST deny: want 200, got %d — %s", w.Code, w.Body.String())
	}

	// Request must no longer be pending.
	if s := approvalStatus(t, reqID); s == "pending" {
		t.Errorf("POST deny: request is still pending")
	}
}

// ── TestEmailPage_POST_Reused ─────────────────────────────────────────────────
//
// A second POST with the same token must get a friendly "already decided" page.
// The request's idempotency guard (BZ108) makes this free.
func TestEmailPage_POST_Reused(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	insertFixtures(t, pool)
	reqID := insertMailExternalRequest(t, testRequesterID, testApproverID)

	tok, _ := SignApprovalToken(ApprovalEmailClaims{
		RequestID:      reqID,
		ApproverUserID: testApproverID,
		Decision:       "deny",
		ExpiresAt:      time.Now().Add(time.Hour).Unix(),
	}, testSecret)

	h := makeEmailPageHandler(t)
	doPost := func() *httptest.ResponseRecorder {
		form := url.Values{}
		req := httptest.NewRequest(http.MethodPost, "/approvals/email/"+tok,
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetPathValue("token", tok)
		ww := httptest.NewRecorder()
		h.ServePOST(ww, req)
		return ww
	}

	w1 := doPost()
	if w1.Code != http.StatusOK {
		t.Fatalf("first POST: want 200, got %d — %s", w1.Code, w1.Body.String())
	}

	w2 := doPost()
	if w2.Code != http.StatusOK {
		t.Fatalf("reused POST: want 200 with info page, got %d — %s", w2.Code, w2.Body.String())
	}
	if !strings.Contains(w2.Body.String(), "no longer active") {
		t.Errorf("reused POST: expected 'no longer active' in body, got: %.300s", w2.Body.String())
	}
}

// ── TestEmailPage_POST_TamperedToken ──────────────────────────────────────────

func TestEmailPage_POST_TamperedToken(t *testing.T) {
	h := makeEmailPageHandler(t)

	form := url.Values{}
	req := httptest.NewRequest(http.MethodPost, "/approvals/email/bad.token",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("token", "bad.token")
	w := httptest.NewRecorder()
	h.ServePOST(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("tampered POST: want 400, got %d — %s", w.Code, w.Body.String())
	}
}

// ── TestEmailPage_POST_TamperedApprover ──────────────────────────────────────
//
// A token whose payload approver field is changed to a different user (while
// keeping the original signature) must be rejected with HMAC mismatch (400)
// and MUST NOT mutate the request. Exercises actor-binding at the HTTP layer;
// the unit Tampered test covers the crypto, this proves no DB side effect.
func TestEmailPage_POST_TamperedApprover(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	insertFixtures(t, pool)
	reqID := insertMailExternalRequest(t, testRequesterID, testApproverID)

	// Legitimate token for the real approver.
	legit := ApprovalEmailClaims{
		RequestID:      reqID,
		ApproverUserID: testApproverID,
		Decision:       "approve",
		ExpiresAt:      time.Now().Add(time.Hour).Unix(),
	}
	legitTok, err := SignApprovalToken(legit, testSecret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Forge: swap approver in the payload, keep the original signature → HMAC mismatch.
	parts := strings.SplitN(legitTok, ".", 2)
	forged := legit
	forged.ApproverUserID = testNonApproverID // different user, not the real approver
	forgedPayload, _ := json.Marshal(forged)
	forgedTok := base64.URLEncoding.EncodeToString(forgedPayload) + "." + parts[1]

	h := makeEmailPageHandler(t)
	form := url.Values{}
	req := httptest.NewRequest(http.MethodPost, "/approvals/email/"+forgedTok,
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("token", forgedTok)
	w := httptest.NewRecorder()
	h.ServePOST(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("tampered approver POST: want 400 (HMAC mismatch), got %d — %s", w.Code, w.Body.String())
	}

	// Verify no mutation: request must still be pending.
	if s := approvalStatus(t, reqID); s != "pending" {
		t.Errorf("tampered approver POST: request mutated to %q, want 'pending'", s)
	}
}

// ── TestEmailPage_GET_AlreadyDecided ─────────────────────────────────────────

func TestEmailPage_GET_AlreadyDecided(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	insertFixtures(t, pool)
	reqID := insertMailExternalRequest(t, testRequesterID, testApproverID)

	// Decide the request directly so the GET sees a non-pending request.
	if _, err := pool.Exec(context.Background(),
		`UPDATE approval_requests SET status='denied', decided_by_user_id=$1, decided_at=now() WHERE id=$2`,
		testApproverID, reqID,
	); err != nil {
		t.Fatalf("pre-decide: %v", err)
	}

	tok, _ := SignApprovalToken(ApprovalEmailClaims{
		RequestID:      reqID,
		ApproverUserID: testApproverID,
		Decision:       "approve",
		ExpiresAt:      time.Now().Add(time.Hour).Unix(),
	}, testSecret)

	h := makeEmailPageHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/approvals/email/"+tok, nil)
	req.SetPathValue("token", tok)
	w := httptest.NewRecorder()
	h.ServeGET(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("already-decided GET: want 200 info page, got %d — %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "no longer active") {
		t.Errorf("already-decided GET: expected 'no longer active' in body, got: %.300s", w.Body.String())
	}
}

// ── TestEmailPage_POST_DriveExport ───────────────────────────────────────────
//
// drive.export (V116, Drive P5) has no cross-tenant mail leg; the
// approve-by-email surface must route it to drive_export_approval_decide
// exactly like the rbac case above.
func TestEmailPage_POST_DriveExport(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	insertFixtures(t, pool)
	spaceID, versionID := insertDriveExportFixtures(t, pool, testRequesterID)
	payload, _ := json.Marshal(map[string]any{
		"version_id": versionID, "space_id": spaceID, "action": "download",
		"token_hash": strings.Repeat("e", 64), "ttl_minutes": 60,
	})
	reqID := insertConsumerRequestWithPayload(t, pool, "drive.export", testRequesterID, testApproverID, string(payload))

	tok, _ := SignApprovalToken(ApprovalEmailClaims{
		RequestID:      reqID,
		ApproverUserID: testApproverID,
		Decision:       "approve",
		ExpiresAt:      time.Now().Add(time.Hour).Unix(),
	}, testSecret)

	h := makeEmailPageHandler(t)
	form := url.Values{}
	req := httptest.NewRequest(http.MethodPost, "/approvals/email/"+tok,
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("token", tok)
	w := httptest.NewRecorder()
	h.ServePOST(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("POST drive.export approve: want 200, got %d — %s", w.Code, w.Body.String())
	}
	if s := approvalStatus(t, reqID); s != "applied" {
		t.Errorf("drive.export request status = %q, want 'applied'", s)
	}
	var grantee int64
	if err := pool.QueryRow(context.Background(),
		`SELECT grantee FROM drive_export_grants WHERE token_hash = $1`, strings.Repeat("e", 64),
	).Scan(&grantee); err != nil {
		t.Fatalf("expected export grant minted via the email surface: %v", err)
	}
}
