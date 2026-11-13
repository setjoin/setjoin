package jmap

// mailtips_dlp_test.go — HandleDlpCheck (POST /auth/me/dlp-check), the compose-
// time DLP dry-run endpoint. Mirrors mailtips_test coverage conventions: the
// toggle-off fast path needs no DB (fakeCaller/pool untouched), the happy path
// needs a real mailbox row (testsupport.OpenTestPool, skipped without DB_DSN).

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/toggle"
)

func newDlpCheckRequest(t *testing.T, userID int64, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/auth/me/dlp-check", bytes.NewBufferString(body))
	req = req.WithContext(auth.ContextWithUser(context.Background(), &auth.Claims{UserID: userID, Email: "u@test.local"}))
	return req
}

// Unauthenticated: mustUser already wrote the 401 (WriteProblem); handler
// returns before touching toggles/pool/caller.
func TestHandleDlpCheck_Unauthenticated(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	req := httptest.NewRequest(http.MethodPost, "/auth/me/dlp-check", bytes.NewBufferString(`{}`))
	w := httptest.NewRecorder()
	h.HandleDlpCheck(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

// Feature parity with enforcement: !feature.dlp short-circuits to clean, no DB
// call at all — the fake caller must record zero invocations.
func TestHandleDlpCheck_ToggleOff_ShortCircuitsNoDBCall(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	h.toggles = toggle.NewTestFlags(map[string]bool{toggle.FeatureDLP: false})
	fake := &fakeCaller{}
	h.caller = fake

	w := httptest.NewRecorder()
	h.HandleDlpCheck(w, newDlpCheckRequest(t, 1, `{"subject":"s","bodyText":"my ssn is 123-45-6789"}`))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got["violated"] != false {
		t.Errorf("violated = %v, want false", got["violated"])
	}
	if fake.calls != 0 {
		t.Errorf("caller.calls = %d, want 0 (toggle-off must not touch the DB)", fake.calls)
	}
}

// Oversized body: MaxBytesReader trips, json.Decode fails → 400, not a panic
// or a 500 (never let an oversized compose payload wedge the dry-run).
func TestHandleDlpCheck_OversizedBody_400(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	h.toggles = toggle.NewTestFlags(map[string]bool{toggle.FeatureDLP: true})

	huge := `{"subject":"` + strings.Repeat("a", 3<<20) + `"}`
	w := httptest.NewRecorder()
	h.HandleDlpCheck(w, newDlpCheckRequest(t, 1, huge))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

// Invalid JSON body → 400.
func TestHandleDlpCheck_InvalidJSON_400(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	h.toggles = toggle.NewTestFlags(map[string]bool{toggle.FeatureDLP: true})

	w := httptest.NewRecorder()
	h.HandleDlpCheck(w, newDlpCheckRequest(t, 1, `not json`))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

// A reducer-call failure fails OPEN to "no tip" (advisory surface; send-time
// enforcement remains the hard gate) rather than 500ing the compose screen.
func TestHandleDlpCheck_ReducerError_FailsOpenToClean(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	_, userID, _ := insertTestUserWithMailbox(t, pool, false)

	h := &JMAPHandler{
		pool:    pool,
		caller:  &fakeCaller{returnErr: context.DeadlineExceeded},
		toggles: toggle.NewTestFlags(map[string]bool{toggle.FeatureDLP: true}),
		logger:  testsupport.TestLogger(),
	}

	w := httptest.NewRecorder()
	h.HandleDlpCheck(w, newDlpCheckRequest(t, userID, `{"subject":"s","bodyText":"b"}`))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (fail-open)", w.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got["violated"] != false {
		t.Errorf("violated = %v, want false on reducer error (fail open to no tip)", got["violated"])
	}
}

// Happy path: the reducer's JSONB is marshaled through verbatim.
func TestHandleDlpCheck_HappyPath_MarshalsReducerResultVerbatim(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	_, userID, mailboxID := insertTestUserWithMailbox(t, pool, false)

	fake := &fakeCaller{returnRaw: json.RawMessage(`{"violated":true,"policyId":7,"policyName":"test-policy","action":"warn","reasonKind":"content"}`)}
	h := &JMAPHandler{
		pool:    pool,
		caller:  fake,
		toggles: toggle.NewTestFlags(map[string]bool{toggle.FeatureDLP: true}),
		logger:  testsupport.TestLogger(),
	}

	w := httptest.NewRecorder()
	h.HandleDlpCheck(w, newDlpCheckRequest(t, userID, `{"recipients":["bob@test.local"],"subject":"s","bodyText":"b","bodyHtml":"<p>b</p>"}`))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if w.Body.String() != `{"violated":true,"policyId":7,"policyName":"test-policy","action":"warn","reasonKind":"content"}` {
		t.Errorf("body = %s, want the reducer's JSONB verbatim", w.Body.String())
	}
	if fake.gotFn != "dlp_evaluate_draft" {
		t.Errorf("gotFn = %q, want dlp_evaluate_draft", fake.gotFn)
	}
	if fake.gotMailboxID != mailboxID {
		t.Errorf("gotMailboxID = %d, want %d", fake.gotMailboxID, mailboxID)
	}
}
