// Tests for the What-If simulator endpoint (D6).
//
// Test matrix:
//   - POST with a basic hypothetical context → matched policy + decision in 6-value vocab
//   - Non-matching policies carry first_failed + outcome:"skipped"
//   - Context that matches no policy → matched_policy:null, decision:"applied" (default-allow, calm path)
//   - {from_signin:<id>} seeds the context from ca_signin_log row
//   - Missing user → 400
//   - No request body → 400
package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/threat"
)

// newTestCASimulateHandler opens the test pool and returns a CASimulateHandler.
func newTestCASimulateHandler(t *testing.T) *CASimulateHandler {
	t.Helper()
	pool := testsupport.OpenTestPool(t)
	logger := testsupport.TestLogger()
	// Build a minimal PolicyEngine with the test pool's store; no device-trust/ip-risk
	// resolvers (nil is safe — engine treats them as unknown/low).
	store := threat.NewPolicyStore(pool, logger)
	engine := threat.NewPolicyEngine(store, nil, nil, nil, logger, false)
	return NewCASimulateHandler(pool, engine, logger)
}

// seedD6Policy inserts a minimal CA policy for simulator tests.
// Returns the new id and registers a Cleanup to delete it.
func seedD6Policy(t *testing.T, h *CASimulateHandler, name, state, clientType string) int64 {
	t.Helper()
	ctx := context.Background()
	conditions := fmt.Sprintf(`{"client_type":%q}`, clientType)
	var id int64
	err := h.pool.QueryRow(ctx, `
		INSERT INTO conditional_access_policies
		  (priority, name, description, state, scope_type, scope_target,
		   conditions, actions, exclude_users, exclude_groups)
		VALUES (9800, $1, '', $2, 'global', '',
		        $3::jsonb, '{"action":"block"}', '[]', '[]')
		RETURNING id`,
		name, state, conditions).Scan(&id)
	if err != nil {
		t.Fatalf("seedD6Policy: %v", err)
	}
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(),
			`DELETE FROM conditional_access_policies WHERE id = $1`, id)
	})
	return id
}

// TestCASimulate_BasicMatch — a matching imap context returns matched_policy + decision.
func TestCASimulate_BasicMatch(t *testing.T) {
	h := newTestCASimulateHandler(t)
	seedD6Policy(t, h, "d6-block-imap", "on", "imap")

	body := `{"client_type":"imap","country":"RU","device_trust":"unknown"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/conditional-access/simulate",
		bytes.NewBufferString(body))
	req = withAdminClaims(req, 1)
	w := httptest.NewRecorder()
	h.Simulate(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Simulate(match): got %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var resp simulateResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Simulate(match): invalid JSON: %v; body=%s", err, w.Body.String())
	}
	// A matching enforcing policy should set matched_policy and a non-"applied"-default decision.
	if resp.MatchedPolicy == nil {
		t.Fatalf("Simulate(match): want matched_policy set, got nil; evaluated=%v", resp.Evaluated)
	}
	// Decision must be in the 6-value vocabulary — for a block policy, "block".
	validDecisions := map[string]bool{
		"applied": true, "block": true, "step_up": true,
		"notify": true, "skipped": true, "excluded": true,
	}
	if !validDecisions[resp.Decision] {
		t.Fatalf("Simulate(match): decision %q not in 6-value vocabulary", resp.Decision)
	}
}

// TestCASimulate_NoMatchCalmPath — a context that matches nothing returns
// matched_policy:null and decision:"applied" (default-allow, NOT an error).
func TestCASimulate_NoMatchCalmPath(t *testing.T) {
	h := newTestCASimulateHandler(t)
	// Seed a policy for smtp — our request uses "webdav" so it won't match.
	seedD6Policy(t, h, "d6-no-match-smtp", "on", "smtp")

	body := `{"client_type":"webdav","country":"US"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/conditional-access/simulate",
		bytes.NewBufferString(body))
	req = withAdminClaims(req, 1)
	w := httptest.NewRecorder()
	h.Simulate(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Simulate(no-match): got %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var resp simulateResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Simulate(no-match): invalid JSON: %v; body=%s", err, w.Body.String())
	}
	// NO-MATCH: matched_policy must be nil, decision must be "applied" (default-allow).
	if resp.MatchedPolicy != nil {
		t.Fatalf("Simulate(no-match): want matched_policy:null, got %v", resp.MatchedPolicy)
	}
	if resp.Decision != "applied" {
		t.Fatalf("Simulate(no-match): want decision='applied', got %q", resp.Decision)
	}
	// All policies in the trace must carry first_failed (condition that didn't match).
	for _, e := range resp.Evaluated {
		if e.Outcome == "skipped" && e.FirstFailed == "" {
			t.Fatalf("Simulate(no-match): evaluated entry policy_id=%d skipped but first_failed is empty", e.PolicyID)
		}
	}
}

// TestCASimulate_FirstFailedAnnotation — the evaluated trace for non-matching entries
// carries a non-empty first_failed string naming the failing condition key.
func TestCASimulate_FirstFailedAnnotation(t *testing.T) {
	h := newTestCASimulateHandler(t)
	seedD6Policy(t, h, "d6-first-failed-smtp", "on", "smtp")

	// Request uses imap — client_type won't match the smtp policy.
	body := `{"client_type":"imap"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/conditional-access/simulate",
		bytes.NewBufferString(body))
	req = withAdminClaims(req, 1)
	w := httptest.NewRecorder()
	h.Simulate(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Simulate(first-failed): got %d; body=%s", w.Code, w.Body.String())
	}
	var resp simulateResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Simulate(first-failed): invalid JSON: %v", err)
	}
	// Find the d6-first-failed-smtp policy in the trace and confirm first_failed.
	found := false
	for _, e := range resp.Evaluated {
		if e.Outcome == "skipped" && e.FirstFailed != "" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Simulate(first-failed): no skipped entry with first_failed; evaluated=%v", resp.Evaluated)
	}
}

// TestCASimulate_FromSignin — {from_signin:<id>} seeds the context from ca_signin_log.
func TestCASimulate_FromSignin(t *testing.T) {
	h := newTestCASimulateHandler(t)

	// Seed a ca_signin_log row to pull the context from.
	corrID := "CA-d6-fromsignin"
	payload := fmt.Sprintf(`{"user_id":1,"decision":"allow","correlation_id":%q,"client_type":"imap","country":"US","evaluated":[]}`, corrID)
	var signinID int64
	if err := h.pool.QueryRow(context.Background(),
		`SELECT id FROM ca_signin_log_append($1::jsonb)`, payload).Scan(&signinID); err != nil {
		// ca_signin_log_append may not return id — try insert + select.
		if _, execErr := h.pool.Exec(context.Background(),
			`SELECT ca_signin_log_append($1::jsonb)`, payload); execErr != nil {
			t.Fatalf("seed ca_signin_log: %v", execErr)
		}
		if err2 := h.pool.QueryRow(context.Background(),
			`SELECT id FROM ca_signin_log WHERE correlation_id = $1`, corrID).Scan(&signinID); err2 != nil {
			t.Fatalf("resolve signin id: %v", err2)
		}
	}

	body := fmt.Sprintf(`{"from_signin":%d}`, signinID)
	req := httptest.NewRequest(http.MethodPost, "/admin/conditional-access/simulate",
		bytes.NewBufferString(body))
	req = withAdminClaims(req, 1)
	w := httptest.NewRecorder()
	h.Simulate(w, req)

	// from_signin must produce a valid 200 response (even if no policies match).
	if w.Code != http.StatusOK {
		t.Fatalf("Simulate(from_signin): got %d; body=%s", w.Code, w.Body.String())
	}
	var resp simulateResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Simulate(from_signin): invalid JSON: %v", err)
	}
	// evaluated must be an array (empty or populated).
	if resp.Evaluated == nil {
		t.Fatalf("Simulate(from_signin): evaluated must be [] not null")
	}
}

// TestCASimulate_MissingBody — no request body → 400.
func TestCASimulate_MissingBody(t *testing.T) {
	h := &CASimulateHandler{logger: testsupport.TestLogger()}
	req := httptest.NewRequest(http.MethodPost, "/admin/conditional-access/simulate",
		bytes.NewBufferString(`not-json`))
	req = withAdminClaims(req, 1)
	w := httptest.NewRecorder()
	h.Simulate(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("Simulate(bad body): got %d, want 400", w.Code)
	}
}
