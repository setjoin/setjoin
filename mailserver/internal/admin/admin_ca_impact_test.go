package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/shared/testsupport"
)

// newTestCAImpactHandler opens the test pool and returns a CAImpactHandler.
func newTestCAImpactHandler(t *testing.T) *CAImpactHandler {
	t.Helper()
	pool := testsupport.OpenTestPool(t)
	return NewCAImpactHandler(pool, testsupport.TestLogger())
}

// seedD5Policy inserts a minimal CA policy for impact tests. Returns the new id.
// Idempotent name via timestamp suffix to avoid clashes between test runs.
func seedD5Policy(t *testing.T, h *CAImpactHandler) int64 {
	t.Helper()
	ctx := context.Background()

	// Minimal policy row via direct INSERT (not through reducer — avoids needing an admin user for audit).
	var id int64
	err := h.pool.QueryRow(ctx, `
		INSERT INTO conditional_access_policies
		  (priority, name, description, state, scope_type, scope_target,
		   conditions, actions, exclude_users, exclude_groups)
		VALUES (9999, 'd5-impact-test', '', 'report_only', 'global', '',
		        '{}', '{"action":"allow"}', '[]', '[]')
		ON CONFLICT DO NOTHING
		RETURNING id`).Scan(&id)
	if err != nil {
		// Already exists from a prior run — fetch it.
		_ = h.pool.QueryRow(ctx,
			`SELECT id FROM conditional_access_policies WHERE name = 'd5-impact-test'`).Scan(&id)
	}
	if id == 0 {
		t.Fatal("seedD5Policy: could not create or find d5-impact-test policy")
	}
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(),
			`DELETE FROM conditional_access_policies WHERE id = $1`, id)
	})
	return id
}

// TestCAImpact_SummaryWindowHasData — calling impact on a fresh policy (no log rows)
// returns 200 with window_has_data=false (zero row, no data state).
func TestCAImpact_SummaryWindowHasData(t *testing.T) {
	h := newTestCAImpactHandler(t)
	policyID := seedD5Policy(t, h)

	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/admin/conditional-access/policies/%d/impact?window=24h", policyID), nil)
	req.SetPathValue("id", fmt.Sprintf("%d", policyID))
	req = withAdminClaims(req, 1)
	w := httptest.NewRecorder()
	h.Impact(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Impact(summary): got %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Window        string `json:"window"`
		WindowHasData bool   `json:"window_has_data"`
		Matched       int64  `json:"matched"`
		WouldBlock    int64  `json:"would_block"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Impact(summary): invalid JSON: %v; body=%s", err, w.Body.String())
	}
	if resp.Window != "24h" {
		t.Fatalf("Impact(summary): window = %q, want '24h'", resp.Window)
	}
	// Fresh policy with no log rows → window_has_data=false, matched=0.
	if resp.WindowHasData {
		t.Fatalf("Impact(summary): want window_has_data=false for fresh policy, got true")
	}
	if resp.Matched != 0 {
		t.Fatalf("Impact(summary): want matched=0, got %d", resp.Matched)
	}
}

// TestCAImpact_BlockedUsersList — ?list=blocked_users returns the {users,shown,total,admin_users} shape.
func TestCAImpact_BlockedUsersList(t *testing.T) {
	h := newTestCAImpactHandler(t)
	policyID := seedD5Policy(t, h)

	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/admin/conditional-access/policies/%d/impact?window=7d&list=blocked_users", policyID), nil)
	req.SetPathValue("id", fmt.Sprintf("%d", policyID))
	req = withAdminClaims(req, 1)
	w := httptest.NewRecorder()
	h.Impact(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Impact(blocked_users): got %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Users      []any `json:"users"`
		Shown      int64 `json:"shown"`
		Total      int64 `json:"total"`
		AdminUsers []any `json:"admin_users"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Impact(blocked_users): invalid JSON: %v; body=%s", err, w.Body.String())
	}
	// users and admin_users must be arrays (not null) even when empty.
	if resp.Users == nil {
		t.Fatalf("Impact(blocked_users): users must be [] not null")
	}
	if resp.AdminUsers == nil {
		t.Fatalf("Impact(blocked_users): admin_users must be [] not null")
	}
}

// TestCAImpact_MissingPolicyID — missing {id} path value → 400.
func TestCAImpact_MissingPolicyID(t *testing.T) {
	h := &CAImpactHandler{logger: testsupport.TestLogger()}

	req := httptest.NewRequest(http.MethodGet,
		"/admin/conditional-access/policies//impact?window=24h", nil)
	// SetPathValue("id", "") leaves it empty.
	w := httptest.NewRecorder()
	h.Impact(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("Impact(no id): got %d, want 400", w.Code)
	}
}

// TestCAImpact_InvalidWindow — bad window param → 400 (reducer returns 22023).
func TestCAImpact_InvalidWindow(t *testing.T) {
	h := newTestCAImpactHandler(t)
	policyID := seedD5Policy(t, h)

	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/admin/conditional-access/policies/%d/impact?window=badwindow", policyID), nil)
	req.SetPathValue("id", fmt.Sprintf("%d", policyID))
	req = withAdminClaims(req, 1)
	w := httptest.NewRecorder()
	h.Impact(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("Impact(bad window): got %d, want 400; body=%s", w.Code, w.Body.String())
	}
}
