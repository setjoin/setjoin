package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/shared/testsupport"
)

// ── GET /admin/dengbao/sod-mode — read-only precheck handler ─────────────────
//
// These tests are DB-backed (skip without DB_DSN). Each test wraps its work
// in a pgx.Tx that is rolled back at the end; nothing persists in the shared
// test DB.

func getSodModeReq(userID int64) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/admin/dengbao/sod-mode", nil)
	return req.WithContext(ctxWithAdminUser(userID, "secadmin@example.com"))
}

// TestSodModeGetCleanDB: with a violation-free DB, GET returns 200 with
// enabled=false and an empty (not null) violations slice.
func TestSodModeGetCleanDB(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)

	uid := realUserID(t, tx)
	seedDengbaoToggleOff(t, tx)
	neutralizeAllViolations(t, tx)

	var before int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM admin_sod_precheck()`).Scan(&before); err != nil {
		t.Fatalf("precheck count: %v", err)
	}
	if before != 0 {
		t.Fatalf("neutralize failed: precheck still reports %d violations", before)
	}

	h := NewSodModeHandler(tx, testsupport.TestLogger())
	w := httptest.NewRecorder()
	h.Get(w, getSodModeReq(uid))

	if w.Code != http.StatusOK {
		t.Fatalf("GET clean DB: expected 200, got %d — body: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Enabled    bool          `json:"enabled"`
		Violations []interface{} `json:"violations"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Enabled {
		t.Fatal("GET clean DB: enabled must be false (toggle was seeded OFF)")
	}
	if resp.Violations == nil {
		t.Fatal("GET clean DB: violations must be an empty slice, not null")
	}
	if len(resp.Violations) != 0 {
		t.Fatalf("GET clean DB: expected 0 violations, got %d", len(resp.Violations))
	}
}

// TestSodModeGetWithViolations: without neutralization, GET returns 200 with
// a non-empty violations slice (reflecting the preset seeded role groups).
func TestSodModeGetWithViolations(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)

	uid := realUserID(t, tx)

	// Sanity: there must be at least one violation for this test to be meaningful.
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM admin_sod_precheck()`).Scan(&n); err != nil {
		t.Fatalf("precheck count: %v", err)
	}
	if n == 0 {
		t.Skip("test DB has no SoD violations — cannot exercise the violations path")
	}

	h := NewSodModeHandler(tx, testsupport.TestLogger())
	w := httptest.NewRecorder()
	h.Get(w, getSodModeReq(uid))

	if w.Code != http.StatusOK {
		t.Fatalf("GET with violations: expected 200, got %d — body: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Enabled    bool `json:"enabled"`
		Violations []struct {
			ViolationType string `json:"violationType"`
			Subject       string `json:"subject"`
			Detail        string `json:"detail"`
		} `json:"violations"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Violations) == 0 {
		t.Fatal("GET with violations: response must include the violation list")
	}
	// Verify each violation has all required fields.
	for i, v := range resp.Violations {
		if v.ViolationType == "" {
			t.Errorf("violation[%d]: violationType is empty", i)
		}
	}
}

// TestSodModeGetIsReadOnly: GET must not write an audit log row or mutate
// the toggle state.
func TestSodModeGetIsReadOnly(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)

	uid := realUserID(t, tx)
	seedDengbaoToggleOff(t, tx)

	// Count audit log rows before.
	var auditBefore int
	_ = tx.QueryRow(ctx, `SELECT count(*) FROM admin_audit_log`).Scan(&auditBefore)

	h := NewSodModeHandler(tx, testsupport.TestLogger())
	w := httptest.NewRecorder()
	h.Get(w, getSodModeReq(uid))

	if w.Code != http.StatusOK {
		t.Fatalf("GET: expected 200, got %d — body: %s", w.Code, w.Body.String())
	}

	// Toggle must still be OFF.
	if dengbaoEnabled(t, tx) {
		t.Fatal("GET must not mutate the toggle state")
	}

	// No new audit log rows.
	var auditAfter int
	_ = tx.QueryRow(ctx, `SELECT count(*) FROM admin_audit_log`).Scan(&auditAfter)
	if auditAfter != auditBefore {
		t.Fatalf("GET must not write audit_log rows (before=%d after=%d)", auditBefore, auditAfter)
	}
}
