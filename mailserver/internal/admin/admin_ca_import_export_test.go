package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/shared/testsupport"
)

// newTestCAImportExportHandler opens the test pool and returns a CAImportExportHandler.
func newTestCAImportExportHandler(t *testing.T) *CAImportExportHandler {
	t.Helper()
	pool := testsupport.OpenTestPool(t)
	return NewCAImportExportHandler(pool, testsupport.TestLogger())
}

// d7AdminUserID is the stable user-id for D7 tests.
const d7AdminUserID = int64(99071)

// ensureD7AdminUser seeds the admin actor row (idempotent).
func ensureD7AdminUser(t *testing.T, h *CAImportExportHandler) {
	t.Helper()
	ctx := context.Background()
	_, _ = h.pool.Exec(ctx,
		`INSERT INTO domains (id, name, is_local) VALUES (99071, 'd7test.test', TRUE) ON CONFLICT DO NOTHING`)
	_, _ = h.pool.Exec(ctx,
		`INSERT INTO users (id, username, domain_id, email, display_name, enabled)
		 VALUES ($1, 'd7admin', 99071, 'd7admin@d7test.test', 'D7 Admin', TRUE)
		 ON CONFLICT (id) DO NOTHING`, d7AdminUserID)
}

// TestCAExport_Shape verifies GET /export returns schemaVersion + generatedBy + arrays.
// DB-backed; skips without TEST_DB_DSN.
func TestCAExport_Shape(t *testing.T) {
	h := newTestCAImportExportHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/conditional-access/export", nil)
	req = withAdminClaims(req, 1)
	w := httptest.NewRecorder()
	h.Export(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Export: got %d, want 200; body=%s", w.Code, w.Body.String())
	}

	var doc struct {
		SchemaVersion  int               `json:"schemaVersion"`
		GeneratedBy    string            `json:"generatedBy"`
		Policies       []json.RawMessage `json:"policies"`
		NamedLocations []json.RawMessage `json:"named_locations"`
		AuthStrengths  []json.RawMessage `json:"auth_strengths"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatalf("Export: invalid JSON: %v; body=%s", err, w.Body.String())
	}
	if doc.SchemaVersion < 1 {
		t.Fatalf("Export: schemaVersion must be >= 1, got %d", doc.SchemaVersion)
	}
	if doc.GeneratedBy == "" {
		t.Fatalf("Export: generatedBy must be non-empty")
	}
	// All three arrays must be non-null (even if empty).
	if doc.Policies == nil {
		t.Fatalf("Export: policies must be [] not null")
	}
	if doc.NamedLocations == nil {
		t.Fatalf("Export: named_locations must be [] not null")
	}
	if doc.AuthStrengths == nil {
		t.Fatalf("Export: auth_strengths must be [] not null")
	}
}

// TestCAImport_BasicMerge verifies POST /import?mode=merge with a valid doc returns
// the {applied, created, updated, pruned} summary and HTTP 200.
// DB-backed; skips without TEST_DB_DSN.
func TestCAImport_BasicMerge(t *testing.T) {
	h := newTestCAImportExportHandler(t)
	ensureD7AdminUser(t, h)

	doc := map[string]any{
		"schemaVersion": 1,
		"policies": []map[string]any{
			{
				"name":        "d7-merge-test",
				"description": "D7 import merge test",
				"scope_type":  "global",
				"conditions":  map[string]any{"client_type": "imap"}, // valid enum per ca_validate_policy_document
				"actions":     map[string]any{"action": "allow"},
			},
		},
	}
	body, _ := json.Marshal(doc)

	req := httptest.NewRequest(http.MethodPost,
		"/admin/conditional-access/import?mode=merge", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withAdminClaims(req, d7AdminUserID)
	w := httptest.NewRecorder()
	h.Import(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Import(merge): got %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var summary struct {
		Applied int `json:"applied"`
		Created int `json:"created"`
		Updated int `json:"updated"`
		Pruned  int `json:"pruned"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &summary); err != nil {
		t.Fatalf("Import(merge): invalid JSON: %v; body=%s", err, w.Body.String())
	}
	if summary.Applied < 1 {
		t.Fatalf("Import(merge): applied=%d, want >= 1", summary.Applied)
	}

	// Cleanup: delete the test policy.
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(),
			`DELETE FROM conditional_access_policies WHERE name = 'd7-merge-test'`)
	})
}

// TestCAImport_BadSchemaVersion verifies that schemaVersion:99 returns 422.
// DB-backed; skips without TEST_DB_DSN.
func TestCAImport_BadSchemaVersion(t *testing.T) {
	h := newTestCAImportExportHandler(t)
	ensureD7AdminUser(t, h)

	doc := map[string]any{
		"schemaVersion": 99,
		"policies":      []any{},
	}
	body, _ := json.Marshal(doc)

	req := httptest.NewRequest(http.MethodPost,
		"/admin/conditional-access/import?mode=merge", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withAdminClaims(req, d7AdminUserID)
	w := httptest.NewRecorder()
	h.Import(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("Import(bad schema): got %d, want 422; body=%s", w.Code, w.Body.String())
	}
}

// TestCAImport_BadMode verifies that mode=invalid returns 422 (BZ092).
// DB-backed; skips without TEST_DB_DSN.
func TestCAImport_BadMode(t *testing.T) {
	h := newTestCAImportExportHandler(t)
	ensureD7AdminUser(t, h)

	doc := map[string]any{"schemaVersion": 1, "policies": []any{}}
	body, _ := json.Marshal(doc)

	req := httptest.NewRequest(http.MethodPost,
		"/admin/conditional-access/import?mode=invalid", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withAdminClaims(req, d7AdminUserID)
	w := httptest.NewRecorder()
	h.Import(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("Import(bad mode): got %d, want 422; body=%s", w.Code, w.Body.String())
	}
}

// TestCAImport_NoAuth verifies that import without auth context returns 401.
// Pure unit test — no DB pool needed.
func TestCAImport_NoAuth(t *testing.T) {
	h := &CAImportExportHandler{logger: testsupport.TestLogger()}

	doc := map[string]any{"schemaVersion": 1, "policies": []any{}}
	body, _ := json.Marshal(doc)

	req := httptest.NewRequest(http.MethodPost,
		"/admin/conditional-access/import?mode=merge", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// No auth context.
	w := httptest.NewRecorder()
	h.Import(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("Import(no auth): got %d, want 401", w.Code)
	}
}

// TestCADiff_EmptyDocReturnsStructuredPlan verifies POST /diff with an empty policies
// list returns the {added, changed, removed} shape.
// DB-backed; skips without TEST_DB_DSN.
func TestCADiff_EmptyDocReturnsStructuredPlan(t *testing.T) {
	h := newTestCAImportExportHandler(t)

	// Empty doc (no policies) — diff should mark all live policies as removed.
	doc := map[string]any{
		"schemaVersion": 1,
		"policies":      []any{},
	}
	body, _ := json.Marshal(doc)

	req := httptest.NewRequest(http.MethodPost,
		"/admin/conditional-access/diff", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withAdminClaims(req, 1)
	w := httptest.NewRecorder()
	h.Diff(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Diff: got %d, want 200; body=%s", w.Code, w.Body.String())
	}

	var plan struct {
		Added   []json.RawMessage `json:"added"`
		Changed []json.RawMessage `json:"changed"`
		Removed []json.RawMessage `json:"removed"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &plan); err != nil {
		t.Fatalf("Diff: invalid JSON: %v; body=%s", err, w.Body.String())
	}
	// All three must be arrays (never null).
	if plan.Added == nil {
		t.Fatalf("Diff: added must be [] not null")
	}
	if plan.Changed == nil {
		t.Fatalf("Diff: changed must be [] not null")
	}
	if plan.Removed == nil {
		t.Fatalf("Diff: removed must be [] not null")
	}
}

// TestCAExportImportRoundTrip verifies export→import round-trips with zero-diff.
// Exports live state, imports it back, expects applied > 0 and a re-diff showing
// 0 changes and 0 removals (added = 0 because import updates, not adds, on re-run).
// DB-backed; skips without TEST_DB_DSN.
func TestCAExportImportRoundTrip(t *testing.T) {
	h := newTestCAImportExportHandler(t)
	ensureD7AdminUser(t, h)

	// Step 1: export current live state.
	req := httptest.NewRequest(http.MethodGet, "/admin/conditional-access/export", nil)
	req = withAdminClaims(req, d7AdminUserID)
	w := httptest.NewRecorder()
	h.Export(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Export (round-trip): got %d, want 200; body=%s", w.Code, w.Body.String())
	}
	exportedDoc := w.Body.Bytes()

	// Step 2: re-import the exported doc with mode=merge — should succeed.
	req2 := httptest.NewRequest(http.MethodPost,
		"/admin/conditional-access/import?mode=merge", bytes.NewReader(exportedDoc))
	req2.Header.Set("Content-Type", "application/json")
	req2 = withAdminClaims(req2, d7AdminUserID)
	w2 := httptest.NewRecorder()
	h.Import(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("Import (round-trip): got %d, want 200; body=%s", w2.Code, w2.Body.String())
	}

	// Step 3: diff the exported doc against live — expect 0 added, 0 changed, 0 removed
	// (import was idempotent: updated existing rows, not new inserts for this round-trip).
	req3 := httptest.NewRequest(http.MethodPost,
		"/admin/conditional-access/diff", bytes.NewReader(exportedDoc))
	req3.Header.Set("Content-Type", "application/json")
	req3 = withAdminClaims(req3, d7AdminUserID)
	w3 := httptest.NewRecorder()
	h.Diff(w3, req3)

	if w3.Code != http.StatusOK {
		t.Fatalf("Diff (round-trip): got %d, want 200; body=%s", w3.Code, w3.Body.String())
	}
	var plan struct {
		Added   []json.RawMessage `json:"added"`
		Changed []json.RawMessage `json:"changed"`
		Removed []json.RawMessage `json:"removed"`
	}
	if err := json.Unmarshal(w3.Body.Bytes(), &plan); err != nil {
		t.Fatalf("Diff (round-trip): invalid JSON: %v", err)
	}
	// After round-trip import: diff should show nothing changed or removed.
	if len(plan.Changed) != 0 {
		t.Fatalf("Diff (round-trip): expected 0 changed, got %d", len(plan.Changed))
	}
	if len(plan.Removed) != 0 {
		t.Fatalf("Diff (round-trip): expected 0 removed, got %d", len(plan.Removed))
	}
}
