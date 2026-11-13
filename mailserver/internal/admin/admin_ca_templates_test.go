package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/testsupport"
)

// newTestCATemplatesHandler opens the test pool and returns a CATemplatesHandler.
func newTestCATemplatesHandler(t *testing.T) *CATemplatesHandler {
	t.Helper()
	pool := testsupport.OpenTestPool(t)
	return NewCATemplatesHandler(pool, testsupport.TestLogger())
}

// d4AdminUserID is the stable user id for D4 tests; separate range from D2/D3.
const d4AdminUserID = int64(99041)

// ensureD4AdminUser seeds the actor row for admin_audit_log FK (idempotent).
func ensureD4AdminUser(t *testing.T, h *CATemplatesHandler) {
	t.Helper()
	ctx := context.Background()
	_, _ = h.pool.Exec(ctx,
		`INSERT INTO domains (id, name, is_local) VALUES (99041, 'd4test.test', TRUE) ON CONFLICT DO NOTHING`)
	_, _ = h.pool.Exec(ctx,
		`INSERT INTO users (id, username, domain_id, email, display_name, enabled)
		 VALUES ($1, 'd4admin', 99041, 'd4admin@d4test.test', 'D4 Admin', TRUE)
		 ON CONFLICT (id) DO NOTHING`, d4AdminUserID)
}

// TestCATemplates_ListReturnsStarters verifies GET /templates returns the 3 seeded
// starter templates from V030. DB-backed; skips without DB_DSN.
func TestCATemplates_ListReturnsStarters(t *testing.T) {
	h := newTestCATemplatesHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/conditional-access/templates", nil)
	w := httptest.NewRecorder()
	h.List(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("List: got %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var rows []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
		t.Fatalf("List: invalid JSON: %v", err)
	}
	if len(rows) < 3 {
		t.Fatalf("List: want at least 3 starter templates, got %d; body=%s", len(rows), w.Body.String())
	}

	// Verify the 3 known slugs are present.
	slugs := make(map[string]bool, len(rows))
	for _, row := range rows {
		if s, ok := row["slug"].(string); ok {
			slugs[s] = true
		}
	}
	for _, expected := range []string{"block-legacy-auth", "mfa-for-admins", "block-by-geo"} {
		if !slugs[expected] {
			t.Fatalf("List: missing slug %q; slugs=%v; body=%s", expected, slugs, w.Body.String())
		}
	}
}

// TestCATemplates_InstantiateBlockLegacyAuth exercises the full round-trip:
// POST .../block-legacy-auth/instantiate returns a new policy in report_only
// state with the acting admin auto-excluded.
// DB-backed; skips without DB_DSN.
func TestCATemplates_InstantiateBlockLegacyAuth(t *testing.T) {
	h := newTestCATemplatesHandler(t)
	ensureD4AdminUser(t, h)

	ctx := context.Background()

	req := httptest.NewRequest(http.MethodPost,
		"/admin/conditional-access/templates/block-legacy-auth/instantiate", nil)
	req.SetPathValue("slug", "block-legacy-auth")
	req = req.WithContext(auth.ContextWithUser(ctx, &auth.Claims{UserID: d4AdminUserID}))
	w := httptest.NewRecorder()
	h.Instantiate(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("Instantiate: got %d, want 201; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		ID           int64  `json:"id"`
		State        string `json:"state"`
		ExcludeUsers []any  `json:"exclude_users"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.ID == 0 {
		t.Fatalf("Instantiate: invalid JSON or missing id: %s", w.Body.String())
	}
	t.Cleanup(func() {
		_, _ = h.pool.Exec(ctx, `DELETE FROM conditional_access_policies WHERE id = $1`, resp.ID)
	})

	// Policy must be born in report_only state.
	if resp.State != "report_only" {
		t.Fatalf("Instantiate: state=%q, want report_only", resp.State)
	}

	// Admin must be in exclude_users (break-glass auto-exclude).
	found := false
	for _, v := range resp.ExcludeUsers {
		if id, ok := v.(float64); ok && int64(id) == d4AdminUserID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Instantiate: admin %d not in exclude_users=%v", d4AdminUserID, resp.ExcludeUsers)
	}
}

// TestCATemplates_InstantiateUnknownSlug — POST with a nonexistent slug → BZ085 → 400.
// DB-backed; skips without DB_DSN.
func TestCATemplates_InstantiateUnknownSlug(t *testing.T) {
	h := newTestCATemplatesHandler(t)
	ensureD4AdminUser(t, h)

	ctx := context.Background()
	req := httptest.NewRequest(http.MethodPost,
		"/admin/conditional-access/templates/no-such-slug/instantiate", nil)
	req.SetPathValue("slug", "no-such-slug")
	req = req.WithContext(auth.ContextWithUser(ctx, &auth.Claims{UserID: d4AdminUserID}))
	w := httptest.NewRecorder()
	h.Instantiate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("Instantiate(unknown slug): got %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

// TestCATemplates_InstantiateNoAuth — POST without auth context returns 401.
// Pure unit test — no DB pool needed.
func TestCATemplates_InstantiateNoAuth(t *testing.T) {
	h := &CATemplatesHandler{logger: testsupport.TestLogger()}

	req := httptest.NewRequest(http.MethodPost,
		"/admin/conditional-access/templates/block-legacy-auth/instantiate", nil)
	req.SetPathValue("slug", "block-legacy-auth")
	// No auth context.
	w := httptest.NewRecorder()
	h.Instantiate(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("Instantiate(no auth): got %d, want 401", w.Code)
	}
}

// TestCATemplates_InstantiateMissingSlug — empty slug path value → 400.
// Pure unit test — no DB pool needed.
func TestCATemplates_InstantiateMissingSlug(t *testing.T) {
	h := &CATemplatesHandler{logger: testsupport.TestLogger()}

	req := httptest.NewRequest(http.MethodPost,
		"/admin/conditional-access/templates//instantiate", nil)
	// SetPathValue("slug", "") leaves it empty.
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 1}))
	w := httptest.NewRecorder()
	h.Instantiate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("Instantiate(missing slug): got %d, want 400", w.Code)
	}
}

// TestCATemplates_ListShape verifies each template row has the required fields.
// DB-backed; skips without DB_DSN.
func TestCATemplates_ListShape(t *testing.T) {
	h := newTestCATemplatesHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/conditional-access/templates", nil)
	w := httptest.NewRecorder()
	h.List(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("List: got %d", w.Code)
	}
	var rows []struct {
		ID                int64  `json:"id"`
		Slug              string `json:"slug"`
		Name              string `json:"name"`
		Description       string `json:"description"`
		ScopeType         string `json:"scope_type"`
		SuggestedPriority int    `json:"suggested_priority"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
		t.Fatalf("List: invalid JSON: %v; body=%s", err, w.Body.String())
	}
	for i, row := range rows {
		if row.ID == 0 {
			t.Errorf("row[%d]: missing id", i)
		}
		if row.Slug == "" {
			t.Errorf("row[%d]: missing slug", i)
		}
		if row.Name == "" {
			t.Errorf("row[%d]: missing name", i)
		}
		if row.ScopeType == "" {
			t.Errorf("row[%d]: missing scope_type", i)
		}
		_ = fmt.Sprintf("row %d ok: %s", i, row.Slug) // suppress unused
	}
}
