package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/testsupport"
)

// newTestASHandler opens the test pool and returns an AuthStrengthsHandler.
func newTestASHandler(t *testing.T) *AuthStrengthsHandler {
	t.Helper()
	pool := testsupport.OpenTestPool(t)
	return NewAuthStrengthsHandler(pool, testsupport.TestLogger())
}

// cleanupAuthStrengths deletes test-created auth_strengths rows by slug prefix.
func cleanupAuthStrengths(t *testing.T, h *AuthStrengthsHandler, slugPrefix string) {
	t.Helper()
	_, _ = h.pool.Exec(context.Background(),
		`DELETE FROM auth_strengths WHERE slug LIKE $1 AND builtin = false`, slugPrefix+"%")
}

// seedASActor seeds the domain+user rows needed for admin_audit_log FK.
func seedASActor(t *testing.T, h *AuthStrengthsHandler) int64 {
	t.Helper()
	ctx := context.Background()
	const (
		domainID = int64(97201)
		userID   = int64(84201)
	)
	_, _ = h.pool.Exec(ctx,
		`INSERT INTO domains (id, name, is_local) VALUES ($1, 'astest.test', TRUE) ON CONFLICT DO NOTHING`,
		domainID)
	_, _ = h.pool.Exec(ctx,
		`INSERT INTO users (id, username, domain_id, email, display_name, enabled)
		 VALUES ($1, 'astest_u', $2, 'astest@astest.test', 'AS Test User', TRUE)
		 ON CONFLICT (id) DO NOTHING`,
		userID, domainID)
	return userID
}

// TestAuthStrengths_CreateListUpdate exercises create → list → update lifecycle.
func TestAuthStrengths_CreateListUpdate(t *testing.T) {
	h := newTestASHandler(t)
	slug := "test-as-d1-create"
	t.Cleanup(func() { cleanupAuthStrengths(t, h, "test-as-d1-") })

	ctx := context.Background()
	actorID := seedASActor(t, h)

	// POST — create.
	body, _ := json.Marshal(map[string]any{
		"slug":         slug,
		"name":         "D1 Test Strength",
		"combinations": [][]string{{"password", "totp"}},
		"min_acr":      "aal2",
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/conditional-access/auth-strengths",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(auth.ContextWithUser(ctx, &auth.Claims{UserID: actorID}))
	w := httptest.NewRecorder()
	h.Create(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Create: got %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var created struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil || created.ID == 0 {
		t.Fatalf("Create: invalid JSON or missing id: %s", w.Body.String())
	}
	id := created.ID

	// GET — list: must contain the new row.
	listReq := httptest.NewRequest(http.MethodGet, "/admin/conditional-access/auth-strengths", nil)
	listW := httptest.NewRecorder()
	h.List(listW, listReq)
	if listW.Code != http.StatusOK {
		t.Fatalf("List: got %d", listW.Code)
	}
	if !jsonContainsID(listW.Body.Bytes(), id) {
		t.Fatalf("List: new id %d not found; body=%s", id, listW.Body.String())
	}

	// PUT — update name.
	updBody, _ := json.Marshal(map[string]any{
		"slug":         slug,
		"name":         "D1 Test Strength Updated",
		"combinations": [][]string{{"password", "totp"}},
		"min_acr":      "aal2",
	})
	updReq := httptest.NewRequest(http.MethodPut,
		fmt.Sprintf("/admin/conditional-access/auth-strengths/%d", id),
		bytes.NewReader(updBody))
	updReq.SetPathValue("id", fmt.Sprintf("%d", id))
	updReq.Header.Set("Content-Type", "application/json")
	updReq = updReq.WithContext(auth.ContextWithUser(ctx, &auth.Claims{UserID: actorID}))
	updW := httptest.NewRecorder()
	h.Update(updW, updReq)
	if updW.Code != http.StatusOK {
		t.Fatalf("Update: got %d, want 200; body=%s", updW.Code, updW.Body.String())
	}
}

// TestAuthStrengths_BuiltinDeleteReturns400 verifies that attempting to delete
// a built-in auth strength (e.g. slug='phishing-resistant') returns HTTP 400.
// DB-backed; skips without DB_DSN.
func TestAuthStrengths_BuiltinDeleteReturns400(t *testing.T) {
	h := newTestASHandler(t)

	// Fetch the built-in row id; actor seed needed for the reducer's audit log.
	actorID := seedASActor(t, h)

	var builtinID int64
	err := h.pool.QueryRow(context.Background(),
		`SELECT id FROM auth_strengths WHERE builtin = true LIMIT 1`,
	).Scan(&builtinID)
	if err != nil || builtinID == 0 {
		t.Skipf("no built-in auth_strengths row found (test DB might not have seeds): %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete,
		fmt.Sprintf("/admin/conditional-access/auth-strengths/%d", builtinID), nil)
	req.SetPathValue("id", fmt.Sprintf("%d", builtinID))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: actorID}))
	w := httptest.NewRecorder()
	h.Delete(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("Delete(builtin): got %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

// TestAuthStrengths_CreateNoAuth verifies POST without auth context returns 401.
func TestAuthStrengths_CreateNoAuth(t *testing.T) {
	h := &AuthStrengthsHandler{logger: testsupport.TestLogger()}
	body, _ := json.Marshal(map[string]any{"slug": "test", "name": "x"})
	req := httptest.NewRequest(http.MethodPost, "/admin/conditional-access/auth-strengths",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Create(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("Create(no auth): got %d, want 401", w.Code)
	}
}

// TestAuthStrengths_CreateMissingSlug verifies POST without slug returns 400.
func TestAuthStrengths_CreateMissingSlug(t *testing.T) {
	h := &AuthStrengthsHandler{logger: testsupport.TestLogger()}
	body, _ := json.Marshal(map[string]any{"name": "missing slug"})
	req := httptest.NewRequest(http.MethodPost, "/admin/conditional-access/auth-strengths",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 1}))
	w := httptest.NewRecorder()
	h.Create(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("Create(missing slug): got %d, want 400", w.Code)
	}
}

// TestAuthStrengths_ListBuiltins verifies the 3 seeded built-ins appear in List.
// DB-backed; skips without DB_DSN.
func TestAuthStrengths_ListBuiltins(t *testing.T) {
	h := newTestASHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/admin/conditional-access/auth-strengths", nil)
	w := httptest.NewRecorder()
	h.List(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("List: got %d", w.Code)
	}
	var rows []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
		t.Fatalf("List: invalid JSON: %v", err)
	}
	if len(rows) < 3 {
		t.Fatalf("List: want at least 3 built-ins, got %d rows", len(rows))
	}
}
