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

// newTestNLHandler opens the test pool and returns a NamedLocationsHandler.
func newTestNLHandler(t *testing.T) *NamedLocationsHandler {
	t.Helper()
	pool := testsupport.OpenTestPool(t)
	return NewNamedLocationsHandler(pool, testsupport.TestLogger())
}

// cleanupNamedLocations deletes test-created named_locations rows by prefix.
func cleanupNamedLocations(t *testing.T, h *NamedLocationsHandler, namePrefix string) {
	t.Helper()
	_, _ = h.pool.Exec(context.Background(),
		`DELETE FROM named_locations WHERE name LIKE $1`, namePrefix+"%")
}

// seedNLActor seeds the domain+user rows needed for admin_audit_log FK.
// The reducer's audit log INSERT has a FK to users(id); actor must exist.
func seedNLActor(t *testing.T, h *NamedLocationsHandler) int64 {
	t.Helper()
	ctx := context.Background()
	const (
		domainID = int64(97200)
		userID   = int64(84200)
	)
	_, _ = h.pool.Exec(ctx,
		`INSERT INTO domains (id, name, is_local) VALUES ($1, 'nltest.test', TRUE) ON CONFLICT DO NOTHING`,
		domainID)
	_, _ = h.pool.Exec(ctx,
		`INSERT INTO users (id, username, domain_id, email, display_name, enabled)
		 VALUES ($1, 'nltest_u', $2, 'nltest@nltest.test', 'NL Test User', TRUE)
		 ON CONFLICT (id) DO NOTHING`,
		userID, domainID)
	return userID
}

// TestNamedLocations_CreateListDeleteRestore exercises the full lifecycle:
// POST creates → GET lists it → DELETE soft-deletes (gone from default,
// present with ?include_deleted=1) → POST /restore brings it back.
func TestNamedLocations_CreateListDeleteRestore(t *testing.T) {
	h := newTestNLHandler(t)
	t.Cleanup(func() { cleanupNamedLocations(t, h, "TestNL-D1-") })

	ctx := context.Background()
	actorID := seedNLActor(t, h)
	uniqueName := fmt.Sprintf("TestNL-D1-%d", actorID)

	// POST — create.
	body, _ := json.Marshal(map[string]any{
		"name":        uniqueName,
		"description": "d1 test",
		"cidrs":       []string{"10.0.0.0/8"},
		"countries":   []string{"US"},
		"is_trusted":  true,
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/conditional-access/named-locations",
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

	// GET — list (default; no include_deleted).
	listReq := httptest.NewRequest(http.MethodGet, "/admin/conditional-access/named-locations", nil)
	listReq = listReq.WithContext(auth.ContextWithUser(ctx, &auth.Claims{UserID: actorID}))
	listW := httptest.NewRecorder()
	h.List(listW, listReq)
	if listW.Code != http.StatusOK {
		t.Fatalf("List: got %d; body=%s", listW.Code, listW.Body.String())
	}
	if !jsonContainsID(listW.Body.Bytes(), id) {
		t.Fatalf("List: newly created id %d not found in response: %s", id, listW.Body.String())
	}

	// DELETE — soft-delete.
	delReq := httptest.NewRequest(http.MethodDelete,
		fmt.Sprintf("/admin/conditional-access/named-locations/%d", id), nil)
	delReq.SetPathValue("id", fmt.Sprintf("%d", id))
	delReq = delReq.WithContext(auth.ContextWithUser(ctx, &auth.Claims{UserID: actorID}))
	delW := httptest.NewRecorder()
	h.Delete(delW, delReq)
	if delW.Code != http.StatusNoContent {
		t.Fatalf("Delete: got %d, want 204; body=%s", delW.Code, delW.Body.String())
	}

	// GET default — must NOT contain deleted id.
	listReq2 := httptest.NewRequest(http.MethodGet, "/admin/conditional-access/named-locations", nil)
	listReq2 = listReq2.WithContext(auth.ContextWithUser(ctx, &auth.Claims{UserID: actorID}))
	listW2 := httptest.NewRecorder()
	h.List(listW2, listReq2)
	if listW2.Code != http.StatusOK {
		t.Fatalf("List(after delete): got %d", listW2.Code)
	}
	if jsonContainsID(listW2.Body.Bytes(), id) {
		t.Fatalf("List(after delete): deleted id %d still in default list", id)
	}

	// GET ?include_deleted=1 — must contain it.
	listReq3 := httptest.NewRequest(http.MethodGet, "/admin/conditional-access/named-locations?include_deleted=1", nil)
	listReq3 = listReq3.WithContext(auth.ContextWithUser(ctx, &auth.Claims{UserID: actorID}))
	listW3 := httptest.NewRecorder()
	h.List(listW3, listReq3)
	if listW3.Code != http.StatusOK {
		t.Fatalf("List(include_deleted): got %d", listW3.Code)
	}
	if !jsonContainsID(listW3.Body.Bytes(), id) {
		t.Fatalf("List(include_deleted): id %d missing from tombstoned list", id)
	}

	// POST /restore — restore.
	restoreReq := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/admin/conditional-access/named-locations/%d/restore", id), nil)
	restoreReq.SetPathValue("id", fmt.Sprintf("%d", id))
	restoreReq = restoreReq.WithContext(auth.ContextWithUser(ctx, &auth.Claims{UserID: actorID}))
	restoreW := httptest.NewRecorder()
	h.Restore(restoreW, restoreReq)
	if restoreW.Code != http.StatusOK {
		t.Fatalf("Restore: got %d, want 200; body=%s", restoreW.Code, restoreW.Body.String())
	}

	// GET default — must contain id again.
	listReq4 := httptest.NewRequest(http.MethodGet, "/admin/conditional-access/named-locations", nil)
	listReq4 = listReq4.WithContext(auth.ContextWithUser(ctx, &auth.Claims{UserID: actorID}))
	listW4 := httptest.NewRecorder()
	h.List(listW4, listReq4)
	if listW4.Code != http.StatusOK {
		t.Fatalf("List(after restore): got %d", listW4.Code)
	}
	if !jsonContainsID(listW4.Body.Bytes(), id) {
		t.Fatalf("List(after restore): id %d not back in active list", id)
	}
}

// TestNamedLocations_CreateNoAuth verifies POST without auth context returns 401.
func TestNamedLocations_CreateNoAuth(t *testing.T) {
	h := &NamedLocationsHandler{logger: testsupport.TestLogger()}
	body, _ := json.Marshal(map[string]any{"name": "no-auth"})
	req := httptest.NewRequest(http.MethodPost, "/admin/conditional-access/named-locations",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Create(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("Create(no auth): got %d, want 401", w.Code)
	}
}

// TestNamedLocations_CreateMissingName verifies POST without name returns 400.
func TestNamedLocations_CreateMissingName(t *testing.T) {
	h := &NamedLocationsHandler{logger: testsupport.TestLogger()}
	body, _ := json.Marshal(map[string]any{"description": "missing name"})
	req := httptest.NewRequest(http.MethodPost, "/admin/conditional-access/named-locations",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 1}))
	w := httptest.NewRecorder()
	h.Create(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("Create(missing name): got %d, want 400", w.Code)
	}
}

// TestNamedLocations_DeleteInvalidID verifies DELETE with non-numeric id returns 400.
func TestNamedLocations_DeleteInvalidID(t *testing.T) {
	h := &NamedLocationsHandler{logger: testsupport.TestLogger()}
	req := httptest.NewRequest(http.MethodDelete, "/admin/conditional-access/named-locations/abc", nil)
	req.SetPathValue("id", "abc")
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 1}))
	w := httptest.NewRecorder()
	h.Delete(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("Delete(invalid id): got %d, want 400", w.Code)
	}
}

// jsonContainsID scans a JSON array for an "id" field matching the given value.
func jsonContainsID(b []byte, id int64) bool {
	var rows []map[string]any
	if err := json.Unmarshal(b, &rows); err != nil {
		return false
	}
	for _, row := range rows {
		switch v := row["id"].(type) {
		case float64:
			if int64(v) == id {
				return true
			}
		}
	}
	return false
}
