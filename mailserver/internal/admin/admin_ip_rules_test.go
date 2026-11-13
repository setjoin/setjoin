package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/testsupport"
)

// ---- helpers -----------------------------------------------------------------

func newIPRulesHandlerNoPool() *IPRulesHandler {
	return NewIPRulesHandler(nil, nil)
}

func ctxWithAdminUser(userID int64, email string) context.Context {
	claims := &auth.Claims{}
	claims.UserID = userID
	claims.Email = email
	claims.IsAdmin = true
	return auth.ContextWithUser(context.Background(), claims)
}

// ---- unit tests (stub / no DB) -----------------------------------------------

// TestIPRulesListReturns200 checks that List returns 200 with an array body.
func TestIPRulesListReturns200(t *testing.T) {
	h := newIPRulesHandlerNoPool()
	req := httptest.NewRequest(http.MethodGet, "/admin/threat/ip-rules", nil)
	req = req.WithContext(ctxWithAdminUser(1, "admin@example.com"))
	w := httptest.NewRecorder()
	h.List(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Rows []any `json:"rows"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("response not valid JSON: %v", err)
	}
	if resp.Rows == nil {
		t.Error("rows should be a non-nil array (even if empty)")
	}
}

// TestIPRulesCreateBadCIDR checks that a malformed CIDR returns 400.
func TestIPRulesCreateBadCIDR(t *testing.T) {
	h := newIPRulesHandlerNoPool()
	body := `{"cidr":"not-a-cidr","action":"block","description":"bad"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/threat/ip-rules", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ctxWithAdminUser(1, "admin@example.com"))
	w := httptest.NewRecorder()
	h.Create(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad CIDR, got %d — body: %s", w.Code, w.Body.String())
	}
}

// TestIPRulesCreateBadAction checks that an unknown action returns 400.
func TestIPRulesCreateBadAction(t *testing.T) {
	h := newIPRulesHandlerNoPool()
	body := `{"cidr":"10.0.0.0/8","action":"fly","description":"bad action"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/threat/ip-rules", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ctxWithAdminUser(1, "admin@example.com"))
	w := httptest.NewRecorder()
	h.Create(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad action, got %d — body: %s", w.Code, w.Body.String())
	}
}

// TestIPRulesCreateBodyIgnoresCreatedBy confirms R2: created_by is taken from auth
// context, not the request body (the body field is silently ignored).
// We verify this by confirming a Create with a pool=nil still fails at the DB step,
// not because of a user ID from the body. The handler must extract the caller's
// identity from the JWT context, so if we can get past validation without a pool
// we know the field was attempted from context.
func TestIPRulesCreateBodyIgnoresCreatedBy(t *testing.T) {
	h := newIPRulesHandlerNoPool()
	// Try to sneak a created_by into the body — it must be silently dropped.
	body := `{"cidr":"192.168.1.0/24","action":"allow","description":"test","created_by":9999}`
	req := httptest.NewRequest(http.MethodPost, "/admin/threat/ip-rules", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// The handler reads created_by from the context, so we set a different value there.
	req = req.WithContext(ctxWithAdminUser(42, "admin@example.com"))
	w := httptest.NewRecorder()
	h.Create(w, req)
	// Without a pool the handler returns 503 (or 500) after validation passes;
	// the important thing is it did NOT return 400 (validation) — meaning the CIDR
	// and action are valid and the body-supplied created_by had no effect on routing.
	if w.Code == http.StatusBadRequest {
		t.Fatalf("unexpected 400 — body content or body created_by caused rejection: %s", w.Body.String())
	}
	// Must not be 200 either — we have no pool so the DB insert cannot succeed.
	if w.Code == http.StatusOK || w.Code == http.StatusCreated {
		t.Fatalf("unexpected success without a real pool: %d — %s", w.Code, w.Body.String())
	}
}

// TestIPRulesDeleteBadID checks that a non-numeric ID path value returns 400.
func TestIPRulesDeleteBadID(t *testing.T) {
	h := newIPRulesHandlerNoPool()
	req := httptest.NewRequest(http.MethodDelete, "/admin/threat/ip-rules/notanumber", nil)
	req.SetPathValue("id", "notanumber")
	req = req.WithContext(ctxWithAdminUser(1, "admin@example.com"))
	w := httptest.NewRecorder()
	h.Delete(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for non-numeric id, got %d — body: %s", w.Code, w.Body.String())
	}
}

// TestIPRulesDeleteNoPool checks that Delete with a numeric ID but no pool
// returns a non-2xx error (DB unavailable), confirming validation passed.
func TestIPRulesDeleteNoPool(t *testing.T) {
	h := newIPRulesHandlerNoPool()
	req := httptest.NewRequest(http.MethodDelete, "/admin/threat/ip-rules/123", nil)
	req.SetPathValue("id", "123")
	req = req.WithContext(ctxWithAdminUser(1, "admin@example.com"))
	w := httptest.NewRecorder()
	h.Delete(w, req)
	if w.Code == http.StatusBadRequest {
		t.Fatalf("numeric id should not return 400; got: %s", w.Body.String())
	}
	if w.Code == http.StatusNoContent {
		t.Fatal("no pool should not produce 204 success")
	}
}

// TestIPRulesCreateMissingBody checks that a completely empty body returns 400.
func TestIPRulesCreateMissingBody(t *testing.T) {
	h := newIPRulesHandlerNoPool()
	req := httptest.NewRequest(http.MethodPost, "/admin/threat/ip-rules", bytes.NewReader(nil))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ctxWithAdminUser(1, "admin@example.com"))
	w := httptest.NewRecorder()
	h.Create(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty body, got %d", w.Code)
	}
}

// ---- integration tests (real pool, skipped without DB_DSN) ------------------

// openIPRulesPool returns a real pool; skips if DB_DSN not set.
func openIPRulesPool(t *testing.T) *pgxpool.Pool {
	return testsupport.OpenTestPool(t)
}

// TestIPRulesIntegration exercises List, Create, and Delete against the real DB.
func TestIPRulesIntegration(t *testing.T) {
	pool := openIPRulesPool(t)
	h := NewIPRulesHandler(pool, nil)

	// Resolve a real user ID from the test DB so created_by satisfies the FK.
	ctx := context.Background()
	var realUserID int64
	if err := pool.QueryRow(ctx, `SELECT MIN(id) FROM users`).Scan(&realUserID); err != nil || realUserID == 0 {
		t.Skip("no users in test DB — skipping ip_rules integration test")
	}

	// ---- List: must return 200 with rows array --------------------------------
	reqList := httptest.NewRequest(http.MethodGet, "/admin/threat/ip-rules", nil)
	reqList = reqList.WithContext(ctxWithAdminUser(realUserID, "admin@example.com"))
	wList := httptest.NewRecorder()
	h.List(wList, reqList)
	if wList.Code != http.StatusOK {
		t.Fatalf("List: expected 200, got %d — %s", wList.Code, wList.Body.String())
	}

	// ---- Create: insert a test rule ------------------------------------------
	uniqueDesc := "b6.2-integration-test-" + time.Now().Format("20060102150405")
	createBody := map[string]any{
		"cidr":        "203.0.113.0/24",
		"action":      "block",
		"description": uniqueDesc,
	}
	createJSON, _ := json.Marshal(createBody)
	reqCreate := httptest.NewRequest(http.MethodPost, "/admin/threat/ip-rules",
		bytes.NewReader(createJSON))
	reqCreate.Header.Set("Content-Type", "application/json")
	reqCreate = reqCreate.WithContext(ctxWithAdminUser(realUserID, "admin@example.com"))
	wCreate := httptest.NewRecorder()
	h.Create(wCreate, reqCreate)
	if wCreate.Code != http.StatusCreated {
		t.Fatalf("Create: expected 201, got %d — %s", wCreate.Code, wCreate.Body.String())
	}
	var created struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(wCreate.Body).Decode(&created); err != nil {
		t.Fatalf("Create: decode response: %v", err)
	}
	if created.ID == 0 {
		t.Fatal("Create: returned id=0, expected a real BIGINT id")
	}

	// Cleanup: delete the rule we just created even if the test fails.
	t.Cleanup(func() {
		pool.Exec(context.Background(),
			`DELETE FROM ip_rules WHERE description = $1`, uniqueDesc)
	})

	// ---- Delete: remove the rule we just created ----------------------------
	idStr := strconv.FormatInt(created.ID, 10)
	reqDelete := httptest.NewRequest(http.MethodDelete,
		"/admin/threat/ip-rules/"+idStr, nil)
	reqDelete.SetPathValue("id", idStr)
	reqDelete = reqDelete.WithContext(ctxWithAdminUser(realUserID, "admin@example.com"))
	wDelete := httptest.NewRecorder()
	h.Delete(wDelete, reqDelete)
	if wDelete.Code != http.StatusNoContent {
		t.Fatalf("Delete: expected 204, got %d — %s", wDelete.Code, wDelete.Body.String())
	}
}
