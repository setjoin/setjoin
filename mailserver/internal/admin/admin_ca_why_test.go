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

// d5TestDomainID and d5TestUserID are stable test IDs for D5 tests.
// d5TestZeroUserID is a separate user with NO log rows (used only for the zero-sign-ins test).
const (
	d5TestDomainID   = int64(99050)
	d5TestUserID     = int64(99051) // has seeded log rows from RowsReturnedWithEvaluated + ByCorrelationID
	d5TestZeroUserID = int64(99052) // zero sign-ins — never seeded in any other D5 test
)

// newTestCAWhyHandler opens the test pool and returns a CAWhyHandler.
func newTestCAWhyHandler(t *testing.T) *CAWhyHandler {
	t.Helper()
	pool := testsupport.OpenTestPool(t)
	return NewCAWhyHandler(pool, testsupport.TestLogger())
}

// ensureD5User seeds a domain + users for D5 tests (idempotent).
// Two users are created: d5TestUserID (seeded log rows in other tests) and
// d5TestZeroUserID (never seeded — used for the zero-sign-ins invariant).
func ensureD5User(t *testing.T, h *CAWhyHandler) {
	t.Helper()
	ctx := context.Background()
	_, _ = h.pool.Exec(ctx,
		`INSERT INTO domains (id, name, is_local) VALUES ($1, 'd5test.test', TRUE) ON CONFLICT DO NOTHING`,
		d5TestDomainID)
	_, _ = h.pool.Exec(ctx,
		`INSERT INTO users (id, username, domain_id, email, display_name, enabled)
		 VALUES ($1, 'd5user', $2, 'd5user@d5test.test', 'D5 User', TRUE)
		 ON CONFLICT (id) DO NOTHING`,
		d5TestUserID, d5TestDomainID)
	_, _ = h.pool.Exec(ctx,
		`INSERT INTO users (id, username, domain_id, email, display_name, enabled)
		 VALUES ($1, 'd5zero', $2, 'd5zero@d5test.test', 'D5 Zero User', TRUE)
		 ON CONFLICT (id) DO NOTHING`,
		d5TestZeroUserID, d5TestDomainID)
}

// seedD5SignInRow inserts a ca_signin_log row for user d5TestUserID with the given decision+evaluated.
func seedD5SignInRow(t *testing.T, h *CAWhyHandler, decision, corrID string, evaluated string) {
	t.Helper()
	payload := fmt.Sprintf(`{"user_id":%d,"decision":%q,"correlation_id":%q,"evaluated":%s}`,
		d5TestUserID, decision, corrID, evaluated)
	if _, err := h.pool.Exec(context.Background(),
		`SELECT ca_signin_log_append($1::jsonb)`, payload); err != nil {
		t.Fatalf("seedD5SignInRow: %v", err)
	}
}

// TestCAWhy_UserNotFound — unresolvable user= returns 404 with {found:false}.
// Pure unit test for the missing-user branch; DB-backed for the actual lookup.
func TestCAWhy_UserNotFound(t *testing.T) {
	h := newTestCAWhyHandler(t)

	req := httptest.NewRequest(http.MethodGet,
		"/admin/conditional-access/why?user=nonexistent@nowhere.invalid&since=24h", nil)
	req = withAdminClaims(req, 1)
	w := httptest.NewRecorder()
	h.Why(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("Why(unknown user): got %d, want 404; body=%s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Why(unknown user): invalid JSON: %v", err)
	}
	if found, _ := resp["found"].(bool); found {
		t.Fatalf("Why(unknown user): want found=false, got %v", resp)
	}
}

// TestCAWhy_UserNumericNotFound — numeric user= that doesn't exist → 404 {found:false}.
func TestCAWhy_UserNumericNotFound(t *testing.T) {
	h := newTestCAWhyHandler(t)

	req := httptest.NewRequest(http.MethodGet,
		"/admin/conditional-access/why?user=999999999&since=24h", nil)
	req = withAdminClaims(req, 1)
	w := httptest.NewRecorder()
	h.Why(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("Why(numeric not found): got %d, want 404; body=%s", w.Code, w.Body.String())
	}
}

// TestCAWhy_UserFoundZeroSignIns — known user with no log rows → 200 + empty rows list
// (distinct from not-found; the UI shows the calm empty state).
// Uses d5TestZeroUserID, which is NEVER seeded with sign-in rows in any other D5 test.
func TestCAWhy_UserFoundZeroSignIns(t *testing.T) {
	h := newTestCAWhyHandler(t)
	ensureD5User(t, h)

	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/admin/conditional-access/why?user=%d&since=24h", d5TestZeroUserID), nil)
	req = withAdminClaims(req, 1)
	w := httptest.NewRecorder()
	h.Why(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Why(zero sign-ins): got %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Found  bool              `json:"found"`
		UserID int64             `json:"user_id"`
		Rows   []json.RawMessage `json:"rows"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Why(zero sign-ins): invalid JSON: %v", err)
	}
	if !resp.Found {
		t.Fatalf("Why(zero sign-ins): want found=true, got false")
	}
	// rows must be an empty list (not null) — the UI needs this to distinguish from not-found.
	if resp.Rows == nil {
		t.Fatalf("Why(zero sign-ins): rows must be [] not null")
	}
	if len(resp.Rows) != 0 {
		t.Fatalf("Why(zero sign-ins): want 0 rows, got %d", len(resp.Rows))
	}
}

// TestCAWhy_RowsReturnedWithEvaluated — seeded rows appear; evaluated[] is passed through.
func TestCAWhy_RowsReturnedWithEvaluated(t *testing.T) {
	h := newTestCAWhyHandler(t)
	ensureD5User(t, h)

	corrID := "CA-d5-eval-test"
	evaluated := `[{"policy_id":1,"name":"Block legacy","outcome":"applied"}]`
	seedD5SignInRow(t, h, "block", corrID, evaluated)

	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/admin/conditional-access/why?user=%d&since=24h", d5TestUserID), nil)
	req = withAdminClaims(req, 1)
	w := httptest.NewRecorder()
	h.Why(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Why(rows): got %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Found bool `json:"found"`
		Rows  []struct {
			Decision  string          `json:"decision"`
			Evaluated json.RawMessage `json:"evaluated"`
			CorrID    *string         `json:"correlation_id"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Why(rows): invalid JSON: %v", err)
	}
	if !resp.Found {
		t.Fatalf("Why(rows): want found=true")
	}
	if len(resp.Rows) == 0 {
		t.Fatalf("Why(rows): want at least 1 row, got 0; body=%s", w.Body.String())
	}
	// Verify evaluated is passed through as JSONB array.
	var evSlice []map[string]any
	if err := json.Unmarshal(resp.Rows[len(resp.Rows)-1].Evaluated, &evSlice); err != nil {
		t.Fatalf("Why(rows): evaluated not parseable: %v", err)
	}
	if len(evSlice) == 0 {
		t.Fatalf("Why(rows): want non-empty evaluated, got []")
	}
	if evSlice[0]["outcome"] != "applied" {
		t.Fatalf("Why(rows): evaluated[0].outcome = %q, want 'applied'", evSlice[0]["outcome"])
	}
}

// TestCAWhy_ByCorrelationID — ?correlation_id= resolves a single sign-in event.
func TestCAWhy_ByCorrelationID(t *testing.T) {
	h := newTestCAWhyHandler(t)
	ensureD5User(t, h)

	corrID := "CA-d5-corr-single"
	seedD5SignInRow(t, h, "allow", corrID, `[]`)

	req := httptest.NewRequest(http.MethodGet,
		"/admin/conditional-access/why?correlation_id="+corrID+"&since=24h", nil)
	req = withAdminClaims(req, 1)
	w := httptest.NewRecorder()
	h.Why(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Why(correlation_id): got %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Rows []struct {
			CorrID *string `json:"correlation_id"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Why(correlation_id): invalid JSON: %v", err)
	}
	if len(resp.Rows) == 0 {
		t.Fatalf("Why(correlation_id): want 1 row, got 0")
	}
	if resp.Rows[0].CorrID == nil || *resp.Rows[0].CorrID != corrID {
		t.Fatalf("Why(correlation_id): row correlation_id = %v, want %q", resp.Rows[0].CorrID, corrID)
	}
}

// TestCAWhy_MissingParams — no user= and no correlation_id → 400.
func TestCAWhy_MissingParams(t *testing.T) {
	h := &CAWhyHandler{logger: testsupport.TestLogger()}

	req := httptest.NewRequest(http.MethodGet, "/admin/conditional-access/why?since=24h", nil)
	w := httptest.NewRecorder()
	h.Why(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("Why(no user or corr): got %d, want 400", w.Code)
	}
}

// TestCAWhy_LookupByEmail — user= as email address resolves to the user.
func TestCAWhy_LookupByEmail(t *testing.T) {
	h := newTestCAWhyHandler(t)
	ensureD5User(t, h)

	req := httptest.NewRequest(http.MethodGet,
		"/admin/conditional-access/why?user=d5user@d5test.test&since=24h", nil)
	req = withAdminClaims(req, 1)
	w := httptest.NewRecorder()
	h.Why(w, req)

	// User exists; 200 + found=true (may have 0 rows from this window, that's fine).
	if w.Code != http.StatusOK {
		t.Fatalf("Why(by email): got %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Found bool `json:"found"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Why(by email): invalid JSON: %v", err)
	}
	if !resp.Found {
		t.Fatalf("Why(by email): want found=true")
	}
}
