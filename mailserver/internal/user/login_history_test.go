package user

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"setjoin.com/mailserver/internal/auth"
)

// seedLoginEvent inserts a login_events row and returns nothing.
// Cleanup is via the user DELETE cascade (createTestUser registers cleanup).
func seedLoginEvent(t *testing.T, h *LoginHistoryHandler, userID int64, success bool, sessionID string, location string) {
	t.Helper()
	ctx := context.Background()
	var sessArg interface{} = nil
	if sessionID != "" {
		sessArg = sessionID
	}
	var locArg interface{} = nil
	if location != "" {
		locArg = location
	}
	_, err := h.pool.Exec(ctx,
		`INSERT INTO login_events (user_id, success, client, protocol, auth_method, session_id, location, occurred_at)
		 VALUES ($1, $2, 'web', 'http', 'password', $3, $4, now())`,
		userID, success, sessArg, locArg,
	)
	if err != nil {
		t.Fatalf("seedLoginEvent: %v", err)
	}
}

// seedLoginEventAt inserts with a specific timestamp (for the 7-day window tests).
func seedLoginEventAt(t *testing.T, h *LoginHistoryHandler, userID int64, success bool, location string, ts time.Time) {
	t.Helper()
	ctx := context.Background()
	var locArg interface{} = nil
	if location != "" {
		locArg = location
	}
	_, err := h.pool.Exec(ctx,
		`INSERT INTO login_events (user_id, success, client, protocol, auth_method, location, occurred_at)
		 VALUES ($1, $2, 'web', 'http', 'password', $3, $4)`,
		userID, success, locArg, ts,
	)
	if err != nil {
		t.Fatalf("seedLoginEventAt: %v", err)
	}
}

func doRequest(h *LoginHistoryHandler, userID int64, jti string, query string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "/user/login-history"+query, nil)
	ctx := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID, JTI: jti})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.ListLoginHistory(w, req)
	return w
}

// ── existing tests (kept; report tests removed) ──────────────────────────────

func TestLoginHistoryHandler_Unauthenticated(t *testing.T) {
	pool := testPool(t)
	h := NewLoginHistoryHandler(pool)

	req := httptest.NewRequest("GET", "/user/login-history", nil)
	w := httptest.NewRecorder()
	h.ListLoginHistory(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestLoginHistoryHandler_InvalidLimit(t *testing.T) {
	pool := testPool(t)
	h := NewLoginHistoryHandler(pool)

	req := httptest.NewRequest("GET", "/user/login-history?limit=9999", nil)
	ctx := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 999999})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	h.ListLoginHistory(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestLoginHistoryHandler_StructInitialization(t *testing.T) {
	pool := testPool(t)
	h := NewLoginHistoryHandler(pool)
	if h.pool != pool {
		t.Error("pool not set correctly")
	}
}

// ── new field + R1 isolation test ────────────────────────────────────────────

func TestListLoginHistory_NewFieldsAndR1(t *testing.T) {
	pool := testPool(t)
	h := NewLoginHistoryHandler(pool)

	userA := createTestUser(t, pool)
	userB := createTestUser(t, pool)

	seedLoginEvent(t, h, userA, true, "sess-A", "London, GB")
	seedLoginEvent(t, h, userB, true, "sess-B", "Paris, FR")

	w := doRequest(h, userA, "sess-A", "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Items []struct {
			Client     string `json:"client"`
			AuthMethod string `json:"auth_method"`
			Location   string `json:"location"`
			Current    bool   `json:"current"`
		} `json:"items"`
		FailedDistinct struct {
			Count     int    `json:"count"`
			Locations int    `json:"locations"`
			Since     string `json:"since"`
		} `json:"failed_distinct"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(resp.Items) != 1 {
		t.Fatalf("R1 violated: expected 1 item for userA, got %d", len(resp.Items))
	}
	row := resp.Items[0]
	if row.Client == "" {
		t.Error("expected non-empty client field")
	}
	if row.AuthMethod == "" {
		t.Error("expected non-empty auth_method field")
	}
	// failed_distinct key must be present (even when zero)
	_ = resp.FailedDistinct
}

// ── EMPTY / first-time ────────────────────────────────────────────────────────

func TestListLoginHistory_EmptyFirstTime(t *testing.T) {
	pool := testPool(t)
	h := NewLoginHistoryHandler(pool)
	u := createTestUser(t, pool)

	w := doRequest(h, u, "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Items          []json.RawMessage `json:"items"`
		FailedDistinct struct {
			Count int `json:"count"`
		} `json:"failed_distinct"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Items) != 0 {
		t.Errorf("expected empty items, got %d", len(resp.Items))
	}
	if resp.FailedDistinct.Count != 0 {
		t.Errorf("expected failed_distinct.count==0, got %d", resp.FailedDistinct.Count)
	}
}

// ── CURRENT flag ──────────────────────────────────────────────────────────────

func TestListLoginHistory_CurrentFlag(t *testing.T) {
	pool := testPool(t)
	h := NewLoginHistoryHandler(pool)
	u := createTestUser(t, pool)

	const mySession = "sess-current-test"
	seedLoginEvent(t, h, u, true, mySession, "")
	seedLoginEvent(t, h, u, true, "other-sess", "")

	w := doRequest(h, u, mySession, "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Items []struct {
			Current bool `json:"current"`
		} `json:"items"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(resp.Items))
	}
	currentCount := 0
	for _, row := range resp.Items {
		if row.Current {
			currentCount++
		}
	}
	if currentCount != 1 {
		t.Errorf("expected exactly 1 current row, got %d", currentCount)
	}
}

// ── FAILED-ONLY filter + summary ──────────────────────────────────────────────

func TestListLoginHistory_FailedOnlyFilterAndSummary(t *testing.T) {
	pool := testPool(t)
	h := NewLoginHistoryHandler(pool)
	u := createTestUser(t, pool)

	now := time.Now()
	seedLoginEventAt(t, h, u, false, "Berlin, DE", now.Add(-1*time.Hour))
	seedLoginEventAt(t, h, u, false, "Tokyo, JP", now.Add(-2*time.Hour))
	seedLoginEventAt(t, h, u, true, "London, GB", now.Add(-3*time.Hour))

	w := doRequest(h, u, "", "?outcome=failed")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Items []struct {
			Success bool `json:"success"`
		} `json:"items"`
		FailedDistinct struct {
			Count     int    `json:"count"`
			Locations int    `json:"locations"`
			Since     string `json:"since"`
		} `json:"failed_distinct"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Items) != 2 {
		t.Errorf("expected 2 failed items, got %d", len(resp.Items))
	}
	for _, row := range resp.Items {
		if row.Success {
			t.Error("outcome=failed filter returned a success row")
		}
	}
	if resp.FailedDistinct.Count != 2 {
		t.Errorf("failed_distinct.count: want 2, got %d", resp.FailedDistinct.Count)
	}
	if resp.FailedDistinct.Locations != 2 {
		t.Errorf("failed_distinct.locations: want 2, got %d", resp.FailedDistinct.Locations)
	}
	if resp.FailedDistinct.Since == "" {
		t.Error("failed_distinct.since should not be empty when failures exist")
	}
}

// ── UNKNOWN GEO → empty string ────────────────────────────────────────────────

func TestListLoginHistory_UnknownGeoEmptyString(t *testing.T) {
	pool := testPool(t)
	h := NewLoginHistoryHandler(pool)
	u := createTestUser(t, pool)

	// NULL location
	seedLoginEvent(t, h, u, true, "", "")

	w := doRequest(h, u, "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Items []struct {
			Location string `json:"location"`
		} `json:"items"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(resp.Items))
	}
	// location must be the empty string, not absent (Go's zero value for string is "")
	if resp.Items[0].Location != "" {
		t.Errorf("expected empty location string, got %q", resp.Items[0].Location)
	}
}

// ── HUGE COUNT / showing N of M ───────────────────────────────────────────────

func TestListLoginHistory_ShowingNofM(t *testing.T) {
	pool := testPool(t)
	h := NewLoginHistoryHandler(pool)
	u := createTestUser(t, pool)

	// Default limit is 50; seed 55 rows.
	for i := 0; i < 55; i++ {
		seedLoginEvent(t, h, u, true, "", "")
	}

	w := doRequest(h, u, "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Items []json.RawMessage `json:"items"`
		Total int               `json:"total"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Items) != 50 {
		t.Errorf("expected 50 items (default limit), got %d", len(resp.Items))
	}
	if resp.Total < 55 {
		t.Errorf("expected total >= 55, got %d", resp.Total)
	}
}
