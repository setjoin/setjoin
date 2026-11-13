package user

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/mailserver/internal/auth"
)

func TestApprovalDelegation_GetRequiresAuth(t *testing.T) {
	h := NewApprovalDelegationHandler(nil)
	req := httptest.NewRequest("GET", "/user/approval-delegation", nil) // no auth context
	rr := httptest.NewRecorder()
	h.Get(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
}

func TestApprovalDelegation_SetRequiresAuth(t *testing.T) {
	h := NewApprovalDelegationHandler(nil)
	req := httptest.NewRequest("PUT", "/user/approval-delegation", nil) // no auth context
	rr := httptest.NewRecorder()
	h.Set(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
}

func TestApprovalDelegation_SetRejectsBadJSON(t *testing.T) {
	h := NewApprovalDelegationHandler(nil)
	req := httptest.NewRequest("PUT", "/user/approval-delegation", bytes.NewReader([]byte("not json")))
	ctx := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 999999})
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()
	h.Set(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rr.Code)
	}
}

// TestApprovalDelegation_RoundTrip exercises PUT (set) → GET (read) → PUT (clear)
// against a real DB. The delegator is derived from the auth context only (R2) — never
// from the request body. Delegate must share the delegator's domain (both users come
// from createTestUser → same test domain).
func TestApprovalDelegation_RoundTrip(t *testing.T) {
	pool := testPool(t)
	delegator := createTestUser(t, pool)
	delegate := createTestUser(t, pool)

	t.Cleanup(func() {
		pool.Exec(t.Context(), `DELETE FROM approval_delegations WHERE delegator_user_id = $1`, delegator)
	})

	h := NewApprovalDelegationHandler(pool)
	ctx := auth.ContextWithUser(t.Context(), &auth.Claims{UserID: delegator})

	// PUT — enable an entrust to the delegate for a valid window.
	put := map[string]interface{}{
		"enabled":          true,
		"delegate_user_id": delegate,
		"starts_at":        "2026-07-01T09:00",
		"ends_at":          "2026-07-08T09:00",
	}
	pb, _ := json.Marshal(put)
	preq := httptest.NewRequest("PUT", "/user/approval-delegation", bytes.NewReader(pb)).WithContext(ctx)
	pw := httptest.NewRecorder()
	h.Set(pw, preq)
	if pw.Code != http.StatusOK {
		t.Fatalf("PUT want 200, got %d — body: %s", pw.Code, pw.Body.String())
	}

	// GET — should echo the delegate + enabled.
	greq := httptest.NewRequest("GET", "/user/approval-delegation", nil).WithContext(ctx)
	gw := httptest.NewRecorder()
	h.Get(gw, greq)
	if gw.Code != http.StatusOK {
		t.Fatalf("GET want 200, got %d — body: %s", gw.Code, gw.Body.String())
	}
	var got ApprovalDelegation
	if err := json.Unmarshal(gw.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode GET: %v", err)
	}
	if !got.Enabled {
		t.Errorf("enabled = false, want true")
	}
	if got.DelegateUserID != delegate {
		t.Errorf("delegate_user_id = %d, want %d", got.DelegateUserID, delegate)
	}

	// PUT — disable clears the entrust (NULL delegate).
	clr, _ := json.Marshal(map[string]interface{}{"enabled": false})
	creq := httptest.NewRequest("PUT", "/user/approval-delegation", bytes.NewReader(clr)).WithContext(ctx)
	cw := httptest.NewRecorder()
	h.Set(cw, creq)
	if cw.Code != http.StatusOK {
		t.Fatalf("PUT clear want 200, got %d — body: %s", cw.Code, cw.Body.String())
	}
	greq2 := httptest.NewRequest("GET", "/user/approval-delegation", nil).WithContext(ctx)
	gw2 := httptest.NewRecorder()
	h.Get(gw2, greq2)
	var got2 ApprovalDelegation
	if err := json.Unmarshal(gw2.Body.Bytes(), &got2); err != nil {
		t.Fatalf("decode GET after clear: %v", err)
	}
	if got2.Enabled {
		t.Errorf("enabled = true after clear, want false")
	}
}

// TestApprovalDelegation_SetRejectsBadWindow verifies the reducer's BZ119 (ends <=
// starts) surfaces as a 400, not a 500.
func TestApprovalDelegation_SetRejectsBadWindow(t *testing.T) {
	pool := testPool(t)
	delegator := createTestUser(t, pool)
	delegate := createTestUser(t, pool)
	t.Cleanup(func() {
		pool.Exec(t.Context(), `DELETE FROM approval_delegations WHERE delegator_user_id = $1`, delegator)
	})

	h := NewApprovalDelegationHandler(pool)
	ctx := auth.ContextWithUser(t.Context(), &auth.Claims{UserID: delegator})

	bad, _ := json.Marshal(map[string]interface{}{
		"enabled":          true,
		"delegate_user_id": delegate,
		"starts_at":        "2026-07-08T09:00",
		"ends_at":          "2026-07-01T09:00", // ends before starts
	})
	req := httptest.NewRequest("PUT", "/user/approval-delegation", bytes.NewReader(bad)).WithContext(ctx)
	rr := httptest.NewRecorder()
	h.Set(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for inverted window, got %d — body: %s", rr.Code, rr.Body.String())
	}
}
