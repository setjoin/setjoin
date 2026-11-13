package user

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/mailserver/internal/auth"
)

func TestExternalSenderGetNewUser(t *testing.T) {
	pool := testPool(t)
	h := NewExternalSenderHandler(pool, testLogger())

	userID := createTestUser(t, pool)

	claims := &auth.Claims{UserID: userID, Type: auth.TypeAccess}
	req := httptest.NewRequest(http.MethodGet, "/settings/external-sender", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	rec := httptest.NewRecorder()
	h.Get(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET returned %d, want 200", rec.Code)
	}

	var resp struct {
		UserEnabled   bool `json:"userEnabled"`
		DomainEnabled bool `json:"domainEnabled"`
		GlobalEnabled bool `json:"globalEnabled"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	// New user defaults: user toggle ON, domain override absent -> domainEnabled true, global ON
	if !resp.UserEnabled {
		t.Errorf("expected userEnabled=true (default), got %v", resp.UserEnabled)
	}
	if !resp.GlobalEnabled {
		t.Errorf("expected globalEnabled=true, got %v", resp.GlobalEnabled)
	}
}

func TestExternalSenderPutThenGet(t *testing.T) {
	pool := testPool(t)
	h := NewExternalSenderHandler(pool, testLogger())

	userID := createTestUser(t, pool)

	// PUT to disable the warning.
	body, _ := json.Marshal(map[string]interface{}{"enabled": false})
	claims := &auth.Claims{UserID: userID, Type: auth.TypeAccess}
	req := httptest.NewRequest(http.MethodPut, "/settings/external-sender", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	rec := httptest.NewRecorder()
	h.Put(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT returned %d, want 200: %s", rec.Code, rec.Body.String())
	}

	// GET and verify toggle is now false.
	req2 := httptest.NewRequest(http.MethodGet, "/settings/external-sender", nil)
	req2 = req2.WithContext(auth.ContextWithUser(req2.Context(), claims))
	rec2 := httptest.NewRecorder()
	h.Get(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("GET returned %d, want 200", rec2.Code)
	}

	var resp struct {
		UserEnabled bool `json:"userEnabled"`
	}
	if err := json.NewDecoder(rec2.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.UserEnabled {
		t.Errorf("expected userEnabled=false after PUT, got %v", resp.UserEnabled)
	}
}

func TestExternalSenderUnauthorized(t *testing.T) {
	pool := testPool(t)
	h := NewExternalSenderHandler(pool, testLogger())

	req := httptest.NewRequest(http.MethodGet, "/settings/external-sender", nil)
	rec := httptest.NewRecorder()
	h.Get(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET without auth returned %d, want 401", rec.Code)
	}
}
