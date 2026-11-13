package user

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/mailserver/internal/auth"
)

func TestSenderListGetNewUser(t *testing.T) {
	pool := testPool(t)
	h := NewSenderListHandler(pool, testLogger())

	userID := createTestUser(t, pool)

	claims := &auth.Claims{UserID: userID, Type: auth.TypeAccess}
	req := httptest.NewRequest(http.MethodGet, "/settings/senders", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	rec := httptest.NewRecorder()
	h.Get(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET returned %d, want 200", rec.Code)
	}

	var resp struct {
		Safe    []string `json:"safe"`
		Blocked []string `json:"blocked"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Safe) != 0 {
		t.Errorf("expected empty safe list, got %v", resp.Safe)
	}
	if len(resp.Blocked) != 0 {
		t.Errorf("expected empty blocked list, got %v", resp.Blocked)
	}
}

func TestSenderListPutThenGet(t *testing.T) {
	pool := testPool(t)
	h := NewSenderListHandler(pool, testLogger())

	userID := createTestUser(t, pool)

	// PUT some senders.
	body, _ := json.Marshal(map[string][]string{
		"safe":    {"alice@setjoin.com", "*@trusted-vendor.com"},
		"blocked": {"spam@evil.com"},
	})
	claims := &auth.Claims{UserID: userID, Type: auth.TypeAccess}
	req := httptest.NewRequest(http.MethodPut, "/settings/senders", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	rec := httptest.NewRecorder()
	h.Put(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT returned %d, want 200: %s", rec.Code, rec.Body.String())
	}

	// GET and verify.
	req2 := httptest.NewRequest(http.MethodGet, "/settings/senders", nil)
	req2 = req2.WithContext(auth.ContextWithUser(req2.Context(), claims))
	rec2 := httptest.NewRecorder()
	h.Get(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("GET returned %d, want 200", rec2.Code)
	}

	var resp struct {
		Safe    []string `json:"safe"`
		Blocked []string `json:"blocked"`
	}
	if err := json.NewDecoder(rec2.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Safe) != 2 {
		t.Errorf("expected 2 safe, got %d: %v", len(resp.Safe), resp.Safe)
	}
	if len(resp.Blocked) != 1 || resp.Blocked[0] != "spam@evil.com" {
		t.Errorf("expected [spam@evil.com] blocked, got %v", resp.Blocked)
	}
}

func TestSenderListUnauthorized(t *testing.T) {
	pool := testPool(t)
	h := NewSenderListHandler(pool, testLogger())

	// GET without auth context should return 401.
	req := httptest.NewRequest(http.MethodGet, "/settings/senders", nil)
	rec := httptest.NewRecorder()
	h.Get(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET without auth returned %d, want 401", rec.Code)
	}
}

func TestNeverBlock(t *testing.T) {
	pool := testPool(t)
	h := NewSenderListHandler(pool, testLogger())
	userID := createTestUser(t, pool)

	// First, block a sender by inserting directly into the table.
	_, err := h.pool.Exec(context.Background(),
		`INSERT INTO user_sender_list (user_id, sender, list_type) VALUES ($1, $2, 'blocked')`,
		userID, "bad@spam.com",
	)
	if err != nil {
		t.Fatalf("failed to insert blocked sender: %v", err)
	}

	// Call never-block
	body, _ := json.Marshal(map[string]string{"sender": "bad@spam.com"})
	req := httptest.NewRequest("POST", "/settings/senders/never-block", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rec := httptest.NewRecorder()
	h.NeverBlock(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify sender is now in safe list and NOT in blocked
	rows, err := h.pool.Query(context.Background(),
		`SELECT list_type FROM user_sender_list WHERE user_id = $1 AND sender = $2`,
		userID, "bad@spam.com",
	)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	defer rows.Close()
	var types []string
	for rows.Next() {
		var lt string
		rows.Scan(&lt)
		types = append(types, lt)
	}
	if len(types) != 1 || types[0] != "safe" {
		t.Fatalf("expected exactly ['safe'], got %v", types)
	}
}
