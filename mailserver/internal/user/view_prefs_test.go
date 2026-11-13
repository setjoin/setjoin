package user

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/mailserver/internal/auth"
)

func TestOfflineWindowDefault(t *testing.T) {
	if defaultViewPrefs["offlineWindow"] != "30d" {
		t.Fatalf("expected default offlineWindow 30d, got %v", defaultViewPrefs["offlineWindow"])
	}
}

func TestValidOfflineWindow(t *testing.T) {
	if !validOfflineWindow("30d") || !validOfflineWindow("all") {
		t.Fatal("30d/all must be valid")
	}
	if validOfflineWindow("99d") || validOfflineWindow("") {
		t.Fatal("invalid windows must be rejected")
	}
}

// TestViewPrefsGetBackfillsDefaults: a user who saved prefs before offlineWindow
// was added must still receive the default for that key on GET.
func TestViewPrefsGetBackfillsDefaults(t *testing.T) {
	pool := testPool(t)
	h := NewViewPrefsHandler(pool, testLogger())
	userID := createTestUser(t, pool)

	// Simulate pre-existing row without offlineWindow.
	_, err := pool.Exec(t.Context(),
		`UPDATE users SET view_prefs = $2 WHERE id = $1`,
		userID, []byte(`{"defaultView":"flat"}`),
	)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	req := httptest.NewRequest("GET", "/settings/view", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rec := httptest.NewRecorder()
	h.Get(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET returned %d", rec.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["offlineWindow"] != "30d" {
		t.Fatalf("expected back-filled offlineWindow '30d', got %v", resp["offlineWindow"])
	}
	if resp["defaultView"] != "flat" {
		t.Fatalf("stored defaultView 'flat' should be preserved, got %v", resp["defaultView"])
	}
}

func TestViewPrefsGetPut(t *testing.T) {
	pool := testPool(t)
	h := NewViewPrefsHandler(pool, testLogger())
	userID := createTestUser(t, pool)

	// GET with no saved prefs → defaults
	req := httptest.NewRequest("GET", "/settings/view", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rec := httptest.NewRecorder()
	h.Get(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET returned %d", rec.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["defaultView"] != "conversation" {
		t.Fatalf("expected default 'conversation', got %v", resp["defaultView"])
	}
	if resp["readingPane"] != "right" {
		t.Fatalf("expected readingPane 'right', got %v", resp["readingPane"])
	}
	if resp["senderImages"] != true {
		t.Fatalf("expected senderImages true, got %v", resp["senderImages"])
	}
	if resp["extSenderWarning"] != true {
		t.Fatalf("expected extSenderWarning true, got %v", resp["extSenderWarning"])
	}
	if resp["smartMute"] != false {
		t.Fatalf("expected smartMute false, got %v", resp["smartMute"])
	}

	// PUT a custom value
	body, _ := json.Marshal(map[string]interface{}{
		"defaultView": "flat",
		"smartMute":   true,
	})
	req2 := httptest.NewRequest("PUT", "/settings/view", bytes.NewReader(body))
	req2 = req2.WithContext(auth.ContextWithUser(req2.Context(), &auth.Claims{UserID: userID}))
	rec2 := httptest.NewRecorder()
	h.Put(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("PUT returned %d", rec2.Code)
	}

	// GET again and verify the saved partial prefs
	req3 := httptest.NewRequest("GET", "/settings/view", nil)
	req3 = req3.WithContext(auth.ContextWithUser(req3.Context(), &auth.Claims{UserID: userID}))
	rec3 := httptest.NewRecorder()
	h.Get(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("GET after PUT returned %d", rec3.Code)
	}
	var resp3 map[string]interface{}
	json.NewDecoder(rec3.Body).Decode(&resp3)
	if resp3["defaultView"] != "flat" {
		t.Fatalf("expected defaultView 'flat', got %v", resp3["defaultView"])
	}
	if resp3["smartMute"] != true {
		t.Fatalf("expected smartMute true, got %v", resp3["smartMute"])
	}
}
