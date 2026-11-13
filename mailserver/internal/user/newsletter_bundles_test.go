package user

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/mailserver/internal/auth"
)

// TestNewsletterBundlesGetReturnsDefaults asserts that GET /settings/newsletter-bundles
// returns a default response (bundleNewsletters=true, empty opt-out list) when
// the user has no saved prefs.
func TestNewsletterBundlesGetReturnsDefaults(t *testing.T) {
	pool := testPool(t)
	h := NewNewsletterBundlesHandler(pool, testLogger())
	userID := createTestUser(t, pool)

	req := httptest.NewRequest("GET", "/settings/newsletter-bundles", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rec := httptest.NewRecorder()
	h.Get(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET returned %d, want 200", rec.Code)
	}

	var resp NewsletterBundlesResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.BundleNewsletters {
		t.Errorf("default bundleNewsletters = false, want true")
	}
	if len(resp.OptedOutLists) != 0 {
		t.Errorf("default optedOutLists = %v, want []", resp.OptedOutLists)
	}
}

// TestNewsletterBundlesPutTogglesGlobalFlag asserts that PUT with
// {bundleNewsletters: false} persists the flag and GET reflects it.
func TestNewsletterBundlesPutTogglesGlobalFlag(t *testing.T) {
	pool := testPool(t)
	h := NewNewsletterBundlesHandler(pool, testLogger())
	userID := createTestUser(t, pool)

	body, _ := json.Marshal(map[string]interface{}{
		"bundleNewsletters": false,
	})
	req := httptest.NewRequest("PUT", "/settings/newsletter-bundles", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rec := httptest.NewRecorder()
	h.Put(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("PUT returned %d, want 200", rec.Code)
	}

	// GET should now reflect bundleNewsletters=false
	req2 := httptest.NewRequest("GET", "/settings/newsletter-bundles", nil)
	req2 = req2.WithContext(auth.ContextWithUser(req2.Context(), &auth.Claims{UserID: userID}))
	rec2 := httptest.NewRecorder()
	h.Get(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("GET returned %d, want 200", rec2.Code)
	}
	var resp NewsletterBundlesResponse
	if err := json.NewDecoder(rec2.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.BundleNewsletters {
		t.Errorf("after PUT false, bundleNewsletters = true, want false")
	}
}

// TestNewsletterBundlesPutOptOutList asserts that PUT with an optedOutLists
// array persists the list and GET reflects it.
func TestNewsletterBundlesPutOptOutList(t *testing.T) {
	pool := testPool(t)
	h := NewNewsletterBundlesHandler(pool, testLogger())
	userID := createTestUser(t, pool)

	body, _ := json.Marshal(map[string]interface{}{
		"bundleNewsletters": true,
		"optedOutLists":     []string{"news.acme.io", "deals.shop.io"},
	})
	req := httptest.NewRequest("PUT", "/settings/newsletter-bundles", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rec := httptest.NewRecorder()
	h.Put(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("PUT returned %d, want 200", rec.Code)
	}

	req2 := httptest.NewRequest("GET", "/settings/newsletter-bundles", nil)
	req2 = req2.WithContext(auth.ContextWithUser(req2.Context(), &auth.Claims{UserID: userID}))
	rec2 := httptest.NewRecorder()
	h.Get(rec2, req2)

	var resp NewsletterBundlesResponse
	json.NewDecoder(rec2.Body).Decode(&resp)
	if len(resp.OptedOutLists) != 2 {
		t.Errorf("optedOutLists len = %d, want 2", len(resp.OptedOutLists))
	}
}

// TestNewsletterBundlesPutBadBody asserts that PUT with a malformed body
// returns 400 with a validation problem.
func TestNewsletterBundlesPutBadBody(t *testing.T) {
	pool := testPool(t)
	h := NewNewsletterBundlesHandler(pool, testLogger())
	userID := createTestUser(t, pool)

	req := httptest.NewRequest("PUT", "/settings/newsletter-bundles", bytes.NewReader([]byte("not json")))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rec := httptest.NewRecorder()
	h.Put(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT with bad body returned %d, want 400", rec.Code)
	}
}

// TestNewsletterBundlesUnauthorized asserts 401 when no auth context is present.
func TestNewsletterBundlesUnauthorized(t *testing.T) {
	pool := testPool(t)
	h := NewNewsletterBundlesHandler(pool, testLogger())

	req := httptest.NewRequest("GET", "/settings/newsletter-bundles", nil)
	rec := httptest.NewRecorder()
	h.Get(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET without auth returned %d, want 401", rec.Code)
	}

	req2 := httptest.NewRequest("PUT", "/settings/newsletter-bundles", bytes.NewReader([]byte(`{}`)))
	rec2 := httptest.NewRecorder()
	h.Put(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("PUT without auth returned %d, want 401", rec2.Code)
	}
}
