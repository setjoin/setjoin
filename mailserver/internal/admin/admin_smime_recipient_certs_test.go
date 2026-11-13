package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/mailserver/internal/auth"
)

// Compile-time assertions: handler methods must satisfy http.HandlerFunc's signature.
var _ http.HandlerFunc = (&RecipientCertHandler{}).ListRecipientCerts
var _ http.HandlerFunc = (&RecipientCertHandler{}).ImportRecipientCert
var _ http.HandlerFunc = (&RecipientCertHandler{}).DeleteRecipientCert

// TestListRecipientCerts_NoAuth verifies that ListRecipientCerts returns 401 without auth.
func TestListRecipientCerts_NoAuth(t *testing.T) {
	h := &RecipientCertHandler{pool: nil, logger: nil}

	req := httptest.NewRequest(http.MethodGet, "/auth/me/smime/recipient-certs", nil)
	w := httptest.NewRecorder()

	h.ListRecipientCerts(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without auth, got %d", w.Code)
	}
}

// TestImportRecipientCert_NoAuth verifies that ImportRecipientCert returns 401 without auth.
func TestImportRecipientCert_NoAuth(t *testing.T) {
	h := &RecipientCertHandler{pool: nil, logger: nil}

	req := httptest.NewRequest(http.MethodPost, "/auth/me/smime/recipient-certs", nil)
	w := httptest.NewRecorder()

	h.ImportRecipientCert(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without auth, got %d", w.Code)
	}
}

// TestDeleteRecipientCert_NoAuth verifies that DeleteRecipientCert returns 401 without auth.
func TestDeleteRecipientCert_NoAuth(t *testing.T) {
	h := &RecipientCertHandler{pool: nil, logger: nil}

	req := httptest.NewRequest(http.MethodDelete, "/auth/me/smime/recipient-certs/1", nil)
	req.SetPathValue("id", "1")
	w := httptest.NewRecorder()

	h.DeleteRecipientCert(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without auth, got %d", w.Code)
	}
}

// TestDeleteRecipientCert_BadID verifies that a non-numeric cert id returns 400.
func TestDeleteRecipientCert_BadID(t *testing.T) {
	h := &RecipientCertHandler{pool: nil, logger: nil}

	req := httptest.NewRequest(http.MethodDelete, "/auth/me/smime/recipient-certs/not-a-number", nil)
	req.SetPathValue("id", "not-a-number")

	ctx := auth.ContextWithUser(context.Background(), &auth.Claims{
		UserID: 42,
		Email:  "user@example.com",
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	h.DeleteRecipientCert(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad id, got %d", w.Code)
	}
}

// TestImportRecipientCert_NilPool_ReachesDBBoundary confirms that with valid auth
// the handler clears the auth gate and reaches the DB boundary (nil pool → panic or 500).
// This mirrors TestSetDefaultCert_OwnershipGuard_Logic.
func TestImportRecipientCert_NilPool_ReachesDBBoundary(t *testing.T) {
	h := &RecipientCertHandler{pool: nil, logger: nil}

	req := httptest.NewRequest(http.MethodPost, "/auth/me/smime/recipient-certs", nil)

	ctx := auth.ContextWithUser(context.Background(), &auth.Claims{
		UserID: 42,
		Email:  "user@example.com",
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	// With valid auth, the handler will attempt to parse the body then hit a nil pool.
	// Either outcome (panic from nil pool or error response) proves the auth gate passed.
	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		h.ImportRecipientCert(w, req)
	}()

	// A 401 here means the auth gate was not passed — that is the bug we are guarding against.
	if !panicked && w.Code == http.StatusUnauthorized {
		t.Error("unexpected 401: auth context was not propagated")
	}
	// Any other outcome (panic, 400 on body parse, 500) confirms the handler cleared auth.
	t.Logf("nil-pool outcome: panicked=%v code=%d (expected panic, 400, or 500)", panicked, w.Code)
}
