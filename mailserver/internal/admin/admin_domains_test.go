package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/mailserver/internal/middleware"
)

// TestDomainScope_Domains verifies that a scoped admin receives 403 when
// trying to access domains outside their assigned scope. These tests only
// validate the scope rejection path; the scope-check happens before any
// database call, so no DB pool is needed.
func TestDomainScope_Domains(t *testing.T) {
	h := &DomainsHandler{pool: nil, logger: nil}

	// --- Get: scoped admin accessing another domain returns 403
	t.Run("Get_crossScope_returns403", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/admin/domains/99", nil)
		ctx := middleware.ContextWithDomainScope(req.Context(), 42)
		req = req.WithContext(ctx)
		req.SetPathValue("id", "99")
		w := httptest.NewRecorder()
		h.Get(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403 for cross-scope domain access (scope=42, requested=99), got %d", w.Code)
		}
	})

	// --- Create: scoped admin cannot create domains
	t.Run("Create_scopedAdmin_returns403", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/admin/domains", nil)
		ctx := middleware.ContextWithDomainScope(req.Context(), 42)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()
		h.Create(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403 for scoped admin creating domain, got %d", w.Code)
		}
	})

	// --- Update: scoped admin can only update own domain
	t.Run("Update_crossScope_returns403", func(t *testing.T) {
		req := httptest.NewRequest("PUT", "/admin/domains/99", nil)
		ctx := middleware.ContextWithDomainScope(req.Context(), 42)
		req = req.WithContext(ctx)
		req.SetPathValue("id", "99")
		w := httptest.NewRecorder()
		h.Update(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403 for cross-scope domain update (scope=42, requested=99), got %d", w.Code)
		}
	})

	// --- Delete: scoped admin can only delete own domain
	t.Run("Delete_crossScope_returns403", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/admin/domains/99", nil)
		ctx := middleware.ContextWithDomainScope(req.Context(), 42)
		req = req.WithContext(ctx)
		req.SetPathValue("id", "99")
		w := httptest.NewRecorder()
		h.Delete(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403 for cross-scope domain delete (scope=42, requested=99), got %d", w.Code)
		}
	})
}

// TestDomainScope_DLP validates scoped DLP handler access.
func TestDomainScope_DLP(t *testing.T) {
	h := &DLPHandler{pool: nil}

	t.Run("UpdatePatterns_scopedAdmin_returns403", func(t *testing.T) {
		req := httptest.NewRequest("PUT", "/admin/dlp/patterns", nil)
		ctx := middleware.ContextWithDomainScope(req.Context(), 42)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()
		h.UpdatePatterns(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403 for scoped admin updating DLP patterns, got %d", w.Code)
		}
	})
}

// TestDomainScope_InvalidInput verifies that invalid input is rejected before scope checks.
func TestDomainScope_InvalidInput(t *testing.T) {
	h := &DomainsHandler{pool: nil, logger: nil}

	t.Run("Get_invalidID_returns400", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/admin/domains/not-a-number", nil)
		ctx := middleware.ContextWithDomainScope(req.Context(), 42)
		req = req.WithContext(ctx)
		req.SetPathValue("id", "not-a-number")
		w := httptest.NewRecorder()
		h.Get(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for invalid id, got %d", w.Code)
		}
	})

	t.Run("MailboxGet_invalidID_returns400", func(t *testing.T) {
		mh := &MailboxesHandler{pool: nil, logger: nil}
		req := httptest.NewRequest("GET", "/admin/mailboxes/abc", nil)
		req.SetPathValue("id", "abc")
		w := httptest.NewRecorder()
		mh.Get(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for invalid mailbox id, got %d", w.Code)
		}
	})
}

// TestDomainScopeFromContext tests the middleware scope helpers directly.
func TestDomainScopeFromContext(t *testing.T) {
	t.Run("no_scope_returns_zero", func(t *testing.T) {
		ctx := context.Background()
		if got := middleware.DomainScopeFromContext(ctx); got != 0 {
			t.Errorf("expected 0 for no scope, got %d", got)
		}
	})

	t.Run("scoped_returns_value", func(t *testing.T) {
		ctx := middleware.ContextWithDomainScope(context.Background(), 42)
		if got := middleware.DomainScopeFromContext(ctx); got != 42 {
			t.Errorf("expected 42, got %d", got)
		}
	})

	t.Run("scoped_zero_is_treated_as_global", func(t *testing.T) {
		ctx := middleware.ContextWithDomainScope(context.Background(), 0)
		if got := middleware.DomainScopeFromContext(ctx); got != 0 {
			t.Errorf("expected 0, got %d", got)
		}
	})
}
