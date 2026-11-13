package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/permissions"
)

// TestImpersonateRoute_ServeMuxPrecedence builds a REAL http.ServeMux with both
// patterns registered exactly as main.go does — the specific impersonate route
// and the wildcard /auth/admin/ subtree — and proves via mux.Handler that Go
// 1.22 ServeMux specificity routes the impersonate URL to the perm-gated handler,
// NOT to the wildcard proxy.  A sibling path confirms the wildcard still wins for
// everything else under /auth/admin/.
func TestImpersonateRoute_ServeMuxPrecedence(t *testing.T) {
	const (
		headerImpersonate = "X-Handler"
		valImpersonate    = "impersonate"
		valProxy          = "proxy"
	)

	impersonateHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(headerImpersonate, valImpersonate)
		w.WriteHeader(http.StatusOK)
	})
	proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(headerImpersonate, valProxy)
		w.WriteHeader(http.StatusOK)
	})

	mux := http.NewServeMux()
	// Register in the same order as main.go.
	mux.Handle("/auth/admin/", proxyHandler)
	mux.Handle("POST /auth/admin/users/{id}/impersonate", impersonateHandler)

	tests := []struct {
		name    string
		method  string
		path    string
		wantHdr string
	}{
		{
			name:    "POST impersonate path routes to impersonate handler",
			method:  http.MethodPost,
			path:    "/auth/admin/users/42/impersonate",
			wantHdr: valImpersonate,
		},
		{
			name:    "GET impersonate path (wrong method) routes to wildcard proxy",
			method:  http.MethodGet,
			path:    "/auth/admin/users/42/impersonate",
			wantHdr: valProxy,
		},
		{
			name:    "POST sibling path under /auth/admin/ routes to wildcard proxy",
			method:  http.MethodPost,
			path:    "/auth/admin/foo",
			wantHdr: valProxy,
		},
		{
			name:    "GET /auth/admin/ subtree routes to wildcard proxy",
			method:  http.MethodGet,
			path:    "/auth/admin/users/42/other",
			wantHdr: valProxy,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			h, _ := mux.Handler(req)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			got := rec.Header().Get(headerImpersonate)
			if got != tc.wantHdr {
				t.Errorf("%s %s: routed to %q, want %q", tc.method, tc.path, got, tc.wantHdr)
			}
		})
	}
}

// TestImpersonateRoute_PermGate proves that the POST
// /auth/admin/users/{id}/impersonate path is gated on users.impersonate:
//
//   - A caller whose claims carry users.impersonate passes through to the
//     downstream handler (200).
//   - A caller whose claims do NOT carry users.impersonate is denied with 403.
//
// The test validates the middleware composition in isolation: it does not spin
// up the full server or proxy to authserver, so it is fast, self-contained, and
// requires no database.
func TestImpersonateRoute_PermGate(t *testing.T) {
	downstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	var auditSpy []middleware.AuditEvent
	auditCapture := func(_ context.Context, ev middleware.AuditEvent) {
		auditSpy = append(auditSpy, ev)
	}

	requireImpersonate := middleware.RequirePermAudited(permissions.PermUsersImpersonate, auditCapture)
	handler := requireImpersonate(downstream)

	makeClaims := func(perms []string) *auth.Claims {
		return &auth.Claims{
			UserID:      1,
			Email:       "admin@example.com",
			IsAdmin:     true,
			Permissions: perms,
			Type:        jwtutil.TypeAccess,
		}
	}

	t.Run("holder passes", func(t *testing.T) {
		auditSpy = nil
		req := httptest.NewRequest(http.MethodPost, "/auth/admin/users/42/impersonate", nil)
		req = req.WithContext(auth.ContextWithUser(req.Context(), makeClaims([]string{
			permissions.PermUsersImpersonate,
		})))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("holder: expected 200, got %d", rec.Code)
		}
		if len(auditSpy) != 0 {
			t.Errorf("holder: expected no audit event, got %d", len(auditSpy))
		}
	})

	t.Run("non-holder 403s", func(t *testing.T) {
		auditSpy = nil
		req := httptest.NewRequest(http.MethodPost, "/auth/admin/users/42/impersonate", nil)
		// users.read is present but users.impersonate is absent
		req = req.WithContext(auth.ContextWithUser(req.Context(), makeClaims([]string{
			permissions.PermUsersRead,
		})))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("non-holder: expected 403, got %d", rec.Code)
		}
		if len(auditSpy) != 1 {
			t.Errorf("non-holder: expected 1 audit event, got %d", len(auditSpy))
		}
		if len(auditSpy) > 0 && auditSpy[0].Detail != permissions.PermUsersImpersonate {
			t.Errorf("audit detail = %q, want %q", auditSpy[0].Detail, permissions.PermUsersImpersonate)
		}
	})
}
