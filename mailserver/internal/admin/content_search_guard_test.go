package admin

// content_search_guard_test.go — pins the security contract for the
// POST /admin/content-search/delete route: a caller without compliance.write
// is rejected 403 by the guard middleware before the handler is reached.
//
// Authorization is ROUTE-DECLARED (RequirePermAudited(PermComplianceWrite, …)
// in main.go). The reducer no longer self-authorizes on admin_role (Task 5
// RBAC unification cut-over). These tests mirror the wiring in main.go.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/permissions"
)

func makeContentSearchDeleteGuard(spy *permAuditSpy) http.Handler {
	return middleware.RequirePermAudited(permissions.PermComplianceWrite, spy.capture)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// tripwire: if reached, middleware let an unauthorized request through
		}))
}

// TestContentSearchDeleteGuard_DeniedWithoutComplianceWrite verifies that a
// caller holding an insufficient permission (e.g. compliance.read only, no
// compliance.write) is rejected 403 by the guard and the denial is audited.
func TestContentSearchDeleteGuard_DeniedWithoutComplianceWrite(t *testing.T) {
	cases := []struct {
		name  string
		perms []string
	}{
		{"no_perms", []string{}},
		{"compliance_read_only", []string{permissions.PermComplianceRead}},
		{"users_read_only", []string{permissions.PermUsersRead}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spy := &permAuditSpy{}
			handler := makeContentSearchDeleteGuard(spy)

			req := httptest.NewRequest("POST", "/admin/content-search/delete", nil)
			req = req.WithContext(auth.ContextWithUser(req.Context(), claimsWith(tc.perms...)))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s: want 403, got %d", tc.name, rec.Code)
			}
			if len(spy.events) != 1 {
				t.Fatalf("%s: want 1 audit event, got %d", tc.name, len(spy.events))
			}
			if spy.events[0].Action != "console.denied" {
				t.Errorf("%s: audit Action = %q, want console.denied", tc.name, spy.events[0].Action)
			}
			if spy.events[0].Detail != permissions.PermComplianceWrite {
				t.Errorf("%s: audit Detail = %q, want %q", tc.name, spy.events[0].Detail, permissions.PermComplianceWrite)
			}
		})
	}
}

// TestContentSearchDeleteGuard_AllowedWithComplianceWrite verifies that a
// caller holding compliance.write passes the guard and reaches the inner
// handler — proven by the handler writing a 200. The guard must NOT audit
// this caller as denied.
func TestContentSearchDeleteGuard_AllowedWithComplianceWrite(t *testing.T) {
	reached := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})

	spy := &permAuditSpy{}
	guarded := middleware.RequirePermAudited(permissions.PermComplianceWrite, spy.capture)(inner)

	req := httptest.NewRequest("POST", "/admin/content-search/delete", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), claimsWith(permissions.PermComplianceWrite)))
	rec := httptest.NewRecorder()
	guarded.ServeHTTP(rec, req)

	if rec.Code == http.StatusForbidden {
		t.Fatalf("compliance.write holder should NOT be denied, got 403")
	}
	if !reached {
		t.Fatal("compliance.write holder did not reach the handler")
	}
	if len(spy.events) != 0 {
		t.Fatalf("authorized caller must not be audited as denied, got %v", spy.events)
	}
}
