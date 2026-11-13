package admin

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/permissions"
)

// permAuditSpy captures console.denied events so each case can assert the
// denial was audited — the whole point of the deepening.
type permAuditSpy struct{ events []middleware.AuditEvent }

func (s *permAuditSpy) capture(_ context.Context, ev middleware.AuditEvent) {
	s.events = append(s.events, ev)
}

// claimsWith builds a *scoped* admin: IsAdmin is true, but the caller carries
// an explicit (non-empty) permission set so the legacy IsAdmin bridge
// (permissions.Check: IsAdmin && len(perms)==0 ⇒ full access) does NOT fire.
// The held permissions deliberately exclude the scope the route requires, so
// the audited middleware must deny.
func claimsWith(perms ...string) *auth.Claims {
	return &auth.Claims{
		UserID:      7,
		Email:       "scoped@example.com",
		IsAdmin:     true, // an admin, but a *scoped* one
		Permissions: perms,
		Type:        jwtutil.TypeAccess,
	}
}

// TestMDMRoutes_UnderPrivilegedDeniedAtMiddleware proves that for every MDM
// route, a caller lacking the required scope is rejected with 403 by the
// guard middleware (not the handler) and the denial is audited. A tripwire
// handler is the wrapped target: if the request ever reaches it the test
// fails, proving enforcement happened strictly upstream.
func TestMDMRoutes_UnderPrivilegedDeniedAtMiddleware(t *testing.T) {
	// tripwire: reaching this means the middleware let an unauthorized
	// request through to the handler — a hard failure.
	tripwire := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("request reached handler; middleware failed to deny")
	})

	readGuard := func(spy *permAuditSpy) http.Handler {
		return middleware.RequirePermAudited(permissions.PermMAMRead, spy.capture)(tripwire)
	}
	writeGuard := func(spy *permAuditSpy) http.Handler {
		return middleware.RequirePermAudited(permissions.PermMAMWrite, spy.capture)(tripwire)
	}

	cases := []struct {
		name   string
		method string
		path   string
		build  func(*permAuditSpy) http.Handler
		held   []string // permissions the caller holds (insufficient, non-empty)
		scope  string   // expected audit Detail
	}{
		{"ListDevices", "GET", "/admin/mdm/devices", readGuard, []string{permissions.PermDomainsRead}, permissions.PermMAMRead},
		{"GetDevice", "GET", "/admin/mdm/devices/x", readGuard, []string{permissions.PermDomainsRead}, permissions.PermMAMRead},
		{"ListPolicies", "GET", "/admin/mdm/policies", readGuard, []string{permissions.PermDomainsRead}, permissions.PermMAMRead},
		{"TriggerWipe", "POST", "/admin/mdm/devices/x/wipe", writeGuard, []string{permissions.PermMAMRead}, permissions.PermMAMWrite},
		{"CreatePolicy", "POST", "/admin/mdm/policies", writeGuard, []string{permissions.PermMAMRead}, permissions.PermMAMWrite},
		{"UpdatePolicy", "PUT", "/admin/mdm/policies/1", writeGuard, []string{permissions.PermMAMRead}, permissions.PermMAMWrite},
		{"DeletePolicy", "DELETE", "/admin/mdm/policies/1", writeGuard, []string{permissions.PermMAMRead}, permissions.PermMAMWrite},
		{"ReorderPolicies", "PUT", "/admin/mdm/policies/reorder", writeGuard, []string{permissions.PermMAMRead}, permissions.PermMAMWrite},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spy := &permAuditSpy{}
			guarded := tc.build(spy)

			req := httptest.NewRequest(tc.method, tc.path, nil)
			req = req.WithContext(auth.ContextWithUser(req.Context(), claimsWith(tc.held...)))
			rec := httptest.NewRecorder()
			guarded.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s: want 403, got %d", tc.name, rec.Code)
			}
			if len(spy.events) != 1 {
				t.Fatalf("%s: want 1 audit event, got %d", tc.name, len(spy.events))
			}
			if spy.events[0].Action != "console.denied" {
				t.Errorf("%s: audit Action = %q, want console.denied", tc.name, spy.events[0].Action)
			}
			if spy.events[0].Detail != tc.scope {
				t.Errorf("%s: audit Detail = %q, want %q", tc.name, spy.events[0].Detail, tc.scope)
			}
			if spy.events[0].Target != tc.path {
				t.Errorf("%s: audit Target = %q, want %q", tc.name, spy.events[0].Target, tc.path)
			}
		})
	}
}

// TestMDMRoutes_SufficientlyPrivilegedReachesHandler proves the wiring grants
// access correctly: a caller holding the required scope passes the guard and
// reaches the (nil-pool) handler — a 500, not a 403 — and is NOT audited as
// denied. This is the regression tripwire that fires if anyone re-adds an
// inline auth check inside the handler.
func TestMDMRoutes_SufficientlyPrivilegedReachesHandler(t *testing.T) {
	h := NewMDMHandler(nil, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	spy := &permAuditSpy{}
	guarded := middleware.RequirePermAudited(permissions.PermMAMRead, spy.capture)(
		http.HandlerFunc(h.ListPolicies))
	req := httptest.NewRequest("GET", "/admin/mdm/policies", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), claimsWith(permissions.PermMAMRead)))
	rec := httptest.NewRecorder()
	guarded.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError { // nil pool -> handler reached
		t.Fatalf("authorized caller should reach handler (500 nil pool), got %d", rec.Code)
	}
	if len(spy.events) != 0 {
		t.Fatalf("authorized caller must not be audited as denied, got %v", spy.events)
	}
}
