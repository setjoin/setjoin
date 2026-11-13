package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/permissions"
)

// TestMAMRoutes_UnderPrivilegedDeniedAtMiddleware mirrors the MDM contract for
// the MAM surface: an under-privileged caller is rejected with 403 at the
// guard middleware (tripwire handler is never reached) and the denial is
// audited exactly once with the missing scope as Detail. Reuses permAuditSpy
// and claimsWith from admin_mdm_perms_test.go (same package).
func TestMAMRoutes_UnderPrivilegedDeniedAtMiddleware(t *testing.T) {
	tripwire := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("request reached handler; middleware failed to deny")
	})
	read := func(s *permAuditSpy) http.Handler {
		return middleware.RequirePermAudited(permissions.PermMAMRead, s.capture)(tripwire)
	}
	write := func(s *permAuditSpy) http.Handler {
		return middleware.RequirePermAudited(permissions.PermMAMWrite, s.capture)(tripwire)
	}

	cases := []struct {
		name   string
		method string
		path   string
		build  func(*permAuditSpy) http.Handler
		held   []string
		scope  string
	}{
		{"ListPolicies", "GET", "/admin/mam/policies", read, []string{permissions.PermDomainsRead}, permissions.PermMAMRead},
		{"ListDevices", "GET", "/admin/mam/devices", read, []string{permissions.PermDomainsRead}, permissions.PermMAMRead},
		{"ListDevicesWriteOnly", "GET", "/admin/mam/devices", read, []string{permissions.PermMAMWrite}, permissions.PermMAMRead},
		{"GetDeviceEvents", "GET", "/admin/mam/devices/1/events", read, []string{permissions.PermDomainsRead}, permissions.PermMAMRead},
		{"SetGlobalPolicy", "PUT", "/admin/mam/policies", write, []string{permissions.PermMAMRead}, permissions.PermMAMWrite},
		{"LockDevice", "POST", "/admin/mam/devices/1/lock", write, []string{permissions.PermMAMRead}, permissions.PermMAMWrite},
		{"UnlockDevice", "POST", "/admin/mam/devices/1/unlock", write, []string{permissions.PermMAMRead}, permissions.PermMAMWrite},
		{"SetPerDevicePolicy", "PUT", "/admin/mam/devices/1/policy", write, []string{permissions.PermMAMRead}, permissions.PermMAMWrite},
		{"UnsetPerDevicePolicy", "DELETE", "/admin/mam/devices/1/policy/k", write, []string{permissions.PermMAMRead}, permissions.PermMAMWrite},
		{"SetGroupPolicy", "PUT", "/admin/mam/policies/group", write, []string{permissions.PermMAMRead}, permissions.PermMAMWrite},
		{"UnsetGroupPolicy", "DELETE", "/admin/mam/policies/group/department/1/k", write, []string{permissions.PermMAMRead}, permissions.PermMAMWrite},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spy := &permAuditSpy{}
			h := tc.build(spy)
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req = req.WithContext(auth.ContextWithUser(req.Context(), claimsWith(tc.held...)))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s: want 403, got %d", tc.name, rec.Code)
			}
			if len(spy.events) != 1 || spy.events[0].Detail != tc.scope {
				t.Fatalf("%s: want 1 audit event scope=%s, got %+v", tc.name, tc.scope, spy.events)
			}
			if spy.events[0].Action != "console.denied" {
				t.Errorf("%s: audit Action = %q, want console.denied", tc.name, spy.events[0].Action)
			}
		})
	}
}
