package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/permissions"
)

// TestRolesManageGuard pins the security contract for the /admin/roles* routes:
// they MUST gate on permissions.RolesManage, NOT the Auth console's users.read.
//
// Regression target: before this guard, /admin/roles* was wired with
// requireAuthPerm (users.read), so any user_admin — who holds users.read — could
// POST /admin/roles to create an all-permissions role group and assign it to
// themselves, a vertical privilege escalation to super-admin. The guard mirrors
// main.go's wiring (RequirePermAudited(PermRolesManage, …)); the matrix-test
// house style verifies the middleware behaviour that main.go composes.
func TestRolesManageGuard(t *testing.T) {
	// Mirrors main.go: requireRolesManage on every /admin/roles* route.
	makeRolesHandler := func(spy *matrixAuditSpy) http.Handler {
		return middleware.RequirePermAudited(permissions.PermRolesManage, spy.capture)(okHandler)
	}

	tests := []struct {
		name      string
		perms     []string
		wantCode  int
		wantAudit int
	}{
		{
			name:      "super_admin (all perms, includes roles.manage) → allowed",
			perms:     superAdminPerms,
			wantCode:  http.StatusOK,
			wantAudit: 0,
		},
		{
			name:      "user_admin (users.read only, no roles.manage) → denied",
			perms:     userAdminPerms, // []string{PermUsersRead}
			wantCode:  http.StatusForbidden,
			wantAudit: 1,
		},
		{
			name:      "roles.manage holder (the single grant) → allowed",
			perms:     []string{permissions.PermRolesManage},
			wantCode:  http.StatusOK,
			wantAudit: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spy := &matrixAuditSpy{}
			handler := makeRolesHandler(spy)

			req := httptest.NewRequest("POST", "/admin/roles", nil)
			ctx := auth.ContextWithUser(req.Context(), matrixTestClaims(1, tt.perms))
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("got %d, want %d", w.Code, tt.wantCode)
			}
			if len(spy.events) != tt.wantAudit {
				t.Errorf("got %d audit events, want %d", len(spy.events), tt.wantAudit)
			}
			if tt.wantAudit > 0 && spy.events[0].Detail != permissions.PermRolesManage {
				t.Errorf("audit detail = %q, want %q", spy.events[0].Detail, permissions.PermRolesManage)
			}
		})
	}
}

// TestRolesManageGuardLegacyBridgeDenied confirms the legacy IsAdmin-with-no-perms
// bridge is GONE: a token holding no granular perms is denied (403 + audit) on the
// roles-manage guard, matching every other audited console guard.
func TestRolesManageGuardLegacyBridgeDenied(t *testing.T) {
	spy := &matrixAuditSpy{}
	handler := middleware.RequirePermAudited(permissions.PermRolesManage, spy.capture)(okHandler)

	claims := &auth.Claims{
		UserID:      1,
		Email:       "admin@example.com",
		IsAdmin:     true,
		Permissions: nil, // no granular perms — bridge deleted, so nothing is held
		Type:        jwtutil.TypeAccess,
	}

	req := httptest.NewRequest("POST", "/admin/roles", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("empty-perms is_admin: got %d, want 403 (legacy bridge deleted)", w.Code)
	}
	if len(spy.events) != 1 {
		t.Errorf("empty-perms is_admin: got %d audit events, want 1", len(spy.events))
	}
}

// TestRolesManageGuardUnauthenticated confirms no-claims → 401, never audited.
func TestRolesManageGuardUnauthenticated(t *testing.T) {
	spy := &matrixAuditSpy{}
	handler := middleware.RequirePermAudited(permissions.PermRolesManage, spy.capture)(okHandler)

	req := httptest.NewRequest("POST", "/admin/roles", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated: got %d, want 401", w.Code)
	}
	if len(spy.events) != 0 {
		t.Errorf("unauthenticated: got %d audit events, want 0 (401 not audited)", len(spy.events))
	}
}
