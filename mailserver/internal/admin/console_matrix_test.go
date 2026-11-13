package admin

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

// ── test helpers ─────────────────────────────────────────────────────────────

// matrixTestClaims creates test Claims with explicit permissions.  Mirrors the
// pattern in console_guard_test.go.
func matrixTestClaims(uid int64, perms []string) *auth.Claims {
	return &auth.Claims{
		UserID:      uid,
		Email:       "test@example.com",
		IsAdmin:     true,
		Permissions: perms,
		DomainScope: nil,
		Type:        jwtutil.TypeAccess,
	}
}

// okHandler returns 200 for any request (passthrough after middleware).
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

// auditSpy captures audit events in-memory for the matrix test assertions.
type matrixAuditSpy struct {
	events []middleware.AuditEvent
}

func (s *matrixAuditSpy) capture(_ context.Context, ev middleware.AuditEvent) {
	s.events = append(s.events, ev)
}

// ── 4-role definitions ───────────────────────────────────────────────────────

var (
	superAdminPerms = permissions.AllPermissions
	userAdminPerms  = []string{permissions.PermUsersRead}
	auditorPerms    = []string{permissions.PermAuditRead}
	readOnlyPerms   = []string{permissions.PermReportsRead}
)

// ── Console middleware builders (mirror main.go) ──────────────────────────────

// makeLogsHandler returns a handler guarded by RequirePermAudited for audit.read
// (the Logs console guard), wired to an audit spy.
func makeLogsHandler(spy *matrixAuditSpy) http.Handler {
	return middleware.RequirePermAudited(permissions.PermAuditRead, spy.capture)(okHandler)
}

// makeAuthHandler returns a handler guarded by RequirePermAudited for users.read
// (the Auth admin console guard).
func makeAuthHandler(spy *matrixAuditSpy) http.Handler {
	return middleware.RequirePermAudited(permissions.PermUsersRead, spy.capture)(okHandler)
}

// makeSystemHandler returns a handler guarded by RequireAnyPermAudited for the
// System console scopes (system.config|system.upgrade|backup.read).
func makeSystemHandler(spy *matrixAuditSpy) http.Handler {
	return middleware.RequireAnyPermAudited(
		[]string{permissions.PermSystemConfig, permissions.PermSystemUpgrade, permissions.PermBackupRead},
		spy.capture,
	)(okHandler)
}

// makeMailHandler returns a handler guarded by RequireAnyPermAudited for the
// Mail admin console scopes (domains.read|queue.read|reports.read).
func makeMailHandler(spy *matrixAuditSpy) http.Handler {
	return middleware.RequireAnyPermAudited(
		[]string{permissions.PermDomainsRead, permissions.PermQueueRead, permissions.PermReportsRead},
		spy.capture,
	)(okHandler)
}

// ── matrix test ──────────────────────────────────────────────────────────────

func TestConsoleMatrix(t *testing.T) {
	type endpoint struct {
		name    string
		handler http.Handler
		spy     *matrixAuditSpy
	}

	// Build the four console-guarded endpoints matching main.go's wiring.
	logsSpy := &matrixAuditSpy{}
	authSpy := &matrixAuditSpy{}
	systemSpy := &matrixAuditSpy{}
	mailSpy := &matrixAuditSpy{}

	endpoints := []endpoint{
		{name: "/admin/audit", handler: makeLogsHandler(logsSpy), spy: logsSpy},
		{name: "/admin/users", handler: makeAuthHandler(authSpy), spy: authSpy},
		{name: "/admin/features", handler: makeSystemHandler(systemSpy), spy: systemSpy},
		{name: "/admin/domains", handler: makeMailHandler(mailSpy), spy: mailSpy},
	}

	tests := []struct {
		name         string
		perms        []string
		wantAudit    int // /admin/audit (logs console)
		wantUsers    int // /admin/users (auth console)
		wantFeatures int // /admin/features (system console)
		wantDomains  int // /admin/domains (mail console)
	}{
		{
			name:         "super_admin (all perms)",
			perms:        superAdminPerms,
			wantAudit:    http.StatusOK,
			wantUsers:    http.StatusOK,
			wantFeatures: http.StatusOK,
			wantDomains:  http.StatusOK,
		},
		{
			name:         "user_admin (users.read only)",
			perms:        userAdminPerms,
			wantAudit:    http.StatusForbidden,
			wantUsers:    http.StatusOK,
			wantFeatures: http.StatusForbidden,
			wantDomains:  http.StatusForbidden,
		},
		{
			name:         "auditor (audit.read only)",
			perms:        auditorPerms,
			wantAudit:    http.StatusOK,
			wantUsers:    http.StatusForbidden,
			wantFeatures: http.StatusForbidden,
			wantDomains:  http.StatusForbidden,
		},
		{
			name:         "read_only (reports.read only)",
			perms:        readOnlyPerms,
			wantAudit:    http.StatusForbidden,
			wantUsers:    http.StatusForbidden,
			wantFeatures: http.StatusForbidden,
			wantDomains:  http.StatusOK,
		},
	}

	// Map endpoint name to expected status for quick lookup.
	wantMap := map[string]map[string]int{}
	for _, tt := range tests {
		wantMap[tt.name] = map[string]int{
			"/admin/audit":    tt.wantAudit,
			"/admin/users":    tt.wantUsers,
			"/admin/features": tt.wantFeatures,
			"/admin/domains":  tt.wantDomains,
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := matrixTestClaims(1, tt.perms)

			for _, ep := range endpoints {
				want := wantMap[tt.name][ep.name]

				ep.spy.events = nil // reset audit spy between requests

				req := httptest.NewRequest("GET", ep.name, nil)
				ctx := auth.ContextWithUser(req.Context(), claims)
				req = req.WithContext(ctx)
				w := httptest.NewRecorder()
				ep.handler.ServeHTTP(w, req)

				if w.Code != want {
					t.Errorf("%s → %s: got %d, want %d", tt.name, ep.name, w.Code, want)
				}

				// On 403, an audit event must be emitted.
				if want == http.StatusForbidden && len(ep.spy.events) != 1 {
					t.Errorf("%s → %s: expected 1 audit event for denial, got %d",
						tt.name, ep.name, len(ep.spy.events))
				}

				// On 200, no audit event must be emitted.
				if want == http.StatusOK && len(ep.spy.events) != 0 {
					t.Errorf("%s → %s: expected 0 audit events for success, got %d",
						tt.name, ep.name, len(ep.spy.events))
				}
			}
		})
	}
}

// ── auditor least-privilege assertion ─────────────────────────────────────────

// TestConsoleMatrixAuditorLeastPrivilege is the targeted assertion for spec
// §6.6 risk #5: "auditor least-privilege is a stated product property".  The
// auditor (audit.read only) must see ONLY Logs endpoints.
func TestConsoleMatrixAuditorLeastPrivilege(t *testing.T) {
	auditorClaims := matrixTestClaims(1, auditorPerms)

	// Auditor must access Logs console endpoints.
	logsSpy := &matrixAuditSpy{}
	logsHandler := makeLogsHandler(logsSpy)

	req := httptest.NewRequest("GET", "/admin/audit", nil)
	ctx := auth.ContextWithUser(req.Context(), auditorClaims)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	logsHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("auditor on /admin/audit: got %d, want 200 — auditor must access audit log", w.Code)
	}
	if len(logsSpy.events) != 0 {
		t.Errorf("auditor on /admin/audit: expected 0 audit events, got %d", len(logsSpy.events))
	}

	// Auditor must NOT access auth console endpoints.
	authSpy := &matrixAuditSpy{}
	authHandler := makeAuthHandler(authSpy)

	req = httptest.NewRequest("GET", "/admin/users", nil)
	ctx = auth.ContextWithUser(req.Context(), auditorClaims)
	req = req.WithContext(ctx)
	w = httptest.NewRecorder()
	authHandler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("auditor on /admin/users: got %d, want 403 — auditor must NOT access auth console", w.Code)
	}
	if len(authSpy.events) != 1 {
		t.Errorf("auditor on /admin/users: expected 1 audit event for denial, got %d", len(authSpy.events))
	}

	// Auditor must NOT access system console endpoints.
	systemSpy := &matrixAuditSpy{}
	systemHandler := makeSystemHandler(systemSpy)

	req = httptest.NewRequest("GET", "/admin/features", nil)
	ctx = auth.ContextWithUser(req.Context(), auditorClaims)
	req = req.WithContext(ctx)
	w = httptest.NewRecorder()
	systemHandler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("auditor on /admin/features: got %d, want 403 — auditor must NOT access system console", w.Code)
	}
	if len(systemSpy.events) != 1 {
		t.Errorf("auditor on /admin/features: expected 1 audit event for denial, got %d", len(systemSpy.events))
	}

	// Auditor must NOT access mail admin console endpoints.
	mailSpy := &matrixAuditSpy{}
	mailHandler := makeMailHandler(mailSpy)

	req = httptest.NewRequest("GET", "/admin/domains", nil)
	ctx = auth.ContextWithUser(req.Context(), auditorClaims)
	req = req.WithContext(ctx)
	w = httptest.NewRecorder()
	mailHandler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("auditor on /admin/domains: got %d, want 403 — auditor must NOT access mail admin console", w.Code)
	}
	if len(mailSpy.events) != 1 {
		t.Errorf("auditor on /admin/domains: expected 1 audit event for denial, got %d", len(mailSpy.events))
	}
}

// ── ConsolesForPerms integration assertions ───────────────────────────────────

func TestConsoleMatrixConsolesForPermsMatchesMiddleware(t *testing.T) {
	// Verify that ConsolesForPerms output is consistent with what the
	// middleware actually enforces.  For each role, the consoles returned by
	// ConsolesForPerms should be exactly those whose endpoints return 200.

	roles := []struct {
		name  string
		perms []string
	}{
		{"super_admin", superAdminPerms},
		{"user_admin", userAdminPerms},
		{"auditor", auditorPerms},
		{"read_only", readOnlyPerms},
	}

	for _, r := range roles {
		t.Run(r.name, func(t *testing.T) {
			claims := matrixTestClaims(1, r.perms)

			// Determine which consoles ConsolesForPerms returns.
			accessibleConsoles := ConsolesForPerms(r.perms)

			// For each console, verify the middleware matches.
			consoleTests := []struct {
				console ConsoleID
				handler http.Handler
				spy     *matrixAuditSpy
			}{
				{ConsoleLogs, makeLogsHandler(&matrixAuditSpy{}), nil},
				{ConsoleAuth, makeAuthHandler(&matrixAuditSpy{}), nil},
				{ConsoleSystem, makeSystemHandler(&matrixAuditSpy{}), nil},
				{ConsoleMail, makeMailHandler(&matrixAuditSpy{}), nil},
			}

			hasConsole := func(id ConsoleID) bool {
				for _, c := range accessibleConsoles {
					if c == id {
						return true
					}
				}
				return false
			}

			for _, ct := range consoleTests {
				req := httptest.NewRequest("GET", "/admin/test", nil)
				ctx := auth.ContextWithUser(req.Context(), claims)
				req = req.WithContext(ctx)
				w := httptest.NewRecorder()
				ct.handler.ServeHTTP(w, req)

				expectedAccess := hasConsole(ct.console)
				if expectedAccess && w.Code != http.StatusOK {
					t.Errorf("%s: ConsolesForPerms says %q is accessible, but middleware returned %d",
						r.name, ct.console, w.Code)
				}
				if !expectedAccess && w.Code != http.StatusForbidden {
					t.Errorf("%s: ConsolesForPerms says %q is NOT accessible, but middleware returned %d",
						r.name, ct.console, w.Code)
				}
			}
		})
	}
}

// ── Super-admin (all perms) ────────────────────────────────────────────────────

func TestConsoleMatrixLegacySuperAdmin(t *testing.T) {
	// A real super-admin carries AllPermissions (resolved from a governed Super
	// Admin assignment) and reaches every console. The legacy is_admin bridge has
	// been deleted, so the all-perms slice — not the IsAdmin flag — is what grants.
	claims := &auth.Claims{
		UserID:      1,
		Email:       "admin@example.com",
		IsAdmin:     true,
		Permissions: permissions.AllPermissions,
		DomainScope: nil,
		Type:        jwtutil.TypeAccess,
	}

	logsSpy := &matrixAuditSpy{}
	authSpy := &matrixAuditSpy{}
	systemSpy := &matrixAuditSpy{}
	mailSpy := &matrixAuditSpy{}

	endpoints := []struct {
		name    string
		handler http.Handler
		spy     *matrixAuditSpy
	}{
		{"/admin/audit", makeLogsHandler(logsSpy), logsSpy},
		{"/admin/users", makeAuthHandler(authSpy), authSpy},
		{"/admin/features", makeSystemHandler(systemSpy), systemSpy},
		{"/admin/domains", makeMailHandler(mailSpy), mailSpy},
	}

	for _, ep := range endpoints {
		req := httptest.NewRequest("GET", ep.name, nil)
		ctx := auth.ContextWithUser(req.Context(), claims)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()
		ep.handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("super_admin (all perms) on %s: got %d, want 200", ep.name, w.Code)
		}
		if len(ep.spy.events) != 0 {
			t.Errorf("super_admin (all perms) on %s: expected 0 audit events, got %d", ep.name, len(ep.spy.events))
		}
	}
}

func TestConsoleAccessScope(t *testing.T) {
	// V126 (Chat A4a Task 1) added the chat compliance perms to the Access
	// console scope set (Global Constraints, perm registration site 4).
	// V127 (Chat A4b Task 1) appended chat.ediscovery (D-A perm registration
	// site 4) — deliberately outside the SoD class map, but still surfaced
	// on the Access console the way its sibling chat.compliance_* perms are.
	// V139 (Pillar C1 Task 8) appended federation.manage on the same
	// visibility-only precedent as drive.view. V181 adds system.recovery as a
	// dedicated route-gated Access page without broadening the System umbrella.
	got := ConsoleScopes[ConsoleAccess]
	if len(got) != 8 || got[0] != permissions.PermRolesManage || got[1] != permissions.PermSharingRead ||
		got[2] != permissions.PermChatComplianceView || got[3] != permissions.PermChatComplianceManage ||
		got[4] != permissions.PermChatEDiscovery || got[5] != permissions.PermDriveView ||
		got[6] != permissions.PermFederationManage || got[7] != permissions.PermSystemRecovery {
		t.Fatalf("ConsoleScopes[ConsoleAccess] = %v, want [roles.manage sharing.read chat.compliance_view chat.compliance_manage chat.ediscovery drive.view federation.manage system.recovery]", got)
	}
	// ConsolesForPerms surfaces it for a roles.manage holder, not for a plain user_admin.
	if !contains(ConsolesForPerms([]string{permissions.PermRolesManage}), ConsoleAccess) {
		t.Error("roles.manage holder should see the access console")
	}
	if contains(ConsolesForPerms(userAdminPerms), ConsoleAccess) {
		t.Error("user_admin (users.read) must NOT see the access console")
	}
	// drive.view rides Access for VISIBILITY only (consoles.go's comment): a
	// drive.view-only admin must see the Access console (it carries the SPA's
	// /admin/drive + /admin/meet-recordings nav items) — and MUST NOT see the
	// System console, whose scope set also derives requireSystemPerm
	// (backup-download/config-export must stay locked to system perms, SoD).
	driveOnly := ConsolesForPerms([]string{permissions.PermDriveView})
	if !contains(driveOnly, ConsoleAccess) {
		t.Error("drive.view-only holder should see the access console")
	}
	if contains(driveOnly, ConsoleSystem) {
		t.Error("drive.view-only holder must NOT see the system console")
	}
}

func contains(ids []ConsoleID, want ConsoleID) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// ── Unauthenticated ───────────────────────────────────────────────────────────

func TestConsoleMatrixUnauthenticated(t *testing.T) {
	// No claims in context = 401, never 403.
	logsSpy := &matrixAuditSpy{}
	authSpy := &matrixAuditSpy{}
	systemSpy := &matrixAuditSpy{}
	mailSpy := &matrixAuditSpy{}

	endpoints := []struct {
		name    string
		handler http.Handler
		spy     *matrixAuditSpy
	}{
		{"/admin/audit", makeLogsHandler(logsSpy), logsSpy},
		{"/admin/users", makeAuthHandler(authSpy), authSpy},
		{"/admin/features", makeSystemHandler(systemSpy), systemSpy},
		{"/admin/domains", makeMailHandler(mailSpy), mailSpy},
	}

	for _, ep := range endpoints {
		req := httptest.NewRequest("GET", ep.name, nil)
		// No auth context attached — unauthenticated.
		w := httptest.NewRecorder()
		ep.handler.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("unauthenticated on %s: got %d, want 401", ep.name, w.Code)
		}
		if len(ep.spy.events) != 0 {
			t.Errorf("unauthenticated on %s: expected 0 audit events (401 is not audited), got %d",
				ep.name, len(ep.spy.events))
		}
	}
}
