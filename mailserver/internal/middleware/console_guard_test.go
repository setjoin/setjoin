package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/permissions"
)

// ── AuditEvent / AuditFunc ──────────────────────────────────────────────────
// These types are defined in console_guard.go; tests reference them directly.

// permTestClaims creates a Claims with explicit permissions and domain-scope for
// permission-middleware tests.  Distinct from the single-arg permTestClaims in
// app_entitlement_test.go.
func permTestClaims(uid int64, perms []string, scope *int64) *auth.Claims {
	// IsAdmin is set true here but no longer grants anything on its own: the legacy
	// is_admin bridge has been deleted, so authorization flows exclusively from the
	// Permissions slice. Tests passing explicit perms exercise the real grant path;
	// tests passing nil perms now assert DENY.
	return &auth.Claims{
		UserID:      uid,
		Email:       "test@example.com",
		IsAdmin:     true,
		Permissions: perms,
		DomainScope: scope,
		Type:        jwtutil.TypeAccess,
	}
}

// ── Audit spy ────────────────────────────────────────────────────────────────

// auditSpy captures audit events in-memory for test assertions.
type auditSpy struct {
	events []AuditEvent
}

func (s *auditSpy) capture(_ context.Context, ev AuditEvent) {
	s.events = append(s.events, ev)
}

// ── RequirePermAudited tests ─────────────────────────────────────────────────

func TestRequirePermAudited_Unauthenticated(t *testing.T) {
	req := httptest.NewRequest("GET", "/admin/logs/audit", nil)
	w := httptest.NewRecorder()
	spy := &auditSpy{}

	handler := RequirePermAudited(permissions.PermAuditRead, spy.capture)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for unauthenticated, got %d", w.Code)
	}
	if len(spy.events) != 0 {
		t.Errorf("expected no audit event for 401, got %d", len(spy.events))
	}
}

func TestRequirePermAudited_MissingPermission(t *testing.T) {
	claims := permTestClaims(1, []string{"queue.read"}, nil)
	req := httptest.NewRequest("GET", "/admin/logs/audit", nil)
	ctx := auth.ContextWithUser(req.Context(), claims)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	spy := &auditSpy{}

	handler := RequirePermAudited(permissions.PermAuditRead, spy.capture)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for missing permission, got %d", w.Code)
	}
	if len(spy.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(spy.events))
	}
	ev := spy.events[0]
	if ev.Actor != "test@example.com" {
		t.Errorf("expected actor 'test@example.com', got %q", ev.Actor)
	}
	if ev.Action != "console.denied" {
		t.Errorf("expected action 'console.denied', got %q", ev.Action)
	}
	if ev.Target != "/admin/logs/audit" {
		t.Errorf("expected target '/admin/logs/audit', got %q", ev.Target)
	}
	if ev.Detail != permissions.PermAuditRead {
		t.Errorf("expected detail %q, got %q", permissions.PermAuditRead, ev.Detail)
	}
}

func TestRequirePermAudited_HasPermission(t *testing.T) {
	claims := permTestClaims(1, []string{permissions.PermAuditRead, "queue.read"}, nil)
	req := httptest.NewRequest("GET", "/admin/logs/audit", nil)
	ctx := auth.ContextWithUser(req.Context(), claims)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	spy := &auditSpy{}

	handler := RequirePermAudited(permissions.PermAuditRead, spy.capture)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for held permission, got %d", w.Code)
	}
	if len(spy.events) != 0 {
		t.Errorf("expected no audit event on success, got %d", len(spy.events))
	}
}

func TestRequirePermAudited_LegacyIsAdminDenied(t *testing.T) {
	// Bridge deleted: IsAdmin=true with no resolved permissions → 403 + audit.
	claims := permTestClaims(2, nil, nil)
	req := httptest.NewRequest("GET", "/admin/system/config", nil)
	ctx := auth.ContextWithUser(req.Context(), claims)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	spy := &auditSpy{}

	handler := RequirePermAudited(permissions.PermSystemConfig, spy.capture)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 (legacy is_admin bridge deleted), got %d", w.Code)
	}
	if len(spy.events) != 1 {
		t.Errorf("expected 1 audit event on denial, got %d", len(spy.events))
	}
}

func TestRequirePermAudited_LegacyNoAdminNoPermissions(t *testing.T) {
	claims := permTestClaims(3, nil, nil)
	claims.IsAdmin = false
	req := httptest.NewRequest("GET", "/admin/logs/audit", nil)
	ctx := auth.ContextWithUser(req.Context(), claims)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	spy := &auditSpy{}

	handler := RequirePermAudited(permissions.PermAuditRead, spy.capture)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-admin without permissions, got %d", w.Code)
	}
	if len(spy.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(spy.events))
	}
}

func TestRequirePermAudited_DomainScopePropagation(t *testing.T) {
	scope := int64(5)
	claims := permTestClaims(1, []string{"users.read"}, &scope)
	req := httptest.NewRequest("GET", "/admin/users", nil)
	ctx := auth.ContextWithUser(req.Context(), claims)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	spy := &auditSpy{}

	var capturedScope int64
	handler := RequirePermAudited("users.read", spy.capture)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedScope = DomainScopeFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		}),
	)
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if capturedScope != 5 {
		t.Errorf("expected domain scope 5, got %d", capturedScope)
	}
}

// ── RequireAnyPermAudited tests ──────────────────────────────────────────────

func TestRequireAnyPermAudited_MissingAllPermissions(t *testing.T) {
	claims := permTestClaims(1, []string{"some.other.perm"}, nil)
	req := httptest.NewRequest("GET", "/admin/mail/domains", nil)
	ctx := auth.ContextWithUser(req.Context(), claims)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	spy := &auditSpy{}

	scopes := []string{permissions.PermDomainsRead, permissions.PermQueueRead, permissions.PermReportsRead}
	handler := RequireAnyPermAudited(scopes, spy.capture)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 when holding none of the required scopes, got %d", w.Code)
	}
	if len(spy.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(spy.events))
	}
	ev := spy.events[0]
	if ev.Action != "console.denied" {
		t.Errorf("expected action 'console.denied', got %q", ev.Action)
	}
}

func TestRequireAnyPermAudited_HasOneOfMany(t *testing.T) {
	claims := permTestClaims(1, []string{permissions.PermDomainsRead}, nil)
	req := httptest.NewRequest("GET", "/admin/mail/domains", nil)
	ctx := auth.ContextWithUser(req.Context(), claims)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	spy := &auditSpy{}

	scopes := []string{permissions.PermDomainsRead, permissions.PermQueueRead, permissions.PermReportsRead}
	handler := RequireAnyPermAudited(scopes, spy.capture)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 when holding one of the required scopes, got %d", w.Code)
	}
	if len(spy.events) != 0 {
		t.Errorf("expected no audit event on success, got %d", len(spy.events))
	}
}

func TestRequireAnyPermissionSetAudited_ORBetweenANDSets(t *testing.T) {
	t.Parallel()
	permissionSets := [][]string{
		{permissions.PermAuditExport},
		{permissions.PermSystemUpgrade, permissions.PermIdentityWrite},
	}
	tests := []struct {
		name   string
		perms  []string
		status int
	}{
		{"audit exporter", []string{permissions.PermAuditExport}, http.StatusOK},
		{"upgrade pair", []string{
			permissions.PermSystemUpgrade, permissions.PermIdentityWrite,
		}, http.StatusOK},
		{"upgrade alone", []string{permissions.PermSystemUpgrade}, http.StatusForbidden},
		{"identity alone", []string{permissions.PermIdentityWrite}, http.StatusForbidden},
		{"unrelated", []string{permissions.PermUsersRead}, http.StatusForbidden},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims := permTestClaims(1, tc.perms, nil)
			req := httptest.NewRequest("GET", "/admin/identity/v2/jobs/id", nil)
			req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
			w := httptest.NewRecorder()
			spy := &auditSpy{}
			handler := RequireAnyPermissionSetAudited(permissionSets, spy.capture)(
				http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusOK)
				}),
			)
			handler.ServeHTTP(w, req)
			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d", w.Code, tc.status)
			}
			if tc.status == http.StatusForbidden {
				if len(spy.events) != 1 ||
					spy.events[0].Detail !=
						permissions.PermAuditExport+"|"+
							permissions.PermSystemUpgrade+"&"+
							permissions.PermIdentityWrite {
					t.Fatalf("denial audit = %+v", spy.events)
				}
			} else if len(spy.events) != 0 {
				t.Fatalf("successful access was audited as denied: %+v", spy.events)
			}
		})
	}
}

func TestRequireAnyPermAudited_HasSecondOfMany(t *testing.T) {
	// tests that the second scope in the list also works.
	claims := permTestClaims(1, []string{permissions.PermQueueRead}, nil)
	req := httptest.NewRequest("GET", "/admin/mail/queue", nil)
	ctx := auth.ContextWithUser(req.Context(), claims)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	spy := &auditSpy{}

	scopes := []string{permissions.PermDomainsRead, permissions.PermQueueRead, permissions.PermReportsRead}
	handler := RequireAnyPermAudited(scopes, spy.capture)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 when holding second scope, got %d", w.Code)
	}
}

func TestRequireAnyPermAudited_LegacyIsAdminDenied(t *testing.T) {
	claims := permTestClaims(2, nil, nil) // IsAdmin=true, no perms → 403 (bridge deleted)
	req := httptest.NewRequest("GET", "/admin/mail/domains", nil)
	ctx := auth.ContextWithUser(req.Context(), claims)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	spy := &auditSpy{}

	scopes := []string{permissions.PermDomainsRead, permissions.PermQueueRead, permissions.PermReportsRead}
	handler := RequireAnyPermAudited(scopes, spy.capture)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 (legacy is_admin bridge deleted), got %d", w.Code)
	}
	if len(spy.events) != 1 {
		t.Errorf("expected 1 audit event on denial, got %d", len(spy.events))
	}
}

func TestRequireAnyPermAudited_Unauthenticated(t *testing.T) {
	req := httptest.NewRequest("GET", "/admin/mail/domains", nil)
	w := httptest.NewRecorder()
	spy := &auditSpy{}

	scopes := []string{permissions.PermDomainsRead}
	handler := RequireAnyPermAudited(scopes, spy.capture)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for unauthenticated, got %d", w.Code)
	}
	if len(spy.events) != 0 {
		t.Errorf("expected no audit event for 401, got %d", len(spy.events))
	}
}

func TestRequireAnyPermAudited_EmptyScopeList(t *testing.T) {
	// An empty scope list should deny access (no scope means no one gets in).
	claims := permTestClaims(1, []string{"some.perm"}, nil)
	req := httptest.NewRequest("GET", "/admin/something", nil)
	ctx := auth.ContextWithUser(req.Context(), claims)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	spy := &auditSpy{}

	handler := RequireAnyPermAudited(nil, spy.capture)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for empty scope list, got %d", w.Code)
	}
	if len(spy.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(spy.events))
	}
}

// ── AuditEvent shape test ────────────────────────────────────────────────────

func TestAuditEventShape(t *testing.T) {
	ev := AuditEvent{
		Actor:  "admin@example.com",
		Action: "console.denied",
		Target: "/admin/logs/audit",
		Detail: "audit.read",
	}
	if ev.Actor != "admin@example.com" {
		t.Errorf("unexpected actor")
	}
	if ev.Action != "console.denied" {
		t.Errorf("unexpected action")
	}
	if ev.Target != "/admin/logs/audit" {
		t.Errorf("unexpected target")
	}
	if ev.Detail != "audit.read" {
		t.Errorf("unexpected detail")
	}
}
