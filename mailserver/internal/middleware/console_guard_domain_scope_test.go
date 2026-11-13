package middleware

// Domain-scope contract tests (er5-s15, sealed anchors admin-worker-domain-
// scope-ignored + scoped-audit-readers-receive-organization-wide-audit-records-
// and-exports): a permission classified DomainGlobalOnlyScopes (audit.read /
// audit.export — org-wide by design, no domain dimension to filter by) is
// never served to a domain-scoped principal. The refusal is audited with the
// scope in the Detail; global admins pass unchanged; per-domain surfaces
// (DLP/MDM/... perms) keep serving scoped admins.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/permissions"
)

func scopeClaims(scope *int64, perms ...string) *auth.Claims {
	return &auth.Claims{
		Email:       "admin@setjoin.test",
		Permissions: perms,
		DomainScope: scope,
	}
}

var testScope = int64(42)

func runGuarded(h http.Handler, claims *auth.Claims) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/admin/audit", nil)
	if claims != nil {
		req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestRequirePermAudited_DomainScopedRefusedOnGlobalOnlySurface: audit.export
// (the audit CSV export / policy write grant) refuses a domain-scoped admin
// with an audited 403 before any handler work runs.
func TestRequirePermAudited_DomainScopedRefusedOnGlobalOnlySurface(t *testing.T) {
	spy := &auditSpy{}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("domain-scoped principal reached an org-wide-only surface")
	})
	h := RequirePermAudited(permissions.PermAuditExport, spy.capture)(next)

	rec := runGuarded(h, scopeClaims(&testScope, permissions.PermAuditExport))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d; want 403 for a scoped principal on audit.export", rec.Code)
	}
	if len(spy.events) != 1 {
		t.Fatalf("audited %d events; want exactly the refusal", len(spy.events))
	}
	if e := spy.events[0]; e.Detail == "" || !contains(e.Detail, "domain=42") || !contains(e.Detail, permissions.PermAuditExport) {
		t.Fatalf("refusal audit Detail = %q; want the permission and scope", e.Detail)
	}
}

// TestRequireAnyPermAudited_DomainScopedRefusedOnAuditRead: audit.read (the
// Logs console umbrella guard: admin audit log, auth log, threat views, IP
// rules, link-protect audit) refuses a domain-scoped admin — the sealed
// org-wide audit read/export surface.
func TestRequireAnyPermAudited_DomainScopedRefusedOnAuditRead(t *testing.T) {
	spy := &auditSpy{}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("domain-scoped principal reached the audit read surface")
	})
	h := RequireAnyPermAudited([]string{permissions.PermAuditRead}, spy.capture)(next)

	rec := runGuarded(h, scopeClaims(&testScope, permissions.PermAuditRead))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d; want 403 for a scoped principal on audit.read", rec.Code)
	}
	if len(spy.events) != 1 {
		t.Fatalf("audited %d events; want exactly the refusal", len(spy.events))
	}
}

// TestRequirePermAudited_GlobalAdminPassesGlobalOnlySurface: the same grant
// with NO domain scope passes unchanged — the contract narrows scoped tokens,
// never the global ones.
func TestRequirePermAudited_GlobalAdminPassesGlobalOnlySurface(t *testing.T) {
	spy := &auditSpy{}
	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reached = true })
	h := RequirePermAudited(permissions.PermAuditRead, spy.capture)(next)

	rec := runGuarded(h, scopeClaims(nil, permissions.PermAuditRead))

	if rec.Code != http.StatusOK || !reached {
		t.Fatalf("global admin refused audit.read (status %d, reached %v)", rec.Code, reached)
	}
	if len(spy.events) != 0 {
		t.Fatalf("global admin pass audited %d events; want 0", len(spy.events))
	}
}

// TestRequirePermAudited_DomainScopedServesDomainScopablePerm: a scoped
// admin holding a NON-classified permission passes — per-domain surfaces
// (DLP etc.) legitimately serve domain-scoped admins and scope themselves at
// the handler.
func TestRequirePermAudited_DomainScopedServesDomainScopablePerm(t *testing.T) {
	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reached = true })
	h := RequirePermAudited(permissions.PermMailSecurity, func(context.Context, AuditEvent) {})(next)

	rec := runGuarded(h, scopeClaims(&testScope, permissions.PermMailSecurity))

	if rec.Code != http.StatusOK || !reached {
		t.Fatalf("scoped admin refused mail.security (status %d, reached %v); per-domain surfaces must keep serving scoped admins", rec.Code, reached)
	}
}

// TestRequireAnyPermissionSetAudited_DomainScopedRefusedOnGlobalOnlyMember:
// the set guard refuses a scoped principal when the ACCEPTED set member is
// org-wide-only.
func TestRequireAnyPermissionSetAudited_DomainScopedRefusedOnGlobalOnlyMember(t *testing.T) {
	spy := &auditSpy{}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("scoped principal reached an org-wide-only surface through a set guard")
	})
	h := RequireAnyPermissionSetAudited(
		[][]string{{permissions.PermAuditExport}, {permissions.PermSystemUpgrade}},
		spy.capture,
	)(next)

	rec := runGuarded(h, scopeClaims(&testScope, permissions.PermAuditExport))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d; want 403", rec.Code)
	}
	if len(spy.events) != 1 {
		t.Fatalf("audited %d events; want exactly the refusal", len(spy.events))
	}
}

// TestDomainGlobalOnlyScopeClassification pins the classification itself so
// an accidental drop is caught: audit.read and audit.export must remain
// org-wide-only, and a per-domain-scopable permission must NOT be listed.
func TestDomainGlobalOnlyScopeClassification(t *testing.T) {
	if !IsDomainGlobalOnlyScope(permissions.PermAuditRead) {
		t.Fatal("audit.read must be domain-global-only (org-wide audit records and exports)")
	}
	if !IsDomainGlobalOnlyScope(permissions.PermAuditExport) {
		t.Fatal("audit.export must be domain-global-only (org-wide audit CSV export)")
	}
	for _, perm := range []string{permissions.PermMailSecurity, permissions.PermUsersRead, permissions.PermIdentityWrite} {
		if IsDomainGlobalOnlyScope(perm) {
			t.Fatalf("%s must NOT be domain-global-only; its surfaces scope by DomainScope at the handler", perm)
		}
	}
}
