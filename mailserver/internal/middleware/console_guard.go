// Package middleware — console_guard.go provides the server-side enforcement
// layer (S6 layer 2) for the four-console permission model defined in
// internal/admin/consoles.go.
//
// RequirePermAudited checks a single permission and audit-logs denials.
// RequireAnyPermAudited checks a set of permissions with OR semantics.
// RequireAnyPermissionSetAudited applies OR-between/AND-within set semantics.
//
// All three enforce the domain-scope contract (er5-s15): a permission
// classified in DomainGlobalOnlyScopes below — org-wide by design, no domain
// dimension to filter by (audit/auth-log/threat reads and exports) — is never
// served to a domain-scoped principal. The refusal is
// audited with the scope in the Detail, so a scoped token cannot read
// organization-wide records by holding the read permission alone; global
// admins (no DomainScope) pass unchanged, and per-domain surfaces (DLP, MDM,
// MAM, roles, identity, retention) keep their own handler-level scoping.
//
// Both apply the same authorization semantics: a pure set-membership test
// over the resolved permissions (the legacy IsAdmin=true / empty-permission
// bridge has been deleted, so such tokens are denied). The audit callback is
// injected so tests can use an in-memory spy without coupling to the
// database.
package middleware

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/permissions"
)

// ── Audit types ──────────────────────────────────────────────────────────────

// AuditEvent is the payload delivered to the audit callback on a console denial.
type AuditEvent struct {
	Actor  string // email from the JWT claims
	Action string // "console.denied"
	Target string // request URL path
	Detail string // the permission that was missing
}

// AuditFunc is the callback signature for writing audit events. Tests pass an
// in-memory spy; main.go passes a function that writes to admin_audit_log.
type AuditFunc func(context.Context, AuditEvent)

// ── Domain-scope contract ────────────────────────────────────────────────────

// DomainGlobalOnlyScopes classifies console permissions whose data plane is
// organization-wide BY DESIGN and can never be narrowed to a caller's domain:
// the audit/auth-log/threat surfaces are backed by org-wide tables
// (admin_audit_log carries no domain dimension — V001 baseline), so a
// domain-scoped admin admitted to them does not see "their" slice, they see
// every domain's records and the audit CSV export (sealed defect
// scoped-audit-readers-receive-organization-wide-audit-records-and-exports;
// domain-scoped admin mutations across org-wide surfaces —
// admin-worker-domain-scope-ignored).
//
// All three console guards below refuse any domain-scoped principal exercising
// a classified permission, audited, before any handler work runs: fail-closed,
// the only safe posture for un-narrowable org-wide data. Global admins
// (claims.DomainScope == nil) pass unchanged, and per-domain surfaces whose
// handlers DO scope by DomainScope (DLP, MDM, MAM, roles, identity,
// retention) are deliberately NOT classified — they legitimately serve
// domain-scoped admins. Adding a permission here is a security-posture
// decision: it must name data with no domain dimension to filter by.
//
// The map lives in middleware (not internal/admin) because the guards are the
// enforcement point; internal/admin imports this package, so the dependency
// points from the policy consumer to the enforcement site with no cycle.
var DomainGlobalOnlyScopes = map[string]struct{}{
	permissions.PermAuditRead:   {}, // audit log, auth log, threat views, IP rules, link-protect audit
	permissions.PermAuditExport: {}, // audit CSV export + audit policy writes (audit class, org-wide)
}

// IsDomainGlobalOnlyScope reports whether the given permission is classified
// as organization-wide-only (never served to a domain-scoped principal).
func IsDomainGlobalOnlyScope(perm string) bool {
	_, ok := DomainGlobalOnlyScopes[perm]
	return ok
}

// denyDomainScopedForGlobalOnly refuses a domain-scoped principal when the
// permission being exercised is classified DomainGlobalOnlyScopes. It returns
// true when the caller was denied (response written + audited); the scope
// value rides the audit Detail so the refusal is attributable.
func denyDomainScopedForGlobalOnly(w http.ResponseWriter, r *http.Request, claims *auth.Claims, perms []string, auditFn AuditFunc) bool {
	if claims.DomainScope == nil {
		return false // global admin: nothing to refuse
	}
	globalOnly := false
	for _, p := range perms {
		if IsDomainGlobalOnlyScope(p) {
			globalOnly = true
			break
		}
	}
	if !globalOnly {
		return false
	}
	auditFn(r.Context(), AuditEvent{
		Actor:  claims.Email,
		Action: "console.denied",
		Target: r.URL.Path,
		Detail: strings.Join(perms, "|") + " (domain-scoped principal; org-wide-only surface, domain=" + strconv.FormatInt(*claims.DomainScope, 10) + ")",
	})
	httputil.WriteProblemStatus(w, http.StatusForbidden, "Forbidden")
	return true
}

// ── RequirePermAudited ───────────────────────────────────────────────────────

// RequirePermAudited returns middleware that checks the caller holds the given
// permission and audit-logs any denial.
//
// The audit callback is only invoked on a genuine 403 caused by a missing
// permission; 401 (unauthenticated) is never audited.
func RequirePermAudited(perm string, auditFn AuditFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := auth.UserFromContext(r.Context())
			if claims == nil {
				httputil.WriteProblemStatus(w, http.StatusUnauthorized, "Unauthorized")
				return
			}

			if !claims.HasPermission(perm) {
				auditFn(r.Context(), AuditEvent{
					Actor:  claims.Email,
					Action: "console.denied",
					Target: r.URL.Path,
					Detail: perm,
				})
				httputil.WriteProblemStatus(w, http.StatusForbidden, "Forbidden")
				return
			}

			// Domain-scope contract: org-wide-only surfaces refuse scoped
			// principals (audited) before any handler work runs.
			if denyDomainScopedForGlobalOnly(w, r, claims, []string{perm}, auditFn) {
				return
			}

			// Propagate domain scope for handler-level filtering.
			if claims.DomainScope != nil {
				ctx := context.WithValue(r.Context(), ctxKeyDomainScope, *claims.DomainScope)
				r = r.WithContext(ctx)
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ── RequireAnyPermAudited ────────────────────────────────────────────────────

// RequireAnyPermAudited returns middleware that checks the caller holds at
// least one of the given permissions (OR semantics). If none are held, a 403
// is returned and the denial is audit-logged.
//
// An empty or nil scopes slice is treated as "no one may pass" — it returns
// 403 with an audit event whose Detail is the empty string.
func RequireAnyPermAudited(scopes []string, auditFn AuditFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := auth.UserFromContext(r.Context())
			if claims == nil {
				httputil.WriteProblemStatus(w, http.StatusUnauthorized, "Unauthorized")
				return
			}

			// Check each scope; if any passes, allow through.
			passed := false
			for _, s := range scopes {
				if claims.HasPermission(s) {
					passed = true
					break
				}
			}

			if !passed {
				// Build a detail string listing all required scopes for the audit log.
				detail := strings.Join(scopes, "|")
				auditFn(r.Context(), AuditEvent{
					Actor:  claims.Email,
					Action: "console.denied",
					Target: r.URL.Path,
					Detail: detail,
				})
				httputil.WriteProblemStatus(w, http.StatusForbidden, "Forbidden")
				return
			}

			// Domain-scope contract: org-wide-only surfaces refuse scoped
			// principals (audited) before any handler work runs.
			if denyDomainScopedForGlobalOnly(w, r, claims, scopes, auditFn) {
				return
			}

			// Propagate domain scope.
			if claims.DomainScope != nil {
				ctx := context.WithValue(r.Context(), ctxKeyDomainScope, *claims.DomainScope)
				r = r.WithContext(ctx)
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyPermissionSetAudited applies OR semantics between permission sets
// and AND semantics inside each set. It is used when one route serves multiple
// job kinds whose originating authorities differ, without weakening a
// two-permission authority into a simple any-of check.
//
// Example: {{audit.export}, {system.upgrade, identity.write}} accepts an
// auditor, or an identity-upgrade operator holding both upgrade permissions.
// Empty sets never grant access.
func RequireAnyPermissionSetAudited(
	permissionSets [][]string,
	auditFn AuditFunc,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := auth.UserFromContext(r.Context())
			if claims == nil {
				httputil.WriteProblemStatus(w, http.StatusUnauthorized, "Unauthorized")
				return
			}

			passed := false
			details := make([]string, 0, len(permissionSets))
			for _, permissionSet := range permissionSets {
				if len(permissionSet) == 0 {
					continue
				}
				all := true
				for _, permission := range permissionSet {
					if !claims.HasPermission(permission) {
						all = false
					}
				}
				details = append(details, strings.Join(permissionSet, "&"))
				if all {
					passed = true
				}
			}
			if !passed {
				auditFn(r.Context(), AuditEvent{
					Actor: claims.Email, Action: "console.denied",
					Target: r.URL.Path, Detail: strings.Join(details, "|"),
				})
				httputil.WriteProblemStatus(w, http.StatusForbidden, "Forbidden")
				return
			}

			// Domain-scope contract: org-wide-only surfaces refuse scoped
			// principals (audited) before any handler work runs.
			flat := make([]string, 0, len(permissionSets))
			for _, permissionSet := range permissionSets {
				flat = append(flat, permissionSet...)
			}
			if denyDomainScopedForGlobalOnly(w, r, claims, flat, auditFn) {
				return
			}

			if claims.DomainScope != nil {
				ctx := context.WithValue(r.Context(), ctxKeyDomainScope, *claims.DomainScope)
				r = r.WithContext(ctx)
			}
			next.ServeHTTP(w, r)
		})
	}
}
