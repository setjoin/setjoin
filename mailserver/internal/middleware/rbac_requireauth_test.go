package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	sharedauth "setjoin.com/shared/auth"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/permissions"
)

// ── RBAC cut-over guard tests (Task 3) ───────────────────────────────────────
//
// These tests pin the post-swap behaviour: every admin route was changed from an
// enum-role wrapper (requireAdmin / requireSuperAdmin / requireReadOnly /
// requireAuditor / requireAdminOrAuditor → all RequireRole closures) to the
// authn-only requireAuth wrapper, leaving the granular inner RequirePermAudited
// gate as the sole authorization. They compose RequireAuth + the inner perm
// guard exactly the way main.go does after the swap, and assert:
//
//  1. A perm-holder with IsAdmin=false / no enum role reaches a formerly-
//     requireAdmin route (authn via RequireAuth, authz via the perm) → 200.
//  2. A security.write holder reaches the formerly-requireSuperAdmin threat
//     ip-rules route (the documented super-admin collapse) → 200.
//  3. DomainScope from the JWT is still attached to the handler context after
//     the swap (a domain-scoped admin still gets per-domain filtering).
//  4. Unauthenticated → 401 (RequireAuth challenges before the perm gate runs).
//  5. The /auth/admin/ catch-all now requires identity.write: a holder passes,
//     a non-holder 403s.

// fakeAuthenticator implements sharedauth.Authenticator. It returns the supplied
// claims, or an error to simulate an unauthenticated request.
type fakeAuthenticator struct {
	claims *jwtutil.Claims
	err    error
}

func (f fakeAuthenticator) Authenticate(_ context.Context, _ *http.Request) (*jwtutil.Claims, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.claims, nil
}

// Compile-time assertion that the fake satisfies the contract.
var _ sharedauth.Authenticator = fakeAuthenticator{}

// rbacChain composes the post-swap middleware stack the way main.go does:
// requireAuth(innerPerm(handler)). It returns the recorded status code and the
// domain scope observed inside the handler (-1 if the handler never ran).
func rbacChain(t *testing.T, authn sharedauth.Authenticator, inner func(http.Handler) http.Handler, req *http.Request) (int, int64) {
	t.Helper()
	observedScope := int64(-1)
	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observedScope = DomainScopeFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	// RequireAuth is the authn-only wrapper that replaced the role wrappers.
	handler := RequireAuth(authn, gateLogger())(inner(final))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Code, observedScope
}

func nullAudit(_ context.Context, _ AuditEvent) {}

// permClaims builds an access-type Claims with IsAdmin=false — authorization
// must flow purely from Permissions (the admin_role enum is gone).
func permClaims(uid int64, perms []string, scope *int64) *jwtutil.Claims {
	return &jwtutil.Claims{
		UserID:      uid,
		Email:       "perm-only@example.com",
		IsAdmin:     false,
		Permissions: perms,
		DomainScope: scope,
		Type:        jwtutil.TypeAccess,
	}
}

// (1) A non-admin perm-holder reaches a formerly-requireAdmin route.
func TestRBAC_PermHolderNoEnum_ReachesFormerlyRequireAdmin(t *testing.T) {
	authn := fakeAuthenticator{claims: permClaims(1, []string{permissions.PermUsersRead}, nil)}
	inner := RequirePermAudited(permissions.PermUsersRead, nullAudit)
	req := httptest.NewRequest("GET", "/admin/users", nil)

	code, _ := rbacChain(t, authn, inner, req)
	if code != http.StatusOK {
		t.Fatalf("perm-holder (IsAdmin=false, no role) on a formerly-requireAdmin route: expected 200, got %d", code)
	}
}

// (1b) Same route, a token WITHOUT the perm (and no enum) is denied — proves the
// inner perm is doing the authorizing now that the role wrapper is gone.
func TestRBAC_NonPermHolder_DeniedOnFormerlyRequireAdmin(t *testing.T) {
	authn := fakeAuthenticator{claims: permClaims(2, []string{permissions.PermQueueRead}, nil)}
	inner := RequirePermAudited(permissions.PermUsersRead, nullAudit)
	req := httptest.NewRequest("GET", "/admin/users", nil)

	code, _ := rbacChain(t, authn, inner, req)
	if code != http.StatusForbidden {
		t.Fatalf("token lacking the route perm: expected 403, got %d", code)
	}
}

// (2) security.write holder reaches the formerly-requireSuperAdmin threat
// ip-rules route — the documented super-admin collapse (Security Admin gains it).
func TestRBAC_SecurityWrite_ReachesFormerlySuperAdminThreatRoute(t *testing.T) {
	authn := fakeAuthenticator{claims: permClaims(3, []string{permissions.PermSecurityWrite}, nil)}
	inner := RequirePermAudited(permissions.PermSecurityWrite, nullAudit)
	req := httptest.NewRequest("POST", "/admin/threat/ip-rules", nil)

	code, _ := rbacChain(t, authn, inner, req)
	if code != http.StatusOK {
		t.Fatalf("security.write holder on the ex-requireSuperAdmin threat route: expected 200 (documented collapse), got %d", code)
	}
}

// (3) DomainScope from the JWT survives the swap and reaches the handler.
func TestRBAC_DomainScope_StillAttachedAfterSwap(t *testing.T) {
	scope := int64(7)
	authn := fakeAuthenticator{claims: permClaims(4, []string{permissions.PermUsersRead}, &scope)}
	inner := RequirePermAudited(permissions.PermUsersRead, nullAudit)
	req := httptest.NewRequest("GET", "/admin/users", nil)

	code, observed := rbacChain(t, authn, inner, req)
	if code != http.StatusOK {
		t.Fatalf("domain-scoped admin: expected 200, got %d", code)
	}
	if observed != 7 {
		t.Fatalf("domain scope lost after swap: expected 7 in handler context, got %d", observed)
	}
}

// (4) Unauthenticated → 401, before the perm gate runs.
func TestRBAC_Unauthenticated_Is401(t *testing.T) {
	authn := fakeAuthenticator{err: errors.New("no credentials")}
	inner := RequirePermAudited(permissions.PermUsersRead, nullAudit)
	req := httptest.NewRequest("GET", "/admin/users", nil)

	code, _ := rbacChain(t, authn, inner, req)
	if code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated request: expected 401, got %d", code)
	}
}

// (5) /auth/admin/ catch-all now requires identity.write (resolved blocker):
// a holder passes, a non-holder 403s.
func TestRBAC_AuthAdminProxy_RequiresIdentityWrite(t *testing.T) {
	inner := RequirePermAudited(permissions.PermIdentityWrite, nullAudit)

	// Holder → 200.
	holder := fakeAuthenticator{claims: permClaims(5, []string{permissions.PermIdentityWrite}, nil)}
	req := httptest.NewRequest("POST", "/auth/admin/methods/saml", nil)
	if code, _ := rbacChain(t, holder, inner, req); code != http.StatusOK {
		t.Fatalf("/auth/admin/ with identity.write: expected 200, got %d", code)
	}

	// Non-holder (some unrelated perm, no enum) → 403.
	nonHolder := fakeAuthenticator{claims: permClaims(6, []string{permissions.PermQueueRead}, nil)}
	req2 := httptest.NewRequest("POST", "/auth/admin/methods/saml", nil)
	if code, _ := rbacChain(t, nonHolder, inner, req2); code != http.StatusForbidden {
		t.Fatalf("/auth/admin/ without identity.write: expected 403, got %d", code)
	}
}
