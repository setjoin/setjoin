package middleware

import (
	"context"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/permissions"
)

// ── Test helpers ────────────────────────────────────────────────────────────

func makeClaims(uid int64, perms []string, scope *int64) *auth.Claims {
	// IsAdmin is set true here but no longer grants anything on its own: the legacy
	// is_admin bridge has been deleted, so authorization flows exclusively from the
	// Permissions slice. Tests that pass explicit perms exercise the real grant
	// path; tests passing nil perms now assert DENY.
	return &auth.Claims{
		UserID:      uid,
		Email:       "test@example.com",
		IsAdmin:     true,
		Permissions: perms,
		DomainScope: scope,
		Type:        jwtutil.TypeAccess,
	}
}

// ── DomainScopeFromContext ──────────────────────────────────────────────────

func TestDomainScopeFromContext_NoScope(t *testing.T) {
	ctx := context.Background()
	if v := DomainScopeFromContext(ctx); v != 0 {
		t.Errorf("expected 0 (global), got %d", v)
	}
}

func TestDomainScopeFromContext_WithScope(t *testing.T) {
	ctx := context.WithValue(context.Background(), ctxKeyDomainScope, int64(5))
	if v := DomainScopeFromContext(ctx); v != 5 {
		t.Errorf("expected 5, got %d", v)
	}
}

// ── HasPermission (Claims method) ───────────────────────────────────────────

func TestHasPermission_DirectMatch(t *testing.T) {
	claims := makeClaims(1, []string{"users.read", "users.write"}, nil)
	if !claims.HasPermission(permissions.PermUsersRead) {
		t.Error("expected to have users.read")
	}
	if claims.HasPermission(permissions.PermUsersDelete) {
		t.Error("expected NOT to have users.delete")
	}
}

func TestHasPermission_LegacyIsAdminDenied(t *testing.T) {
	// Bridge deleted: IsAdmin=true with no resolved permissions grants nothing.
	claims := makeClaims(1, nil, nil)
	if claims.HasPermission(permissions.PermSystemConfig) {
		t.Error("legacy IsAdmin=true with empty perms must NOT have any permission (bridge deleted)")
	}
	if claims.HasPermission(permissions.PermUsersRead) {
		t.Error("legacy IsAdmin=true with empty perms must NOT have any permission (bridge deleted)")
	}
}

func TestHasPermission_NonAdminNoPermissions(t *testing.T) {
	claims := makeClaims(1, nil, nil)
	claims.IsAdmin = false
	if claims.HasPermission(permissions.PermUsersRead) {
		t.Error("non-admin should not have any permissions")
	}
}
