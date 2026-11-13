package admin

// Final-wave changed-lines coverage for admin_roles.go ListRoles: the scoped
// read path (D-MAILSERVER-INTERNAL-ADMIN-F-008) — a domain-scoped viewer sees
// only roles whose domain_scope matches the grant (NULL-scope builtins and
// other domains excluded), while an unconfined caller sees the whole catalog.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/testsupport"
)

// TestRolesListScopedVisibility executes the ListRoles query for both scope
// postures against the real role catalog and asserts the domain predicate.
func TestRolesListScopedVisibility(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())
	domainID := rolesTestEnsureDomain(t, pool)

	roleName := "cov-roles-list-" + rolesTestRandomSuffix(t)
	var scopedRoleID int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO admin_role_groups (name, description, permissions, domain_scope, is_builtin)
		 VALUES ($1, 'cov scoped role', '{}'::text[], $2, FALSE) RETURNING id`,
		roleName, domainID).Scan(&scopedRoleID); err != nil {
		t.Fatalf("seed domain-scoped role: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM admin_role_groups WHERE id = $1`, scopedRoleID)
	})

	// Unconfined caller ($1 <= 0 arm): the full catalog, scoped role included.
	rec := httptest.NewRecorder()
	h.ListRoles(rec, httptest.NewRequest(http.MethodGet, "/admin/roles", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("unconfined ListRoles: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var all []roleResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &all); err != nil {
		t.Fatalf("decode unconfined list: %v", err)
	}
	sawScoped := false
	for _, ro := range all {
		if ro.ID == scopedRoleID {
			sawScoped = true
		}
	}
	if !sawScoped {
		t.Fatalf("unconfined list must contain the domain-scoped role %d (got %d roles)", scopedRoleID, len(all))
	}

	// Domain-scoped caller ($1 > 0 arm): only roles whose domain_scope matches
	// the grant — the scoped role yes, NULL-scope builtins and other domains no.
	req := httptest.NewRequest(http.MethodGet, "/admin/roles", nil)
	req = req.WithContext(middleware.ContextWithDomainScope(req.Context(), domainID))
	rec = httptest.NewRecorder()
	h.ListRoles(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("scoped ListRoles: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var scoped []roleResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &scoped); err != nil {
		t.Fatalf("decode scoped list: %v", err)
	}
	if len(scoped) == 0 {
		t.Fatal("scoped list must still contain the roles scoped to the caller's domain")
	}
	for _, ro := range scoped {
		if ro.DomainScope == nil || *ro.DomainScope != domainID {
			t.Fatalf("scoped list leaked role %d with domain_scope %v (grant %d)", ro.ID, ro.DomainScope, domainID)
		}
	}
}
