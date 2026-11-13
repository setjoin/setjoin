package admin

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/toggle"
)

// rolesTestRandomSuffix returns a short random hex string for unique names.
func rolesTestRandomSuffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return fmt.Sprintf("%x", b)
}

// rolesTestEnsureDomain creates (or finds) a test domain for roles tests.
func rolesTestEnsureDomain(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	ctx := context.Background()
	var id int64
	err := pool.QueryRow(ctx,
		`INSERT INTO domains (name) VALUES ('rolestest.example')
		 ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
		 RETURNING id`,
	).Scan(&id)
	if err != nil {
		t.Fatalf("rolesTestEnsureDomain: %v", err)
	}
	return id
}

// rolesTestSeedUserWithRole inserts a user + assigns it to the named built-in
// role group. Returns the user ID. Cleanup removes the assignment and user.
func rolesTestSeedUserWithRole(t *testing.T, pool *pgxpool.Pool, roleName string) int64 {
	t.Helper()
	ctx := context.Background()
	domainID := rolesTestEnsureDomain(t, pool)
	suffix := rolesTestRandomSuffix(t)
	email := "rolestest-" + suffix + "@rolestest.example"

	var userID int64
	err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, password_hash, domain_id)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		"rolestest-"+suffix, email, "Roles Test", "$2a$10$placeholder", domainID,
	).Scan(&userID)
	if err != nil {
		t.Fatalf("rolesTestSeedUserWithRole INSERT users: %v", err)
	}

	// Look up the built-in group id by name.
	var groupID int64
	err = pool.QueryRow(ctx,
		`SELECT id FROM admin_role_groups WHERE name = $1`, roleName,
	).Scan(&groupID)
	if err != nil {
		t.Fatalf("rolesTestSeedUserWithRole lookup role %q: %v", roleName, err)
	}

	// Assign user to the role group. granted_by references the user themselves
	// (self-grant) — valid for test fixtures since the FK requires a real users row.
	_, err = pool.Exec(ctx,
		`INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by)
		 VALUES ($1, $2, $1)
		 ON CONFLICT (user_id, role_group_id) DO NOTHING`,
		userID, groupID,
	)
	if err != nil {
		t.Fatalf("rolesTestSeedUserWithRole INSERT admin_role_assignments: %v", err)
	}

	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `
			UPDATE admin_role_assignments
			   SET expires_at = statement_timestamp() - interval '1 second'
			 WHERE user_id = $1 AND role_group_id = 1`, userID)
		_, _ = pool.Exec(c, `DELETE FROM admin_role_assignments WHERE user_id = $1`, userID)
		_, _ = pool.Exec(c, `DELETE FROM users WHERE id = $1`, userID)
	})
	return userID
}

// rolesTestHasAll returns true if all wanted permissions appear in got.
func rolesTestHasAll(got []string, wanted ...string) bool {
	set := make(map[string]struct{}, len(got))
	for _, g := range got {
		set[g] = struct{}{}
	}
	for _, w := range wanted {
		if _, ok := set[w]; !ok {
			return false
		}
	}
	return true
}

// builtinRoleID returns the id of a built-in role group by name, failing the test if not found.
func builtinRoleID(t *testing.T, pool *pgxpool.Pool, roleName string) int64 {
	t.Helper()
	var id int64
	err := pool.QueryRow(context.Background(),
		`SELECT id FROM admin_role_groups WHERE name = $1`, roleName).Scan(&id)
	if err != nil {
		t.Fatalf("builtinRoleID(%q): %v", roleName, err)
	}
	return id
}

// seedUser inserts a bare user (no role) and returns its ID. Cleanup removes it.
func seedUser(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	ctx := context.Background()
	domainID := rolesTestEnsureDomain(t, pool)
	suffix := rolesTestRandomSuffix(t)
	email := "seeduser-" + suffix + "@rolestest.example"
	var id int64
	err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, password_hash, domain_id)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		"seeduser-"+suffix, email, "Seed User", "$2a$10$placeholder", domainID,
	).Scan(&id)
	if err != nil {
		t.Fatalf("seedUser INSERT: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `
			UPDATE admin_role_assignments
			   SET expires_at = statement_timestamp() - interval '1 second'
			 WHERE user_id = $1 AND role_group_id = 1`, id)
		_, _ = pool.Exec(c, `DELETE FROM admin_role_assignments WHERE user_id = $1`, id)
		_, _ = pool.Exec(c, `DELETE FROM users WHERE id = $1`, id)
	})
	return id
}

// seedSuperAdmin seeds a bare user AND grants it the built-in Super Admin role
// (role_group_id=1) via a governed admin_role_assignments row, returning its ID.
// This gives the actor REAL DB authority so admin_is_super() short-circuits the
// domination check in admin_protection_check — the actor dominates any target.
// Use this for the actor in tests whose real assertion is downstream of the
// protection gate (SoD 201/409, RemoveMember 204), where the actor's authority
// is incidental to what the test verifies. Cleanup (via seedUser) removes the
// assignment + user.
func seedSuperAdmin(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	id := seedUser(t, pool)
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by)
		 VALUES ($1, 1, $1) ON CONFLICT (user_id, role_group_id) DO NOTHING`, id); err != nil {
		t.Fatalf("seedSuperAdmin assign role 1: %v", err)
	}
	return id
}

// TestAssignMemberWritesAudit verifies that AssignMember emits a role_assign audit row.
func TestAssignMemberWritesAudit(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())
	roleID := builtinRoleID(t, pool, "Help Desk")
	// Super Admin DB assignment gives is_unconfined=TRUE so admin_scope_within passes.
	// (admin_scope_within now requires a real null-scope assignment, not just JWT claims.)
	actorID := seedSuperAdmin(t, pool)
	// Seed the target user to be assigned.
	uid := seedUser(t, pool)

	body := `{"userId":` + strconv.FormatInt(uid, 10) + `}`
	req := httptest.NewRequest("POST", "/admin/roles/"+strconv.FormatInt(roleID, 10)+"/members", strings.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(roleID, 10))
	// Super-admin actor (explicit AllPermissions) so the P2 grant-only-what-you-hold
	// rule passes; this test asserts audit emission.
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: actorID, Email: "admin@x.com", IsAdmin: true, Permissions: permissions.AllPermissions}))
	w := httptest.NewRecorder()
	h.AssignMember(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("got %d, want 201: body=%s", w.Code, w.Body.String())
	}
	var n int
	pool.QueryRow(context.Background(),
		`SELECT count(*) FROM admin_audit_log WHERE action='role_assign' AND user_id=$1 AND target_type='role_assignment'`,
		actorID).Scan(&n)
	if n == 0 {
		t.Error("expected a role_assign audit row")
	}
}

// TestEffectivePermissionsShape verifies GET /admin/users/{id}/effective-permissions
// returns the expected JSON shape with the user's resolved permissions and sources.
func TestEffectivePermissionsShape(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())

	// Seed: a user assigned to Audit Reader (audit.read, reports.read), global.
	uid := rolesTestSeedUserWithRole(t, pool, "Audit Reader")

	req := httptest.NewRequest("GET", "/admin/users/"+strconv.FormatInt(uid, 10)+"/effective-permissions", nil)
	req.SetPathValue("id", strconv.FormatInt(uid, 10))
	w := httptest.NewRecorder()
	h.EffectivePermissions(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200: body=%s", w.Code, w.Body.String())
	}
	var out effectivePermsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !rolesTestHasAll(out.Permissions, "audit.read", "reports.read") {
		t.Errorf("expected audit.read+reports.read, got %v", out.Permissions)
	}
	if len(out.Sources) != 1 || out.Sources[0].RoleName != "Audit Reader" {
		t.Errorf("expected one source 'Audit Reader', got %+v", out.Sources)
	}
}

// TestEffectivePermissions_OutOfScopeReturns404 verifies that a domain-scoped
// admin cannot inspect a user in a different domain — the handler returns 404
// (indistinguishable from missing), not a data leak.
func TestEffectivePermissions_OutOfScopeReturns404(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())

	// Seed two separate domains.
	domA := ensureScopeTestDomain(t, pool, "roles-scopea.example")
	domB := ensureScopeTestDomain(t, pool, "roles-scopeb.example")

	// Seed a user in domain B (the target).
	userB := createScopeTestUser(t, pool, domB, "roles-scopeb.example")

	// Actor is scoped to domain A — it must not see domain-B users.
	actorID := createScopeTestUser(t, pool, domA, "roles-scopea.example")
	req := httptest.NewRequest("GET", "/admin/users/"+strconv.FormatInt(userB, 10)+"/effective-permissions", nil)
	req.SetPathValue("id", strconv.FormatInt(userB, 10))
	ctx := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: actorID, IsAdmin: true, Permissions: permissions.AllPermissions})
	ctx = middleware.ContextWithDomainScope(ctx, domA)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	h.EffectivePermissions(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-domain EffectivePermissions: want 404, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// rolesTestCreateRole creates a non-built-in role group and returns its id.
// Cleanup removes it (assignments cascade).
func rolesTestCreateRole(t *testing.T, pool *pgxpool.Pool, name string) int64 {
	t.Helper()
	ctx := context.Background()
	var id int64
	err := pool.QueryRow(ctx,
		`INSERT INTO admin_role_groups (name, description, permissions, is_builtin)
		 VALUES ($1, $2, $3::text[], FALSE) RETURNING id`,
		name, "test role "+name, []string{"audit.read"},
	).Scan(&id)
	if err != nil {
		t.Fatalf("rolesTestCreateRole(%q): %v", name, err)
	}
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM admin_role_assignments WHERE role_group_id = $1`, id)
		pool.Exec(c, `DELETE FROM admin_role_groups WHERE id = $1`, id)
	})
	return id
}

// TestCreateRoleWritesAudit verifies that CreateRole emits a role_create audit row.
func TestCreateRoleWritesAudit(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())
	actorID := seedUser(t, pool)

	suffix := rolesTestRandomSuffix(t)
	body := `{"name":"audit-test-` + suffix + `","permissions":["audit.read"]}`
	req := httptest.NewRequest("POST", "/admin/roles", strings.NewReader(body))
	// Super-admin actor (explicit AllPermissions) so the P2 grant-only-what-you-hold
	// rule passes; this test asserts audit emission.
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: actorID, Email: "admin@x.com", IsAdmin: true, Permissions: permissions.AllPermissions}))
	w := httptest.NewRecorder()
	h.CreateRole(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("CreateRole: got %d, want 201: body=%s", w.Code, w.Body.String())
	}

	// Clean up the created role.
	var createdID int64
	_ = json.Unmarshal(w.Body.Bytes(), &map[string]int64{"id": createdID})
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM admin_role_groups WHERE name = $1`, "audit-test-"+suffix)
	})

	var n int
	pool.QueryRow(context.Background(),
		`SELECT count(*) FROM admin_audit_log WHERE action='role_create' AND user_id=$1 AND target_type='role_group'`,
		actorID).Scan(&n)
	if n == 0 {
		t.Error("expected a role_create audit row")
	}
}

// TestUpdateRoleWritesAudit verifies that UpdateRole emits a role_update audit row.
func TestUpdateRoleWritesAudit(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())
	actorID := seedUser(t, pool)

	suffix := rolesTestRandomSuffix(t)
	roleID := rolesTestCreateRole(t, pool, "upd-test-"+suffix)

	newDesc := "updated description"
	body := `{"description":"` + newDesc + `"}`
	req := httptest.NewRequest("PATCH", "/admin/roles/"+strconv.FormatInt(roleID, 10), strings.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(roleID, 10))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: actorID, Email: "admin@x.com"}))
	w := httptest.NewRecorder()
	h.UpdateRole(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("UpdateRole: got %d, want 204: body=%s", w.Code, w.Body.String())
	}
	var n int
	pool.QueryRow(context.Background(),
		`SELECT count(*) FROM admin_audit_log WHERE action='role_update' AND user_id=$1 AND target_type='role_group' AND target_id=$2`,
		actorID, roleID).Scan(&n)
	if n == 0 {
		t.Error("expected a role_update audit row")
	}
}

// TestDeleteRoleWritesAudit verifies that DeleteRole emits a role_delete audit row.
func TestDeleteRoleWritesAudit(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())
	actorID := seedUser(t, pool)

	suffix := rolesTestRandomSuffix(t)
	// Insert the role directly (not via rolesTestCreateRole, since we need to delete it in the handler).
	ctx := context.Background()
	var roleID int64
	err := pool.QueryRow(ctx,
		`INSERT INTO admin_role_groups (name, description, permissions, is_builtin)
		 VALUES ($1, $2, $3::text[], FALSE) RETURNING id`,
		"del-test-"+suffix, "delete test", []string{"audit.read"},
	).Scan(&roleID)
	if err != nil {
		t.Fatalf("seed role: %v", err)
	}
	// No t.Cleanup needed — the handler will delete it. If handler fails, leak is acceptable in test.

	req := httptest.NewRequest("DELETE", "/admin/roles/"+strconv.FormatInt(roleID, 10), nil)
	req.SetPathValue("id", strconv.FormatInt(roleID, 10))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: actorID, Email: "admin@x.com"}))
	w := httptest.NewRecorder()
	h.DeleteRole(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("DeleteRole: got %d, want 204: body=%s", w.Code, w.Body.String())
	}
	var n int
	pool.QueryRow(context.Background(),
		`SELECT count(*) FROM admin_audit_log WHERE action='role_delete' AND user_id=$1 AND target_type='role_group' AND target_id=$2`,
		actorID, roleID).Scan(&n)
	if n == 0 {
		t.Error("expected a role_delete audit row")
	}
}

// TestRemoveMemberWritesAudit verifies that RemoveMember emits a role_revoke audit row.
func TestRemoveMemberWritesAudit(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())

	roleID := builtinRoleID(t, pool, "Help Desk")
	// Actor needs REAL DB authority dominating the target: admin_protection_check
	// derives authority from admin_effective_authority(actor), not from JWT claims.
	// Super Admin (role 1) short-circuits domination via admin_is_super().
	actorID := seedSuperAdmin(t, pool)
	targetUID := seedUser(t, pool)

	// Seed the assignment directly so RemoveMember has something to delete.
	ctx := context.Background()
	_, err := pool.Exec(ctx,
		`INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (user_id, role_group_id) DO NOTHING`,
		targetUID, roleID, actorID,
	)
	if err != nil {
		t.Fatalf("seed assignment: %v", err)
	}

	req := httptest.NewRequest("DELETE",
		"/admin/roles/"+strconv.FormatInt(roleID, 10)+"/members/"+strconv.FormatInt(targetUID, 10), nil)
	req.SetPathValue("id", strconv.FormatInt(roleID, 10))
	req.SetPathValue("userId", strconv.FormatInt(targetUID, 10))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: actorID, Email: "admin@x.com"}))
	w := httptest.NewRecorder()
	h.RemoveMember(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("RemoveMember: got %d, want 204: body=%s", w.Code, w.Body.String())
	}
	var n int
	pool.QueryRow(context.Background(),
		`SELECT count(*) FROM admin_audit_log WHERE action='role_revoke' AND user_id=$1 AND target_type='role_assignment'`,
		actorID).Scan(&n)
	if n == 0 {
		t.Error("expected a role_revoke audit row")
	}
}

// ── P2: grant-only-what-you-hold + mutation-scope-confinement ───────────────
//
// These exercise the privilege-escalation / scope-escape backstop on the
// mutating /admin/roles* endpoints (spec §9 P2). Helpers: a scoped admin's
// permissions are set via auth.Claims.Permissions, scope via
// middleware.ContextWithDomainScope.

// rolesP2CtxWithActor builds a request context carrying an actor with the given
// permission set, IsAdmin flag, and domain scope (0 = unscoped/global).
func rolesP2CtxWithActor(ctx context.Context, actorID int64, perms []string, isAdmin bool, scope int64) context.Context {
	ctx = auth.ContextWithUser(ctx, &auth.Claims{UserID: actorID, IsAdmin: isAdmin, Permissions: perms})
	if scope > 0 {
		ctx = middleware.ContextWithDomainScope(ctx, scope)
	}
	return ctx
}

// rolesP2CreateRoleReq builds a CreateRole POST request with the given body.
func rolesP2CreateRoleReq(body string) *http.Request {
	return httptest.NewRequest("POST", "/admin/roles", strings.NewReader(body))
}

// 1a. CreateRole grant-only: actor lacking a requested perm → 403.
func TestP2_CreateRole_GrantOnly_MissingPerm403(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())
	actorID := seedUser(t, pool)
	suffix := rolesTestRandomSuffix(t)
	name := "p2-grantonly-" + suffix

	// Actor holds only audit.read but tries to grant users.delete too.
	body := `{"name":"` + name + `","permissions":["audit.read","users.delete"]}`
	req := rolesP2CreateRoleReq(body)
	req = req.WithContext(rolesP2CtxWithActor(req.Context(), actorID, []string{"audit.read"}, false, 0))
	w := httptest.NewRecorder()
	h.CreateRole(w, req)

	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM admin_role_groups WHERE name = $1`, name) })
	if w.Code != http.StatusForbidden {
		t.Fatalf("CreateRole grant-only: want 403, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// 1b. CreateRole grant-only: actor holding all requested perms → 201.
func TestP2_CreateRole_GrantOnly_HoldsAll201(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())
	actorID := seedUser(t, pool)
	suffix := rolesTestRandomSuffix(t)
	name := "p2-grantall-" + suffix

	body := `{"name":"` + name + `","permissions":["audit.read","reports.read"]}`
	req := rolesP2CreateRoleReq(body)
	req = req.WithContext(rolesP2CtxWithActor(req.Context(), actorID, []string{"audit.read", "reports.read"}, false, 0))
	w := httptest.NewRecorder()
	h.CreateRole(w, req)

	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM admin_role_groups WHERE name = $1`, name) })
	if w.Code != http.StatusCreated {
		t.Fatalf("CreateRole holds-all: want 201, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// 2a. AssignMember grant-only: actor not holding all of the role's perms → 403.
func TestP2_AssignMember_GrantOnly_MissingPerm403(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())
	actorID := seedUser(t, pool)
	targetUID := seedUser(t, pool)

	// Create a role granting a sensitive perm the actor does NOT hold.
	suffix := rolesTestRandomSuffix(t)
	roleName := "p2-assign-powerful-" + suffix
	var roleID int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO admin_role_groups (name, description, permissions, is_builtin)
		 VALUES ($1, 'powerful', $2::text[], FALSE) RETURNING id`,
		roleName, []string{"users.delete"}).Scan(&roleID); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM admin_role_assignments WHERE role_group_id = $1`, roleID)
		pool.Exec(c, `DELETE FROM admin_role_groups WHERE id = $1`, roleID)
	})

	body := `{"userId":` + strconv.FormatInt(targetUID, 10) + `}`
	req := httptest.NewRequest("POST", "/admin/roles/"+strconv.FormatInt(roleID, 10)+"/members", strings.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(roleID, 10))
	// Actor holds only roles.manage (+audit.read), not users.delete.
	req = req.WithContext(rolesP2CtxWithActor(req.Context(), actorID, []string{"roles.manage", "audit.read"}, false, 0))
	w := httptest.NewRecorder()
	h.AssignMember(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("AssignMember grant-only: want 403, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// 2b. AssignMember grant-only: actor holding all of the role's perms → 201.
func TestP2_AssignMember_GrantOnly_HoldsAll201(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())
	// Super Admin DB assignment → is_unconfined=TRUE so admin_scope_within passes
	// for the global (null-scope) grant. JWT claims below are intentionally limited.
	actorID := seedSuperAdmin(t, pool)
	targetUID := seedUser(t, pool)
	roleID := builtinRoleID(t, pool, "Audit Reader") // audit.read + reports.read

	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM admin_role_assignments WHERE user_id = $1`, targetUID)
	})

	body := `{"userId":` + strconv.FormatInt(targetUID, 10) + `}`
	req := httptest.NewRequest("POST", "/admin/roles/"+strconv.FormatInt(roleID, 10)+"/members", strings.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(roleID, 10))
	req = req.WithContext(rolesP2CtxWithActor(req.Context(), actorID, []string{"audit.read", "reports.read"}, false, 0))
	w := httptest.NewRecorder()
	h.AssignMember(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("AssignMember holds-all: want 201, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// 3. CreateRole scope-confinement.
func TestP2_CreateRole_ScopeConfinement(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())
	actorID := seedUser(t, pool)
	domA := ensureScopeTestDomain(t, pool, "roles-p2-create-a.example")
	domB := ensureScopeTestDomain(t, pool, "roles-p2-create-b.example")
	actorPerms := []string{"audit.read"}

	// 3a. scoped actor creating a global (nil domainScope) role → 403.
	suffix := rolesTestRandomSuffix(t)
	nameGlobal := "p2-scope-global-" + suffix
	reqG := rolesP2CreateRoleReq(`{"name":"` + nameGlobal + `","permissions":["audit.read"]}`)
	reqG = reqG.WithContext(rolesP2CtxWithActor(reqG.Context(), actorID, actorPerms, false, domA))
	wG := httptest.NewRecorder()
	h.CreateRole(wG, reqG)
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM admin_role_groups WHERE name = $1`, nameGlobal) })
	if wG.Code != http.StatusForbidden {
		t.Fatalf("CreateRole scoped→global: want 403, got %d (body=%s)", wG.Code, wG.Body.String())
	}

	// 3b. scoped actor creating a role scoped to THEIR domain → 201.
	nameMine := "p2-scope-mine-" + suffix
	reqM := rolesP2CreateRoleReq(`{"name":"` + nameMine + `","permissions":["audit.read"],"domainScope":` + strconv.FormatInt(domA, 10) + `}`)
	reqM = reqM.WithContext(rolesP2CtxWithActor(reqM.Context(), actorID, actorPerms, false, domA))
	wM := httptest.NewRecorder()
	h.CreateRole(wM, reqM)
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM admin_role_groups WHERE name = $1`, nameMine) })
	if wM.Code != http.StatusCreated {
		t.Fatalf("CreateRole scoped→own-domain: want 201, got %d (body=%s)", wM.Code, wM.Body.String())
	}

	// 3c. scoped actor creating a role scoped to ANOTHER domain → 403.
	nameOther := "p2-scope-other-" + suffix
	reqO := rolesP2CreateRoleReq(`{"name":"` + nameOther + `","permissions":["audit.read"],"domainScope":` + strconv.FormatInt(domB, 10) + `}`)
	reqO = reqO.WithContext(rolesP2CtxWithActor(reqO.Context(), actorID, actorPerms, false, domA))
	wO := httptest.NewRecorder()
	h.CreateRole(wO, reqO)
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM admin_role_groups WHERE name = $1`, nameOther) })
	if wO.Code != http.StatusForbidden {
		t.Fatalf("CreateRole scoped→other-domain: want 403, got %d (body=%s)", wO.Code, wO.Body.String())
	}
}

// 4. AssignMember scope-confinement.
func TestP2_AssignMember_ScopeConfinement(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())
	// Super Admin DB assignment → is_unconfined=TRUE; domain confinement is still
	// enforced by the middleware DomainScope context injected below, not DB scope.
	actorID := seedSuperAdmin(t, pool)
	domA := ensureScopeTestDomain(t, pool, "roles-p2-assign-a.example")
	domB := ensureScopeTestDomain(t, pool, "roles-p2-assign-b.example")
	userA := createScopeTestUser(t, pool, domA, "roles-p2-assign-a.example")
	userB := createScopeTestUser(t, pool, domB, "roles-p2-assign-b.example")

	// Role scoped to domain A granting audit.read (actor holds audit.read).
	suffix := rolesTestRandomSuffix(t)
	roleName := "p2-assign-role-a-" + suffix
	var roleID int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO admin_role_groups (name, description, permissions, domain_scope, is_builtin)
		 VALUES ($1, 'scoped A', $2::text[], $3, FALSE) RETURNING id`,
		roleName, []string{"audit.read"}, domA).Scan(&roleID); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM admin_role_assignments WHERE role_group_id = $1`, roleID)
		pool.Exec(c, `DELETE FROM admin_role_groups WHERE id = $1`, roleID)
	})
	actorPerms := []string{"audit.read", "roles.manage"}

	// 4a. target user in another domain (B) → 404.
	bodyB := `{"userId":` + strconv.FormatInt(userB, 10) + `}`
	reqB := httptest.NewRequest("POST", "/admin/roles/"+strconv.FormatInt(roleID, 10)+"/members", strings.NewReader(bodyB))
	reqB.SetPathValue("id", strconv.FormatInt(roleID, 10))
	reqB = reqB.WithContext(rolesP2CtxWithActor(reqB.Context(), actorID, actorPerms, false, domA))
	wB := httptest.NewRecorder()
	h.AssignMember(wB, reqB)
	if wB.Code != http.StatusNotFound {
		t.Fatalf("AssignMember out-of-scope target: want 404, got %d (body=%s)", wB.Code, wB.Body.String())
	}

	// 4b. in-scope target (A) → 201.
	bodyA := `{"userId":` + strconv.FormatInt(userA, 10) + `}`
	reqA := httptest.NewRequest("POST", "/admin/roles/"+strconv.FormatInt(roleID, 10)+"/members", strings.NewReader(bodyA))
	reqA.SetPathValue("id", strconv.FormatInt(roleID, 10))
	reqA = reqA.WithContext(rolesP2CtxWithActor(reqA.Context(), actorID, actorPerms, false, domA))
	wA := httptest.NewRecorder()
	h.AssignMember(wA, reqA)
	if wA.Code != http.StatusCreated {
		t.Fatalf("AssignMember in-scope target: want 201, got %d (body=%s)", wA.Code, wA.Body.String())
	}

	// 4c. domainOverride to another domain → 403.
	bodyOverride := `{"userId":` + strconv.FormatInt(userA, 10) + `,"domainOverride":` + strconv.FormatInt(domB, 10) + `}`
	reqOv := httptest.NewRequest("POST", "/admin/roles/"+strconv.FormatInt(roleID, 10)+"/members", strings.NewReader(bodyOverride))
	reqOv.SetPathValue("id", strconv.FormatInt(roleID, 10))
	reqOv = reqOv.WithContext(rolesP2CtxWithActor(reqOv.Context(), actorID, actorPerms, false, domA))
	wOv := httptest.NewRecorder()
	h.AssignMember(wOv, reqOv)
	if wOv.Code != http.StatusForbidden {
		t.Fatalf("AssignMember override-to-other-domain: want 403, got %d (body=%s)", wOv.Code, wOv.Body.String())
	}
}

// 4d. AssignMember scope: a scoped admin cannot assign a GLOBAL-scope role
// (its effective scope is global, not theirs). Safe-deny.
func TestP2_AssignMember_ScopedCannotAssignGlobalRole(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())
	actorID := seedUser(t, pool)
	domA := ensureScopeTestDomain(t, pool, "roles-p2-glob-a.example")
	userA := createScopeTestUser(t, pool, domA, "roles-p2-glob-a.example")
	roleID := builtinRoleID(t, pool, "Audit Reader") // global (domain_scope NULL)

	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM admin_role_assignments WHERE user_id = $1`, userA)
	})

	body := `{"userId":` + strconv.FormatInt(userA, 10) + `}`
	req := httptest.NewRequest("POST", "/admin/roles/"+strconv.FormatInt(roleID, 10)+"/members", strings.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(roleID, 10))
	req = req.WithContext(rolesP2CtxWithActor(req.Context(), actorID, []string{"audit.read", "reports.read", "roles.manage"}, false, domA))
	w := httptest.NewRecorder()
	h.AssignMember(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("AssignMember scoped→global-role: want 403, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// 5a. DeleteRole scope: acting on a global/out-of-scope role → 404.
func TestP2_DeleteRole_ScopeConfinement404(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())
	actorID := seedUser(t, pool)
	domA := ensureScopeTestDomain(t, pool, "roles-p2-del-a.example")
	domB := ensureScopeTestDomain(t, pool, "roles-p2-del-b.example")

	// Role scoped to domain B; a domain-A admin must not see/delete it.
	suffix := rolesTestRandomSuffix(t)
	var roleID int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO admin_role_groups (name, description, permissions, domain_scope, is_builtin)
		 VALUES ($1, 'scoped B', $2::text[], $3, FALSE) RETURNING id`,
		"p2-del-roleb-"+suffix, []string{"audit.read"}, domB).Scan(&roleID); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM admin_role_groups WHERE id = $1`, roleID) })

	req := httptest.NewRequest("DELETE", "/admin/roles/"+strconv.FormatInt(roleID, 10), nil)
	req.SetPathValue("id", strconv.FormatInt(roleID, 10))
	req = req.WithContext(rolesP2CtxWithActor(req.Context(), actorID, []string{"audit.read"}, false, domA))
	w := httptest.NewRecorder()
	h.DeleteRole(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("DeleteRole out-of-scope: want 404, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// 5b. UpdateRole scope: editing a global/out-of-scope role → 404.
func TestP2_UpdateRole_ScopeConfinement404(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())
	actorID := seedUser(t, pool)
	domA := ensureScopeTestDomain(t, pool, "roles-p2-upd-a.example")
	domB := ensureScopeTestDomain(t, pool, "roles-p2-upd-b.example")

	suffix := rolesTestRandomSuffix(t)
	var roleID int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO admin_role_groups (name, description, permissions, domain_scope, is_builtin)
		 VALUES ($1, 'scoped B', $2::text[], $3, FALSE) RETURNING id`,
		"p2-upd-roleb-"+suffix, []string{"audit.read"}, domB).Scan(&roleID); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM admin_role_groups WHERE id = $1`, roleID) })

	body := `{"description":"hijack"}`
	req := httptest.NewRequest("PATCH", "/admin/roles/"+strconv.FormatInt(roleID, 10), strings.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(roleID, 10))
	req = req.WithContext(rolesP2CtxWithActor(req.Context(), actorID, []string{"audit.read"}, false, domA))
	w := httptest.NewRecorder()
	h.UpdateRole(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("UpdateRole out-of-scope: want 404, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// 5c. UpdateRole scope: editing an in-scope role with a domainScope to another
// domain → 403.
func TestP2_UpdateRole_RescopeToOtherDomain403(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())
	actorID := seedUser(t, pool)
	domA := ensureScopeTestDomain(t, pool, "roles-p2-upd2-a.example")
	domB := ensureScopeTestDomain(t, pool, "roles-p2-upd2-b.example")

	suffix := rolesTestRandomSuffix(t)
	var roleID int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO admin_role_groups (name, description, permissions, domain_scope, is_builtin)
		 VALUES ($1, 'scoped A', $2::text[], $3, FALSE) RETURNING id`,
		"p2-upd2-rolea-"+suffix, []string{"audit.read"}, domA).Scan(&roleID); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM admin_role_groups WHERE id = $1`, roleID) })

	body := `{"domainScope":` + strconv.FormatInt(domB, 10) + `}`
	req := httptest.NewRequest("PATCH", "/admin/roles/"+strconv.FormatInt(roleID, 10), strings.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(roleID, 10))
	req = req.WithContext(rolesP2CtxWithActor(req.Context(), actorID, []string{"audit.read"}, false, domA))
	w := httptest.NewRecorder()
	h.UpdateRole(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("UpdateRole rescope-to-other-domain: want 403, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// 5d. RemoveMember scope: target user in another domain → 404.
func TestP2_RemoveMember_ScopeConfinement404(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())
	actorID := seedUser(t, pool)
	domA := ensureScopeTestDomain(t, pool, "roles-p2-rm-a.example")
	domB := ensureScopeTestDomain(t, pool, "roles-p2-rm-b.example")
	userB := createScopeTestUser(t, pool, domB, "roles-p2-rm-b.example")
	roleID := builtinRoleID(t, pool, "Help Desk")

	// Seed an assignment for the domain-B user so RemoveMember could find it
	// were it not for the scope guard.
	_, err := pool.Exec(context.Background(),
		`INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by)
		 VALUES ($1, $2, $1) ON CONFLICT (user_id, role_group_id) DO NOTHING`, userB, roleID)
	if err != nil {
		t.Fatalf("seed assignment: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM admin_role_assignments WHERE user_id = $1`, userB)
	})

	req := httptest.NewRequest("DELETE",
		"/admin/roles/"+strconv.FormatInt(roleID, 10)+"/members/"+strconv.FormatInt(userB, 10), nil)
	req.SetPathValue("id", strconv.FormatInt(roleID, 10))
	req.SetPathValue("userId", strconv.FormatInt(userB, 10))
	req = req.WithContext(rolesP2CtxWithActor(req.Context(), actorID, []string{"roles.manage"}, false, domA))
	w := httptest.NewRecorder()
	h.RemoveMember(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("RemoveMember out-of-scope target: want 404, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// 6. Unscoped super-admin (IsAdmin + AllPermissions, global scope) → all allowed.
// Regression that the new guards don't break the global admin flow.
func TestP2_UnscopedSuperAdmin_AllAllowed(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())
	// Real Super Admin DB assignment so is_unconfined=TRUE (admin_scope_within needs it).
	actorID := seedSuperAdmin(t, pool)
	targetUID := seedUser(t, pool)
	suffix := rolesTestRandomSuffix(t)

	// CreateRole with a sensitive perm, global scope → 201 (actor holds AllPermissions).
	createName := "p2-super-create-" + suffix
	reqC := rolesP2CreateRoleReq(`{"name":"` + createName + `","permissions":["users.delete","audit.read"]}`)
	reqC = reqC.WithContext(rolesP2CtxWithActor(reqC.Context(), actorID, permissions.AllPermissions, true, 0))
	wC := httptest.NewRecorder()
	h.CreateRole(wC, reqC)
	var created struct {
		ID int64 `json:"id"`
	}
	_ = json.Unmarshal(wC.Body.Bytes(), &created)
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM admin_role_assignments WHERE role_group_id = $1`, created.ID)
		pool.Exec(c, `DELETE FROM admin_role_groups WHERE name = $1`, createName)
	})
	if wC.Code != http.StatusCreated {
		t.Fatalf("super-admin CreateRole: want 201, got %d (body=%s)", wC.Code, wC.Body.String())
	}

	// AssignMember of a powerful global builtin role → 201.
	roleID := builtinRoleID(t, pool, "Super Admin")
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM admin_role_assignments WHERE user_id = $1`, targetUID)
	})
	bodyA := `{"userId":` + strconv.FormatInt(targetUID, 10) + `}`
	reqA := httptest.NewRequest("POST", "/admin/roles/"+strconv.FormatInt(roleID, 10)+"/members", strings.NewReader(bodyA))
	reqA.SetPathValue("id", strconv.FormatInt(roleID, 10))
	reqA = reqA.WithContext(rolesP2CtxWithActor(reqA.Context(), actorID, permissions.AllPermissions, true, 0))
	wA := httptest.NewRecorder()
	h.AssignMember(wA, reqA)
	if wA.Code != http.StatusCreated {
		t.Fatalf("super-admin AssignMember: want 201, got %d (body=%s)", wA.Code, wA.Body.String())
	}

	// UpdateRole on the just-created custom role → 204.
	reqU := httptest.NewRequest("PATCH", "/admin/roles/"+strconv.FormatInt(created.ID, 10),
		strings.NewReader(`{"permissions":["users.delete","users.impersonate"]}`))
	reqU.SetPathValue("id", strconv.FormatInt(created.ID, 10))
	reqU = reqU.WithContext(rolesP2CtxWithActor(reqU.Context(), actorID, permissions.AllPermissions, true, 0))
	wU := httptest.NewRecorder()
	h.UpdateRole(wU, reqU)
	if wU.Code != http.StatusNoContent {
		t.Fatalf("super-admin UpdateRole: want 204, got %d (body=%s)", wU.Code, wU.Body.String())
	}
}

// TestSuperAdminViaGovernedAssignment_NoLockout is the load-bearing safety test
// for deleting the legacy is_admin bridge: it proves a super-admin granted through
// a GOVERNED admin_role_assignments row (Super Admin, role group id 1) resolves to
// the full permission set and is NOT locked out of a perm-gated handler.
//
// Before the bridge deletion, an empty-perms is_admin token rode the bridge to
// full access. With the bridge gone, the ONLY path to super-admin authority is a
// resolved assignment — this test pins that that path works end-to-end:
// seed user → assign Super Admin → permissions.Resolve → build claims with the
// resolved perms → assert 200 on RequirePermAudited (no lockout).
func TestSuperAdminViaGovernedAssignment_NoLockout(t *testing.T) {
	pool := testsupport.OpenTestPool(t)

	// Seed a user and grant it the built-in Super Admin role (id 1) via a governed
	// admin_role_assignments row. granted_by must reference a real user (FK).
	userID := seedUser(t, pool)
	granterID := seedUser(t, pool)
	superAdminID := builtinRoleID(t, pool, "Super Admin")
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by)
		 VALUES ($1, $2, $3)`, userID, superAdminID, granterID); err != nil {
		t.Fatalf("seed Super Admin assignment: %v", err)
	}
	// seedUser's cleanup removes the assignment (DELETE ... WHERE user_id).

	// Resolve permissions through the SAME path the auth chain uses.
	perms, domainScope, err := permissions.Resolve(context.Background(), pool, userID)
	if err != nil {
		t.Fatalf("permissions.Resolve: %v", err)
	}
	if len(perms) == 0 {
		t.Fatal("Super Admin assignment resolved to ZERO permissions — would be a lockout")
	}

	// Build claims exactly as the chain would AFTER resolution (no bridge).
	claims := &auth.Claims{
		UserID:      userID,
		Email:       "superadmin@example.com",
		IsAdmin:     true,
		Permissions: perms,
		DomainScope: domainScope,
		Type:        jwtutil.TypeAccess,
	}

	// Assert 200 on a perm-gated handler (roles.manage — the most sensitive guard).
	spy := &matrixAuditSpy{}
	handler := middleware.RequirePermAudited(permissions.PermRolesManage, spy.capture)(okHandler)
	req := httptest.NewRequest("POST", "/admin/roles", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("governed super-admin locked out of roles.manage: got %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	if len(spy.events) != 0 {
		t.Errorf("governed super-admin: expected 0 audit events on success, got %d", len(spy.events))
	}
}

// ── Task 6: 等保三级 SoD pre-check tests ──────────────────────────────────────
//
// These tests exercise the Go-layer SoD pre-check added in Task 6. The DB
// trigger (trg_sod_exclusion) is the hard gate; the Go check is the early
// 409 with a descriptive error message.
//
// DB-backed tests SKIP when DB_DSN is absent.

// sodTestFlags returns a *toggle.FeatureFlags with dengbao.sod_mode set to on/off.
func sodTestFlags(on bool) *toggle.FeatureFlags {
	return toggle.NewStatic(map[string]bool{"dengbao.sod_mode": on})
}

// sodTestCreateRoleWithClass inserts a non-builtin role with the given sod_class and
// permissions, returning its id. Cleanup removes it (assignments cascade).
func sodTestCreateRoleWithClass(t *testing.T, pool *pgxpool.Pool, name, sodClass string, perms []string) int64 {
	t.Helper()
	ctx := context.Background()
	var id int64
	err := pool.QueryRow(ctx,
		`INSERT INTO admin_role_groups (name, description, permissions, sod_class, is_builtin)
		 VALUES ($1, $2, $3::text[], $4, FALSE) RETURNING id`,
		name, "sod test role "+name, perms, sodClass,
	).Scan(&id)
	if err != nil {
		t.Fatalf("sodTestCreateRoleWithClass(%q, %q): %v", name, sodClass, err)
	}
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM admin_role_assignments WHERE role_group_id = $1`, id)
		pool.Exec(c, `DELETE FROM admin_role_groups WHERE id = $1`, id)
	})
	return id
}

// sodTestAssignRole directly assigns a user to a role (bypasses the Go handler, so the
// trigger fires without the Go pre-check). Used to pre-seed a cross-class baseline.
func sodTestAssignRole(t *testing.T, pool *pgxpool.Pool, userID, roleID, grantedBy int64) {
	t.Helper()
	ctx := context.Background()
	_, err := pool.Exec(ctx,
		`INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (user_id, role_group_id) DO NOTHING`,
		userID, roleID, grantedBy,
	)
	if err != nil {
		t.Fatalf("sodTestAssignRole(user=%d, role=%d): %v", userID, roleID, err)
	}
}

// ── Unit test: sodClassConflict helper (pure, no DB) ─────────────────────────

// TestSodPrecheck_ClassUnionNoConflict_AllowsWhenOff verifies that the
// class-collision decision short-circuits to "allow" when SodMode is OFF — this
// tests the decision helper directly, with no DB or toggle flag lookup.
func TestSodPrecheck_ClassUnionNoConflict_AllowsWhenOff(t *testing.T) {
	offFlags := sodTestFlags(false)
	// OFF: sodClassConflict must return false (allow) regardless of inputs.
	if sodClassConflict(offFlags, []string{"system", "security"}, "audit") {
		t.Fatal("sodClassConflict must return false (allow) when SodMode is OFF")
	}
}

// TestSodPrecheck_ClassUnionConflict_DetectsWhenOn verifies the helper returns
// true (conflict) when adding a second class under ON.
func TestSodPrecheck_ClassUnionConflict_DetectsWhenOn(t *testing.T) {
	onFlags := sodTestFlags(true)
	// ON: existing class = "system", new class = "audit" → conflict.
	if !sodClassConflict(onFlags, []string{"system"}, "audit") {
		t.Fatal("sodClassConflict must return true when principal spans 2 classes under ON")
	}
}

// TestSodPrecheck_SameClassNoConflict verifies adding a same-class role never triggers.
func TestSodPrecheck_SameClassNoConflict(t *testing.T) {
	onFlags := sodTestFlags(true)
	// ON: existing class = "security", new class = "security" → no conflict.
	if sodClassConflict(onFlags, []string{"security"}, "security") {
		t.Fatal("sodClassConflict must return false (allow) for same-class assignment")
	}
}

// TestSodPrecheck_EmptyExistingNoConflict verifies that a principal with no
// existing classed assignments can receive any single class.
func TestSodPrecheck_EmptyExistingNoConflict(t *testing.T) {
	onFlags := sodTestFlags(true)
	if sodClassConflict(onFlags, nil, "system") {
		t.Fatal("sodClassConflict must allow first-ever class assignment")
	}
}

// TestSodPrecheck_NullNewClass_NoConflict verifies that assigning a role with
// no sod_class (empty string) never triggers the pre-check.
func TestSodPrecheck_NullNewClass_NoConflict(t *testing.T) {
	onFlags := sodTestFlags(true)
	if sodClassConflict(onFlags, []string{"system"}, "") {
		t.Fatal("sodClassConflict must allow assignment of a role with no sod_class")
	}
}

// ── DB-backed tests ───────────────────────────────────────────────────────────

// TestSodAssignMember_ON_CrossClassRejects409 — SodMode ON; assigning an 'audit'
// role to a principal that already holds a 'system' role → 409.
func TestSodAssignMember_ON_CrossClassRejects409(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())
	h.SetFeatureFlags(sodTestFlags(true))

	actorID := seedUser(t, pool)
	targetUID := seedUser(t, pool)
	suffix := rolesTestRandomSuffix(t)

	systemRoleID := sodTestCreateRoleWithClass(t, pool, "sod-system-"+suffix, "system", []string{"system.config"})
	auditRoleID := sodTestCreateRoleWithClass(t, pool, "sod-audit-"+suffix, "audit", []string{"audit.read"})

	// Seed target with the 'system' role directly (bypasses Go pre-check).
	sodTestAssignRole(t, pool, targetUID, systemRoleID, actorID)

	// Now try to assign the 'audit' role via the handler — should be 409.
	// Actor must hold the assigned role's perms (audit.read) to pass grant-only and
	// reach the SoD check.
	body := `{"userId":` + strconv.FormatInt(targetUID, 10) + `}`
	req := httptest.NewRequest("POST", "/admin/roles/"+strconv.FormatInt(auditRoleID, 10)+"/members", strings.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(auditRoleID, 10))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: actorID, IsAdmin: true, Permissions: []string{"audit.read"}}))
	w := httptest.NewRecorder()
	h.AssignMember(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("SoD ON cross-class assign: want 409, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// TestSodAssignMember_ON_SameClassAllows — SodMode ON; assigning a second 'system'
// role to a principal already holding a 'system' role → 201.
func TestSodAssignMember_ON_SameClassAllows(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())
	h.SetFeatureFlags(sodTestFlags(true))

	// Super-Admin actor: admin_protection_check derives authority from the DB
	// (admin_effective_authority), not JWT claims — a claims-only actor dominates
	// nothing and 403s before the SoD check the test asserts. Role 1 short-circuits.
	actorID := seedSuperAdmin(t, pool)
	targetUID := seedUser(t, pool)
	suffix := rolesTestRandomSuffix(t)

	systemRole1ID := sodTestCreateRoleWithClass(t, pool, "sod-sys1-"+suffix, "system", []string{"system.config"})
	systemRole2ID := sodTestCreateRoleWithClass(t, pool, "sod-sys2-"+suffix, "system", []string{"system.upgrade"})

	// Seed with first system role.
	sodTestAssignRole(t, pool, targetUID, systemRole1ID, actorID)

	// Assign second system role — same class, must succeed. Actor must hold the
	// assigned role's perms (system.upgrade) to pass grant-only.
	body := `{"userId":` + strconv.FormatInt(targetUID, 10) + `}`
	req := httptest.NewRequest("POST", "/admin/roles/"+strconv.FormatInt(systemRole2ID, 10)+"/members", strings.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(systemRole2ID, 10))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: actorID, IsAdmin: true, Permissions: []string{"system.upgrade"}}))
	w := httptest.NewRecorder()
	h.AssignMember(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("SoD ON same-class assign: want 201, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// TestSodAssignMember_OFF_CrossClassAllows — strict no-op: SodMode OFF; the same
// cross-class assignment that would 409 under ON must succeed (201) under OFF.
func TestSodAssignMember_OFF_CrossClassAllows(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())
	h.SetFeatureFlags(sodTestFlags(false))

	// Super-Admin actor: see TestSodAssignMember_ON_SameClassAllows — the DB-derived
	// authority must dominate the target or the protection gate 403s before the
	// strict-no-op assertion (201) the test verifies.
	actorID := seedSuperAdmin(t, pool)
	targetUID := seedUser(t, pool)
	suffix := rolesTestRandomSuffix(t)

	systemRoleID := sodTestCreateRoleWithClass(t, pool, "sod-off-sys-"+suffix, "system", []string{"system.config"})
	auditRoleID := sodTestCreateRoleWithClass(t, pool, "sod-off-audit-"+suffix, "audit", []string{"audit.read"})

	// Seed with system role.
	sodTestAssignRole(t, pool, targetUID, systemRoleID, actorID)

	// Under OFF, assigning a cross-class role must NOT be blocked by the Go
	// pre-check. The DB trigger is also OFF (toggle row enabled=false), so the
	// INSERT should succeed.
	// Actor must hold the assigned role's perms (audit.read) to pass grant-only.
	body := `{"userId":` + strconv.FormatInt(targetUID, 10) + `}`
	req := httptest.NewRequest("POST", "/admin/roles/"+strconv.FormatInt(auditRoleID, 10)+"/members", strings.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(auditRoleID, 10))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: actorID, IsAdmin: true, Permissions: []string{"audit.read"}}))
	w := httptest.NewRecorder()
	h.AssignMember(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("SoD OFF cross-class assign (strict no-op): want 201, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// TestSodUpdateRole_ON_ClassChangeCollidesRejects409 — SodMode ON; updating a
// role's sod_class from 'system' to 'audit' when there is a principal holding
// both this role AND an 'audit' role → 409.
func TestSodUpdateRole_ON_ClassChangeCollidesRejects409(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())
	h.SetFeatureFlags(sodTestFlags(true))

	actorID := seedUser(t, pool)
	targetUID := seedUser(t, pool)
	suffix := rolesTestRandomSuffix(t)

	// A 'system' role (we'll try to reclassify it to 'audit').
	systemRoleID := sodTestCreateRoleWithClass(t, pool, "sod-upd-sys-"+suffix, "system", []string{"system.config"})
	// An 'audit' role already held by the target.
	auditRoleID := sodTestCreateRoleWithClass(t, pool, "sod-upd-audit-"+suffix, "audit", []string{"audit.read"})

	// Target holds both roles currently.
	sodTestAssignRole(t, pool, targetUID, systemRoleID, actorID)
	sodTestAssignRole(t, pool, targetUID, auditRoleID, actorID)

	// Now try to update systemRole's sod_class to 'security' — this would make
	// the target span system→security AND audit → the EXISTS check must 409.
	body := `{"sodClass":"security"}`
	req := httptest.NewRequest("PATCH", "/admin/roles/"+strconv.FormatInt(systemRoleID, 10), strings.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(systemRoleID, 10))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: actorID, IsAdmin: true, Permissions: permissions.AllPermissions}))
	w := httptest.NewRecorder()
	h.UpdateRole(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("SoD ON UpdateRole class reclassify collision: want 409, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// TestSodUpdateRole_ON_ClassOnlyChangeViolatesRejects — SodMode ON; a role
// created with permissions=['system.config'] (class system) is reclassified to
// sod_class='audit' via an UpdateRole that sends ONLY sodClass (no permissions
// field). The stored permissions are incompatible with the new class, so the
// handler must 409.
//
// This exercises the fix for the "ValidateRoleClass skipped on class-only update"
// gap: before the fix, effectivePerms was empty when req.Permissions was absent,
// so ValidateRoleClass was never called.
func TestSodUpdateRole_ON_ClassOnlyChangeViolatesRejects(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())
	h.SetFeatureFlags(sodTestFlags(true))

	actorID := seedUser(t, pool)
	suffix := rolesTestRandomSuffix(t)

	// Role classified as 'system', holds system.config (valid for system class).
	roleID := sodTestCreateRoleWithClass(t, pool, "sod-classonly-"+suffix, "system", []string{"system.config"})

	// Send ONLY sodClass='audit' — no permissions field.
	// system.config is NOT allowed in the 'audit' class, so the check must 409.
	body := `{"sodClass":"audit"}`
	req := httptest.NewRequest("PATCH", "/admin/roles/"+strconv.FormatInt(roleID, 10), strings.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(roleID, 10))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: actorID, IsAdmin: true, Permissions: permissions.AllPermissions}))
	w := httptest.NewRecorder()
	h.UpdateRole(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("SoD ON class-only reclassify with incompatible stored perm: want 409, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// TestSodUpdateRole_ON_ValidateRoleClassRejects — SodMode ON; creating/updating a
// role with permissions that violate its declared sod_class → 409.
// Example: declaring sod_class='audit' but including 'system.config' (system-only).
func TestSodUpdateRole_ON_ValidateRoleClassRejects(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())
	h.SetFeatureFlags(sodTestFlags(true))

	actorID := seedUser(t, pool)
	suffix := rolesTestRandomSuffix(t)

	// Create a role classified as 'audit' but with a system-only perm.
	roleID := sodTestCreateRoleWithClass(t, pool, "sod-badperm-"+suffix, "audit", []string{"audit.read"})

	// Try to update its permissions to include 'system.config' (system class, not audit).
	// Actor holds AllPermissions so grant-only passes and the SoD class check is what 409s.
	body := `{"permissions":["audit.read","system.config"],"sodClass":"audit"}`
	req := httptest.NewRequest("PATCH", "/admin/roles/"+strconv.FormatInt(roleID, 10), strings.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(roleID, 10))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: actorID, IsAdmin: true, Permissions: permissions.AllPermissions}))
	w := httptest.NewRecorder()
	h.UpdateRole(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("SoD ON UpdateRole invalid class+perms: want 409, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// ── Task 6: scope-set grant tests ─────────────────────────────────────────────
//
// These tests exercise AssignMember + BulkAssign accepting scopeType='set',
// retiring group/user scope (→ 400), and fetchMembers returning setName.
// All DB-backed (testsupport.OpenTestPool skips or fails-closed per REQUIRE_DB).

// seedScopeSetWithOUMember creates an admin_scope_sets row with one 'ou' member
// (a freshly-created department). Returns the set ID. Cleanup removes member + dept + set.
func seedScopeSetWithOUMember(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	suffix := rolesTestRandomSuffix(t)
	path := "/rbac-t6-" + suffix
	var deptID int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO departments (name, path, ldap_ou) VALUES ($1, $2, $3) RETURNING id`,
		"RbacT6-"+suffix, path, "ou=rbact6-"+suffix).Scan(&deptID); err != nil {
		t.Fatalf("seedScopeSetWithOUMember dept: %v", err)
	}
	setID := seedScopeSet(t, pool, "ou-member") // cleanup registered by seedScopeSet
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO admin_scope_set_members (set_id, member_type, member_id) VALUES ($1, 'ou', $2)`,
		setID, deptID); err != nil {
		t.Fatalf("seedScopeSetWithOUMember member: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM admin_scope_set_members WHERE member_type='ou' AND member_id=$1`, deptID)
		pool.Exec(c, `DELETE FROM departments WHERE id = $1`, deptID)
	})
	return setID
}

// doAssignSet sends POST /admin/roles/{id}/members with the given body+claims.
func doAssignSet(t *testing.T, h *RolesHandler, roleID int64, body string, claims *auth.Claims) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/admin/roles/"+strconv.FormatInt(roleID, 10)+"/members", strings.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(roleID, 10))
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	w := httptest.NewRecorder()
	h.AssignMember(w, req)
	return w
}

// doBulkAssignSet sends POST /admin/roles/{id}/members:bulk.
func doBulkAssignSet(t *testing.T, h *RolesHandler, roleID int64, body string, claims *auth.Claims) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/admin/roles/"+strconv.FormatInt(roleID, 10)+"/members:bulk", strings.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(roleID, 10))
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	w := httptest.NewRecorder()
	h.BulkAssign(w, req)
	return w
}

// TestAssignMember_SetScope_OK: a super-admin (is_unconfined=TRUE via null-scope
// DB assignment) assigning with a valid set scope → 201.
func TestAssignMember_SetScope_OK(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())
	actorID := seedSuperAdmin(t, pool) // null-scope DB assignment → is_unconfined=TRUE
	targetID := seedUser(t, pool)
	roleID := builtinRoleID(t, pool, "Help Desk")
	setID := seedScopeSet(t, pool, "assign-ok") // empty set — unconfined actor always passes
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM admin_role_assignments WHERE user_id = $1`, targetID)
	})

	body := `{"userId":` + strconv.FormatInt(targetID, 10) +
		`,"scopeType":"set","scopeId":` + strconv.FormatInt(setID, 10) + `}`
	w := doAssignSet(t, h, roleID, body,
		&auth.Claims{UserID: actorID, IsAdmin: true, Permissions: permissions.AllPermissions})
	if w.Code != http.StatusCreated {
		t.Fatalf("want 201 for valid set scope, got %d: %s", w.Code, w.Body.String())
	}
}

// TestAssignMember_SetScope_OutOfReach_403: an object-confined actor (no null-scope
// DB assignment) trying to grant a set whose OU member is outside their reach → 403.
func TestAssignMember_SetScope_OutOfReach_403(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())
	// Bare actor: no DB assignments → admin_can_manage passes (no assignments)
	// but is_unconfined=FALSE → admin_scope_within fails for any OU-bearing set.
	actorID := seedUser(t, pool)
	targetID := seedUser(t, pool)
	roleID := builtinRoleID(t, pool, "Help Desk")
	setID := seedScopeSetWithOUMember(t, pool) // set has an OU → actor can't contain it

	body := `{"userId":` + strconv.FormatInt(targetID, 10) +
		`,"scopeType":"set","scopeId":` + strconv.FormatInt(setID, 10) + `}`
	w := doAssignSet(t, h, roleID, body,
		&auth.Claims{UserID: actorID, IsAdmin: true, Permissions: permissions.AllPermissions})
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403 for set broader than actor's reach, got %d: %s", w.Code, w.Body.String())
	}
}

// TestAssignMember_GroupUserScope_Retired_400: scopeType 'group' or 'user' → 400
// with a message directing to scope-sets.
func TestAssignMember_GroupUserScope_Retired_400(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())
	actorID := seedUser(t, pool)
	targetID := seedUser(t, pool)
	roleID := builtinRoleID(t, pool, "Help Desk")

	for _, st := range []string{"group", "user"} {
		body := `{"userId":` + strconv.FormatInt(targetID, 10) +
			`,"scopeType":"` + st + `","scopeId":1}`
		w := doAssignSet(t, h, roleID, body,
			&auth.Claims{UserID: actorID, IsAdmin: true, Permissions: permissions.AllPermissions})
		if w.Code != http.StatusBadRequest {
			t.Fatalf("scopeType=%s: want 400 (use a scope-set), got %d: %s", st, w.Code, w.Body.String())
		}
	}
}

// TestBulkAssign_SetScope_OK: bulk assign with scopeType='set' → 202.
func TestBulkAssign_SetScope_OK(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())
	actorID := seedSuperAdmin(t, pool)
	targetID := seedUser(t, pool)
	roleID := builtinRoleID(t, pool, "Help Desk")
	setID := seedScopeSet(t, pool, "bulk-ok")

	body := `{"userIds":[` + strconv.FormatInt(targetID, 10) +
		`],"scopeType":"set","scopeId":` + strconv.FormatInt(setID, 10) + `}`
	w := doBulkAssignSet(t, h, roleID, body,
		&auth.Claims{UserID: actorID, IsAdmin: true, Permissions: permissions.AllPermissions})
	if w.Code != http.StatusAccepted {
		t.Fatalf("want 202 for bulk set scope, got %d: %s", w.Code, w.Body.String())
	}
}

// TestFetchMembers_SetGrant_HasSetName: a 'set'-scoped assignment surfaces its set
// name in the fetchMembers response.
func TestFetchMembers_SetGrant_HasSetName(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())
	actorID := seedSuperAdmin(t, pool)
	targetID := seedUser(t, pool)
	roleID := builtinRoleID(t, pool, "Help Desk")
	setID := seedScopeSet(t, pool, "fetchname")

	// Fetch the set name so we can assert it in the response.
	var setName string
	if err := pool.QueryRow(context.Background(),
		`SELECT name FROM admin_scope_sets WHERE id = $1`, setID).Scan(&setName); err != nil {
		t.Fatalf("fetch set name: %v", err)
	}

	// Seed the assignment with scope_type='set' directly (bypass the handler).
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by, scope_type, scope_id)
		 VALUES ($1, $2, $3, 'set', $4) ON CONFLICT (user_id, role_group_id) DO UPDATE
		 SET scope_type='set', scope_id=$4`,
		targetID, roleID, actorID, setID); err != nil {
		t.Fatalf("seed assignment: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM admin_role_assignments WHERE user_id = $1`, targetID)
	})

	members, err := h.fetchMembers(context.Background(), roleID, actorID)
	if err != nil {
		t.Fatalf("fetchMembers: %v", err)
	}
	var found *roleMember
	for i := range members {
		if members[i].UserID == targetID {
			found = &members[i]
			break
		}
	}
	if found == nil {
		t.Fatal("target member not in fetchMembers result")
	}
	if found.SetName == nil || *found.SetName != setName {
		t.Fatalf("want setName=%q, got %v", setName, found.SetName)
	}
}

func TestEffectivePermsResponse_IncludesConsoles(t *testing.T) {
	// The response must carry consoles derived from ConsolesForPerms (the SSOT),
	// so the Access Preview reads console entry from the backend, not a TS port.
	resp := effectivePermsResponse{
		Permissions: []string{"audit.read", "users.read"},
		Consoles:    ConsolesForPerms([]string{"audit.read", "users.read"}),
	}
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded struct {
		Consoles []string `json:"consoles"`
	}
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// audit.read → logs console; users.read → auth console.
	want := []string{"logs", "auth"}
	if !reflect.DeepEqual(decoded.Consoles, want) {
		t.Errorf("consoles = %v, want %v", decoded.Consoles, want)
	}
}

// TestAssignMember_Eligible_PersistsFlag — assigning with eligible:true must store
// eligible=true and activated_until=NULL (not yet activated). Decision 14.
func TestAssignMember_Eligible_PersistsFlag(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())
	roleID := builtinRoleID(t, pool, "Help Desk")
	actorID := seedSuperAdmin(t, pool)
	uid := seedUser(t, pool)

	body := `{"userId":` + strconv.FormatInt(uid, 10) + `,"eligible":true}`
	req := httptest.NewRequest("POST", "/admin/roles/"+strconv.FormatInt(roleID, 10)+"/members",
		strings.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(roleID, 10))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID: actorID, Email: "admin@x.com", IsAdmin: true, Permissions: permissions.AllPermissions,
	}))
	w := httptest.NewRecorder()
	h.AssignMember(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("got %d, want 201: %s", w.Code, w.Body.String())
	}

	var eligible bool
	var activatedUntil *string
	err := pool.QueryRow(context.Background(),
		`SELECT eligible, activated_until::text FROM admin_role_assignments
		 WHERE user_id = $1 AND role_group_id = $2`, uid, roleID,
	).Scan(&eligible, &activatedUntil)
	if err != nil {
		t.Fatalf("SELECT eligible: %v", err)
	}
	if !eligible {
		t.Error("eligible should be true")
	}
	if activatedUntil != nil {
		t.Errorf("activated_until should be NULL, got %s", *activatedUntil)
	}
}
