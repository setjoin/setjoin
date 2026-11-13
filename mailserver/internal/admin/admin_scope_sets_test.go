package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/testsupport"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func newScopeSetsHandlerForTest(t *testing.T) (*ScopeSetsHandler, *pgxpool.Pool) {
	t.Helper()
	pool := testsupport.OpenTestPool(t)
	return NewScopeSetsHandler(pool, testsupport.TestLogger()), pool
}

// ssEnsureDomain returns (or creates) a test domain for scope-set tests.
func ssEnsureDomain(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	var id int64
	err := pool.QueryRow(context.Background(),
		`INSERT INTO domains (name) VALUES ('scopesets.test')
		 ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
		 RETURNING id`).Scan(&id)
	if err != nil {
		t.Fatalf("ssEnsureDomain: %v", err)
	}
	return id
}

// ssCreateUser inserts a bare user in the scope-set test domain.
func ssCreateUser(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	domainID := ssEnsureDomain(t, pool)
	suffix := rolesTestRandomSuffix(t) // reuse existing helper from admin_roles_test.go
	email := "ssuser-" + suffix + "@scopesets.test"
	var id int64
	err := pool.QueryRow(context.Background(),
		`INSERT INTO users (username, email, display_name, password_hash, domain_id)
		 VALUES ($1, $2, 'SS User', '$2a$10$placeholder', $3) RETURNING id`,
		"ssuser-"+suffix, email, domainID).Scan(&id)
	if err != nil {
		t.Fatalf("ssCreateUser: %v", err)
	}
	t.Cleanup(func() {
		// LOUD cleanup: a silently-ignored delete failure leaked enabled test
		// users (occasionally WITH seeded Super Admin grants) across suites,
		// tripping the authserver SSO sweep's sole-SA precondition. Fail the
		// OWNING test instead of poisoning later suites.
		c := context.Background()
		// The scoped user is the actor for eDiscovery cases/searches and
		// ip_rules this test creates; their user FKs make the row
		// undeletable while its fixtures exist. Remove THIS test's fixtures
		// first (case children before their case rows); any other dependent
		// still fails loudly below.
		if _, err := pool.Exec(c, `DELETE FROM ediscovery_searches WHERE created_by = $1`, id); err != nil {
			t.Errorf("ssCreateUser cleanup: delete ediscovery_searches for user %d: %v", id, err)
		}
		scopedCases := `SELECT id FROM ediscovery_cases WHERE created_by = $1 OR closed_by = $1`
		if _, err := pool.Exec(c, `DELETE FROM chat_ediscovery_searches WHERE case_id IN (`+scopedCases+`)`, id); err != nil {
			t.Errorf("ssCreateUser cleanup: delete chat_ediscovery_searches for user %d: %v", id, err)
		}
		if _, err := pool.Exec(c, `DELETE FROM chat_case_holds WHERE case_id IN (`+scopedCases+`)`, id); err != nil {
			t.Errorf("ssCreateUser cleanup: delete chat_case_holds for user %d: %v", id, err)
		}
		if _, err := pool.Exec(c, `DELETE FROM ediscovery_cases WHERE created_by = $1 OR closed_by = $1`, id); err != nil {
			t.Errorf("ssCreateUser cleanup: delete ediscovery_cases for user %d: %v", id, err)
		}
		if _, err := pool.Exec(c, `DELETE FROM ip_rules WHERE created_by = $1`, id); err != nil {
			t.Errorf("ssCreateUser cleanup: delete ip_rules for user %d: %v", id, err)
		}
		// Role grants this user issued to others: the granted_by FK is
		// RESTRICT, and deleting them is safe because this user's own (still
		// active) Super Admin assignment — if any — keeps the last-SA count
		// above zero for trg_protect_last_super_admin.
		if _, err := pool.Exec(c, `DELETE FROM admin_role_assignments WHERE granted_by = $1 AND user_id <> $1`, id); err != nil {
			t.Errorf("ssCreateUser cleanup: delete assignments granted by user %d: %v", id, err)
		}
		// Expire this user's own assignments before deleting them: the
		// last-SA guard skips expired rows by design, so a test that left
		// the scoped user holding the ONLY enabled Super Admin grant does
		// not wedge cleanup. Any OTHER failure still surfaces below.
		if _, err := pool.Exec(c, `UPDATE admin_role_assignments SET expires_at = now() WHERE user_id = $1 AND (expires_at IS NULL OR expires_at > now())`, id); err != nil {
			t.Errorf("ssCreateUser cleanup: expire assignments for user %d: %v", id, err)
		}
		if _, err := pool.Exec(c, `DELETE FROM admin_role_assignments WHERE user_id = $1`, id); err != nil {
			t.Errorf("ssCreateUser cleanup: delete role assignments for user %d: %v", id, err)
		}
		if _, err := pool.Exec(c, `DELETE FROM users WHERE id = $1`, id); err != nil {
			// Chat spaces (chat_space_ensure) and drive audits are
			// append-only by design, so an author entangled in that web can
			// never be deleted. Demote instead of failing: grants are
			// already gone above, and disabling keeps the user from
			// poisoning later suites. Anything ELSE still fails loudly.
			if _, dis := pool.Exec(c, `UPDATE users SET enabled = false WHERE id = $1`, id); dis != nil {
				t.Errorf("ssCreateUser cleanup: delete user %d failed and disable also failed: delete=%v disable=%v", id, err, dis)
				return
			}
			t.Logf("ssCreateUser cleanup: user %d left disabled (append-only chat/drive web): %v", id, err)
			return
		}
	})
	return id
}

// officeFixtureOwner returns a durable, non-admin user that owns the drive
// fixture subtree. Drive spaces are append-only-audited and cannot be deleted
// via SQL, so their owner and file-version author must be a long-lived
// fixture identity (like the seeded scopesets.test domain) instead of the
// per-test ssCreateUser actor, whose cleanup must be able to delete it.
func officeFixtureOwner(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	domainID := ssEnsureDomain(t, pool)
	var id int64
	err := pool.QueryRow(context.Background(), `SELECT id FROM users
		WHERE username = 'office-drive-fixture' AND domain_id = $1`, domainID).Scan(&id)
	if err == nil {
		return id
	}
	if err != pgx.ErrNoRows {
		t.Fatalf("officeFixtureOwner: lookup: %v", err)
	}
	err = pool.QueryRow(context.Background(), `INSERT INTO users
		(username, email, display_name, password_hash, domain_id)
		VALUES ('office-drive-fixture', 'office-drive-fixture@scopesets.test',
		        'Office Drive Fixture', '$2a$10$placeholder', $1)
		RETURNING id`, domainID).Scan(&id)
	if err != nil {
		t.Fatalf("officeFixtureOwner: insert: %v", err)
	}
	return id
}

// ssSuperClaims returns claims with scope_sets.manage and AllPermissions.
func ssSuperClaims(actorID int64) *auth.Claims {
	return &auth.Claims{UserID: actorID, IsAdmin: true, Permissions: permissions.AllPermissions}
}

// ssNoPerm returns claims with every permission EXCEPT scope_sets.manage.
func ssNoPerm(actorID int64) *auth.Claims {
	var perms []string
	for _, p := range permissions.AllPermissions {
		if p != permissions.PermScopeSetsManage {
			perms = append(perms, p)
		}
	}
	return &auth.Claims{UserID: actorID, IsAdmin: true, Permissions: perms}
}

// seedScopeSet inserts an admin_scope_set and returns its ID.
func seedScopeSet(t *testing.T, pool *pgxpool.Pool, nameSuffix string) int64 {
	t.Helper()
	suffix := rolesTestRandomSuffix(t)
	name := fmt.Sprintf("test-set-%s-%s", nameSuffix, suffix)
	var id int64
	err := pool.QueryRow(context.Background(),
		`INSERT INTO admin_scope_sets (name) VALUES ($1) RETURNING id`, name).Scan(&id)
	if err != nil {
		t.Fatalf("seedScopeSet(%q): %v", name, err)
	}
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM admin_scope_set_members WHERE set_id = $1`, id)
		pool.Exec(c, `DELETE FROM admin_scope_sets WHERE id = $1`, id)
	})
	return id
}

// ssCreateDistGroup creates a mailbox (for the group) then a distribution_group row.
// isDynamic and eligible (usable_as_admin_scope) are controlled by the caller.
// Returns the group id. Cleanup removes both rows.
func ssCreateDistGroup(t *testing.T, pool *pgxpool.Pool, isDynamic, eligible bool) int64 {
	t.Helper()
	ctx := context.Background()
	domainID := ssEnsureDomain(t, pool)
	suffix := rolesTestRandomSuffix(t)
	email := "grpmbx-" + suffix + "@scopesets.test"

	// distribution_groups requires a mailbox row (1:1, unique mailbox_id).
	var mbxID int64
	err := pool.QueryRow(ctx,
		`INSERT INTO mailboxes (domain_id, email, display_name, type)
		 VALUES ($1, $2, $3, 'personal') RETURNING id`,
		domainID, email, "Group-"+suffix).Scan(&mbxID)
	if err != nil {
		t.Fatalf("ssCreateDistGroup mailbox: %v", err)
	}

	var groupID int64
	err = pool.QueryRow(ctx,
		`INSERT INTO distribution_groups (mailbox_id, is_dynamic, usable_as_admin_scope)
		 VALUES ($1, $2, $3) RETURNING id`,
		mbxID, isDynamic, eligible).Scan(&groupID)
	if err != nil {
		t.Fatalf("ssCreateDistGroup group: %v", err)
	}

	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM admin_scope_set_members WHERE member_type='group' AND member_id=$1`, groupID)
		pool.Exec(c, `DELETE FROM distribution_groups WHERE id = $1`, groupID)
		pool.Exec(c, `DELETE FROM mailboxes WHERE id = $1`, mbxID)
	})
	return groupID
}

// ssCreateScimGroup creates a source-bound static SCIM distribution group with
// usable_as_admin_scope = false. A SCIM external ID still makes the group
// eligible, while V168 requires its source ID to be present as the matching
// provenance half of the pair.
func ssCreateScimGroup(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	ctx := context.Background()
	domainID := ssEnsureDomain(t, pool)
	suffix := rolesTestRandomSuffix(t)
	email := "grpmbx-scim-" + suffix + "@scopesets.test"

	var mbxID int64
	err := pool.QueryRow(ctx,
		`INSERT INTO mailboxes (domain_id, email, display_name, type)
		 VALUES ($1, $2, $3, 'personal') RETURNING id`,
		domainID, email, "ScimGroup-"+suffix).Scan(&mbxID)
	if err != nil {
		t.Fatalf("ssCreateScimGroup mailbox: %v", err)
	}

	var groupID int64
	err = pool.QueryRow(ctx,
		`INSERT INTO distribution_groups (
		     mailbox_id, is_dynamic, usable_as_admin_scope,
		     scim_external_id, scim_source_id
		 )
		 VALUES (
		     $1, FALSE, FALSE, $2,
		     (SELECT id FROM identity_sources WHERE source_key='legacy:scim')
		 )
		 RETURNING id`,
		mbxID, "scim-ext-"+suffix).Scan(&groupID)
	if err != nil {
		t.Fatalf("ssCreateScimGroup group: %v", err)
	}

	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM admin_scope_set_members WHERE member_type='group' AND member_id=$1`, groupID)
		pool.Exec(c, `DELETE FROM distribution_groups WHERE id = $1`, groupID)
		pool.Exec(c, `DELETE FROM mailboxes WHERE id = $1`, mbxID)
	})
	return groupID
}

// ssNewRequest builds an httptest.Request with the given auth claims in context.
func ssNewRequest(t *testing.T, method, path, body string, claims *auth.Claims) *http.Request {
	t.Helper()
	b := strings.NewReader(body)
	req := httptest.NewRequest(method, path, b)
	if claims != nil {
		req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	}
	return req
}

// ssItoa converts int64 to string (avoids import bloat in test helpers).
func ssItoa(n int64) string { return fmt.Sprintf("%d", n) }

// ── Tests: permission gate ────────────────────────────────────────────────────

// TestCreateScopeSet_RequiresPermission: 403 when caller lacks scope_sets.manage.
func TestCreateScopeSet_RequiresPermission(t *testing.T) {
	h, pool := newScopeSetsHandlerForTest(t)
	actorID := ssCreateUser(t, pool)
	req := ssNewRequest(t, "POST", "/admin/scope-sets", `{"name":"Region East"}`, ssNoPerm(actorID))
	rec := httptest.NewRecorder()
	h.CreateScopeSet(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403 without scope_sets.manage, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestListScopeSets_RequiresPermission(t *testing.T) {
	h, pool := newScopeSetsHandlerForTest(t)
	actorID := ssCreateUser(t, pool)
	req := ssNewRequest(t, "GET", "/admin/scope-sets", "", ssNoPerm(actorID))
	rec := httptest.NewRecorder()
	h.ListScopeSets(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", rec.Code)
	}
}

func TestAddMember_RequiresPermission(t *testing.T) {
	h, pool := newScopeSetsHandlerForTest(t)
	actorID := ssCreateUser(t, pool)
	req := ssNewRequest(t, "POST", "/admin/scope-sets/1/members",
		`{"memberType":"ou","memberId":1}`, ssNoPerm(actorID))
	req.SetPathValue("id", "1")
	rec := httptest.NewRecorder()
	h.AddMember(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", rec.Code)
	}
}

// ── Tests: CreateScopeSet ─────────────────────────────────────────────────────

// TestCreateScopeSet_OK: happy path → 201 with id + audit row.
func TestCreateScopeSet_OK(t *testing.T) {
	h, pool := newScopeSetsHandlerForTest(t)
	actorID := ssCreateUser(t, pool)
	suffix := rolesTestRandomSuffix(t)
	name := "create-ok-" + suffix

	req := ssNewRequest(t, "POST", "/admin/scope-sets",
		fmt.Sprintf(`{"name":%q}`, name), ssSuperClaims(actorID))
	rec := httptest.NewRecorder()
	h.CreateScopeSet(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var out map[string]int64
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out["id"] == 0 {
		t.Fatalf("want {id:N}, got %s", rec.Body.String())
	}
	var n int
	pool.QueryRow(context.Background(),
		`SELECT count(*) FROM admin_audit_log WHERE action='scope_set_create' AND user_id=$1`, actorID).Scan(&n)
	if n == 0 {
		t.Error("expected scope_set_create audit row")
	}
	id := out["id"]
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM admin_scope_set_members WHERE set_id = $1`, id)
		pool.Exec(c, `DELETE FROM admin_scope_sets WHERE id = $1`, id)
	})
}

// TestCreateScopeSet_DuplicateName_409: (NULL domain_id, same name) → 409.
func TestCreateScopeSet_DuplicateName_409(t *testing.T) {
	h, pool := newScopeSetsHandlerForTest(t)
	actorID := ssCreateUser(t, pool)
	setID := seedScopeSet(t, pool, "dup")

	var name string
	pool.QueryRow(context.Background(), `SELECT name FROM admin_scope_sets WHERE id=$1`, setID).Scan(&name)

	req := ssNewRequest(t, "POST", "/admin/scope-sets",
		fmt.Sprintf(`{"name":%q}`, name), ssSuperClaims(actorID))
	rec := httptest.NewRecorder()
	h.CreateScopeSet(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("want 409 for duplicate name, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// ── Tests: DeleteScopeSet ─────────────────────────────────────────────────────

// TestDeleteScopeSet_InUse_409: V041 RESTRICT trigger → P0001 → 409.
func TestDeleteScopeSet_InUse_409(t *testing.T) {
	h, pool := newScopeSetsHandlerForTest(t)
	actorID := ssCreateUser(t, pool)
	targetID := ssCreateUser(t, pool)
	setID := seedScopeSet(t, pool, "inuse")

	// Wire a grant scoped to this set.
	suffix := rolesTestRandomSuffix(t)
	var roleID int64
	pool.QueryRow(context.Background(),
		`INSERT INTO admin_role_groups (name, permissions) VALUES ($1, ARRAY['audit.read']) RETURNING id`,
		"ss-inuse-role-"+suffix).Scan(&roleID)
	pool.Exec(context.Background(),
		`INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by, scope_type, scope_id)
		 VALUES ($1, $2, $3, 'set', $4)`,
		targetID, roleID, actorID, setID)
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM admin_role_assignments WHERE role_group_id = $1`, roleID)
		pool.Exec(c, `DELETE FROM admin_role_groups WHERE id = $1`, roleID)
	})

	req := ssNewRequest(t, "DELETE", "/admin/scope-sets/"+ssItoa(setID), "", ssSuperClaims(actorID))
	req.SetPathValue("id", ssItoa(setID))
	rec := httptest.NewRecorder()
	h.DeleteScopeSet(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("want 409 for in-use set, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// ── Tests: AddMember ─────────────────────────────────────────────────────────

// TestAddMember_OutOfReach_403: OU member outside actor's OU scope → 403.
// Actor is confined to /sstest-eng-<suffix>, trying to add /sstest-sales-<suffix>.
// admin_scope_within(actor, 'ou', salesID, NULL) must return FALSE.
func TestAddMember_OutOfReach_403(t *testing.T) {
	h, pool := newScopeSetsHandlerForTest(t)
	ctx := context.Background()

	// Two sibling departments.
	suffix := rolesTestRandomSuffix(t)
	engPath := "/sstest-eng-" + suffix
	salesPath := "/sstest-sales-" + suffix

	var engID, salesID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO departments (name, path, ldap_ou) VALUES ($1, $2, $3) RETURNING id`,
		"SSEng-"+suffix, engPath, "ou=sseng-"+suffix).Scan(&engID); err != nil {
		t.Fatalf("insert eng dept: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO departments (name, path, ldap_ou) VALUES ($1, $2, $3) RETURNING id`,
		"SSSales-"+suffix, salesPath, "ou=sssales-"+suffix).Scan(&salesID); err != nil {
		t.Fatalf("insert sales dept: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM admin_scope_set_members WHERE member_type='ou' AND member_id IN ($1, $2)`, engID, salesID)
		pool.Exec(c, `DELETE FROM departments WHERE id IN ($1, $2)`, engID, salesID)
	})

	// Actor confined to /eng via an OU-scoped role assignment.
	actorID := ssCreateUser(t, pool)
	var roleID int64
	pool.QueryRow(ctx,
		`INSERT INTO admin_role_groups (name, permissions) VALUES ($1, ARRAY['roles.manage']) RETURNING id`,
		"ss-eng-role-"+suffix).Scan(&roleID)
	pool.Exec(ctx,
		`INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by, scope_type, scope_id)
		 VALUES ($1, $2, $1, 'ou', $3)`, actorID, roleID, engID)
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM admin_role_assignments WHERE role_group_id = $1`, roleID)
		pool.Exec(c, `DELETE FROM admin_role_groups WHERE id = $1`, roleID)
	})

	setID := seedScopeSet(t, pool, "reach")
	claims := &auth.Claims{UserID: actorID, Permissions: []string{permissions.PermScopeSetsManage}}

	body := fmt.Sprintf(`{"memberType":"ou","memberId":%d}`, salesID)
	req := ssNewRequest(t, "POST", "/admin/scope-sets/"+ssItoa(setID)+"/members", body, claims)
	req.SetPathValue("id", ssItoa(setID))
	rec := httptest.NewRecorder()
	h.AddMember(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403 for out-of-reach OU member, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestAddMember_DynamicGroup_Rejected: is_dynamic=TRUE → 400.
func TestAddMember_DynamicGroup_Rejected(t *testing.T) {
	h, pool := newScopeSetsHandlerForTest(t)
	actorID := ssCreateUser(t, pool)
	setID := seedScopeSet(t, pool, "dyngrp")
	groupID := ssCreateDistGroup(t, pool, true /*isDynamic*/, true /*eligible*/)

	body := fmt.Sprintf(`{"memberType":"group","memberId":%d}`, groupID)
	req := ssNewRequest(t, "POST", "/admin/scope-sets/"+ssItoa(setID)+"/members", body, ssSuperClaims(actorID))
	req.SetPathValue("id", ssItoa(setID))
	rec := httptest.NewRecorder()
	h.AddMember(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for dynamic group, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestAddMember_GroupNotEligible_400: static group with usable_as_admin_scope=false and no scim_external_id → 400.
func TestAddMember_GroupNotEligible_400(t *testing.T) {
	h, pool := newScopeSetsHandlerForTest(t)
	actorID := ssCreateUser(t, pool)
	setID := seedScopeSet(t, pool, "ineligible")
	groupID := ssCreateDistGroup(t, pool, false /*isDynamic*/, false /*eligible*/)

	body := fmt.Sprintf(`{"memberType":"group","memberId":%d}`, groupID)
	req := ssNewRequest(t, "POST", "/admin/scope-sets/"+ssItoa(setID)+"/members", body, ssSuperClaims(actorID))
	req.SetPathValue("id", ssItoa(setID))
	rec := httptest.NewRecorder()
	h.AddMember(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for ineligible group, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestAddMember_StaticGroup_SuperAdmin_201: eligible static group with no members + super-admin → 201.
func TestAddMember_StaticGroup_SuperAdmin_201(t *testing.T) {
	h, pool := newScopeSetsHandlerForTest(t)
	actorID := seedSuperAdmin(t, pool) // reuse existing helper; super-admin reaches all
	setID := seedScopeSet(t, pool, "staticgrp")
	groupID := ssCreateDistGroup(t, pool, false /*isDynamic*/, true /*eligible*/)

	body := fmt.Sprintf(`{"memberType":"group","memberId":%d}`, groupID)
	req := ssNewRequest(t, "POST", "/admin/scope-sets/"+ssItoa(setID)+"/members", body, ssSuperClaims(actorID))
	req.SetPathValue("id", ssItoa(setID))
	rec := httptest.NewRecorder()
	h.AddMember(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// ── Tests: DeleteScopeSet nonexistent → 404 ───────────────────────────────────

// TestDeleteScopeSet_NotFound_404: deleting a nonexistent id must return 404, not 204.
// Also asserts no spurious audit row is written.
func TestDeleteScopeSet_NotFound_404(t *testing.T) {
	h, pool := newScopeSetsHandlerForTest(t)
	actorID := ssCreateUser(t, pool)

	const ghostID = int64(999999999)
	req := ssNewRequest(t, "DELETE", "/admin/scope-sets/999999999", "", ssSuperClaims(actorID))
	req.SetPathValue("id", "999999999")
	rec := httptest.NewRecorder()
	h.DeleteScopeSet(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 for nonexistent scope set, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	// No audit row should have been written for this ghost id.
	var n int
	pool.QueryRow(context.Background(),
		`SELECT count(*) FROM admin_audit_log WHERE action='scope_set_delete' AND target_id=$1`, ghostID).Scan(&n)
	if n != 0 {
		t.Errorf("want 0 scope_set_delete audit rows for nonexistent set, got %d", n)
	}
}

// ── Tests: ListDistributionGroups ─────────────────────────────────────────────

// TestListDistributionGroups_403: 403 when caller lacks scope_sets.manage.
func TestListDistributionGroups_403(t *testing.T) {
	h, pool := newScopeSetsHandlerForTest(t)
	actorID := ssCreateUser(t, pool)
	req := ssNewRequest(t, "GET", "/admin/distribution-groups", "", ssNoPerm(actorID))
	rec := httptest.NewRecorder()
	h.ListDistributionGroups(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403 without scope_sets.manage, got %d", rec.Code)
	}
}

// TestListDistributionGroups_EligibilityFlags: seeds three groups and asserts
// each is returned with the correct isDynamic/scimSynced/usableAsAdminScope flags.
func TestListDistributionGroups_EligibilityFlags(t *testing.T) {
	h, pool := newScopeSetsHandlerForTest(t)
	actorID := ssCreateUser(t, pool)

	// static-eligible: usable_as_admin_scope=true, is_dynamic=false, no scim_external_id
	eligibleID := ssCreateDistGroup(t, pool, false, true)
	// dynamic: is_dynamic=true (ineligible regardless of usable_as_admin_scope)
	dynamicID := ssCreateDistGroup(t, pool, true, false)
	// static-ineligible: is_dynamic=false, usable_as_admin_scope=false, no scim_external_id
	ineligibleID := ssCreateDistGroup(t, pool, false, false)
	// scim-synced: scim_external_id IS NOT NULL → scimSynced=true → eligible even without usable_as_admin_scope
	scimID := ssCreateScimGroup(t, pool)

	req := ssNewRequest(t, "GET", "/admin/distribution-groups", "", ssSuperClaims(actorID))
	rec := httptest.NewRecorder()
	h.ListDistributionGroups(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	var got []directoryGroupResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	byID := make(map[int64]directoryGroupResponse)
	for _, g := range got {
		byID[g.ID] = g
	}

	// Eligible group: static, usable_as_admin_scope=true → scimSynced=false, usableAsAdminScope=true
	e, ok := byID[eligibleID]
	if !ok {
		t.Fatalf("eligible group (id=%d) missing from response", eligibleID)
	}
	if e.IsDynamic || !e.UsableAsAdminScope || e.ScimSynced {
		t.Errorf("eligible group flags wrong: isDynamic=%v usableAsAdminScope=%v scimSynced=%v", e.IsDynamic, e.UsableAsAdminScope, e.ScimSynced)
	}
	if e.MemberCount != 0 {
		t.Errorf("eligible group memberCount want 0, got %d", e.MemberCount)
	}

	// Dynamic group: is_dynamic=true → eligible in app must be false
	d, ok := byID[dynamicID]
	if !ok {
		t.Fatalf("dynamic group (id=%d) missing from response", dynamicID)
	}
	if !d.IsDynamic {
		t.Errorf("dynamic group: want isDynamic=true, got false")
	}

	// Static-ineligible: is_dynamic=false, usable_as_admin_scope=false, no scim_external_id
	i, ok := byID[ineligibleID]
	if !ok {
		t.Fatalf("ineligible group (id=%d) missing from response", ineligibleID)
	}
	if i.IsDynamic || i.UsableAsAdminScope || i.ScimSynced {
		t.Errorf("ineligible group flags wrong: isDynamic=%v usableAsAdminScope=%v scimSynced=%v", i.IsDynamic, i.UsableAsAdminScope, i.ScimSynced)
	}

	// SCIM-synced: scim_external_id IS NOT NULL → scimSynced=true; usable_as_admin_scope=false;
	// client-side groupEligible = !isDynamic && (scimSynced || usableAsAdminScope) = true.
	sc, ok := byID[scimID]
	if !ok {
		t.Fatalf("scim group (id=%d) missing from response", scimID)
	}
	if sc.IsDynamic || sc.UsableAsAdminScope || !sc.ScimSynced {
		t.Errorf("scim group flags wrong: isDynamic=%v usableAsAdminScope=%v scimSynced=%v (want isDynamic=false usableAsAdminScope=false scimSynced=true)",
			sc.IsDynamic, sc.UsableAsAdminScope, sc.ScimSynced)
	}
	eligible := !sc.IsDynamic && (sc.ScimSynced || sc.UsableAsAdminScope)
	if !eligible {
		t.Errorf("scim group should be eligible via scimSynced=true, but groupEligible logic returns false")
	}
}

// ── Tests: RemoveMember invalid memberType → 400 ──────────────────────────────

// TestGetScopeSet_MemberLabels: GetScopeSet returns a resolved `label` for each member type
// (ou → departments.name, group → mailboxes.display_name, user → users.email).
func TestGetScopeSet_MemberLabels(t *testing.T) {
	h, pool := newScopeSetsHandlerForTest(t)
	ctx := context.Background()
	actorID := seedSuperAdmin(t, pool)
	setID := seedScopeSet(t, pool, "labels")

	// Department member.
	suffix := rolesTestRandomSuffix(t)
	deptName := "LabelDept-" + suffix
	var deptID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO departments (name, path, ldap_ou) VALUES ($1, $2, $3) RETURNING id`,
		deptName, "/lbt-"+suffix, "ou=lbt-"+suffix).Scan(&deptID); err != nil {
		t.Fatalf("insert dept: %v", err)
	}
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM departments WHERE id = $1`, deptID) })

	// Group member (eligible static; label comes from mailboxes.display_name).
	groupID := ssCreateDistGroup(t, pool, false, true)
	var groupName string
	pool.QueryRow(ctx,
		`SELECT mb.display_name FROM distribution_groups dg JOIN mailboxes mb ON mb.id = dg.mailbox_id WHERE dg.id = $1`,
		groupID).Scan(&groupName)

	// User member.
	userID := ssCreateUser(t, pool)
	var userEmail string
	pool.QueryRow(ctx, `SELECT email FROM users WHERE id = $1`, userID).Scan(&userEmail)

	// Seed all three members directly.
	pool.Exec(ctx, `INSERT INTO admin_scope_set_members (set_id, member_type, member_id, added_by) VALUES ($1, 'ou', $2, $3)`, setID, deptID, actorID)
	pool.Exec(ctx, `INSERT INTO admin_scope_set_members (set_id, member_type, member_id, added_by) VALUES ($1, 'group', $2, $3)`, setID, groupID, actorID)
	pool.Exec(ctx, `INSERT INTO admin_scope_set_members (set_id, member_type, member_id, added_by) VALUES ($1, 'user', $2, $3)`, setID, userID, actorID)

	req := ssNewRequest(t, "GET", "/admin/scope-sets/"+ssItoa(setID), "", ssSuperClaims(actorID))
	req.SetPathValue("id", ssItoa(setID))
	rec := httptest.NewRecorder()
	h.GetScopeSet(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	var out struct {
		Members []struct {
			MemberType string  `json:"memberType"`
			MemberID   int64   `json:"memberId"`
			Label      *string `json:"label"`
		} `json:"members"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	byType := make(map[string]string)
	for _, m := range out.Members {
		if m.Label != nil {
			byType[m.MemberType] = *m.Label
		}
	}
	if byType["ou"] != deptName {
		t.Errorf("ou label: want %q, got %q", deptName, byType["ou"])
	}
	if byType["group"] != groupName {
		t.Errorf("group label: want %q, got %q", groupName, byType["group"])
	}
	if byType["user"] != userEmail {
		t.Errorf("user label: want %q, got %q", userEmail, byType["user"])
	}
}

// TestRemoveMember_InvalidMemberType_400: bogus memberType must return 400, not write an audit row.
func TestRemoveMember_InvalidMemberType_400(t *testing.T) {
	h, pool := newScopeSetsHandlerForTest(t)
	actorID := ssCreateUser(t, pool)
	setID := seedScopeSet(t, pool, "rmbad")

	req := ssNewRequest(t, "DELETE", "/admin/scope-sets/"+ssItoa(setID)+"/members/FORGERY/1", "", ssSuperClaims(actorID))
	req.SetPathValue("id", ssItoa(setID))
	req.SetPathValue("memberType", "FORGERY")
	req.SetPathValue("memberId", "1")
	rec := httptest.NewRecorder()
	h.RemoveMember(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid memberType, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	// No core audit row should have been written.
	var n int
	pool.QueryRow(context.Background(),
		`SELECT count(*) FROM admin_audit_log WHERE action='scope_set_member_remove' AND user_id=$1 AND target_id=$2`,
		actorID, setID).Scan(&n)
	if n != 0 {
		t.Errorf("want 0 scope_set_member_remove audit rows for invalid memberType, got %d", n)
	}
}
