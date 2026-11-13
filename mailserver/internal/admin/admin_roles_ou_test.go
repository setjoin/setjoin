package admin

// TestRemoveMember_OUScope is a DB-backed TDD test for OU scope enforcement on RemoveMember.
//
// Seed: two domains, departments /eng and /eng/backend and /sales, an actor
// with a role assignment scoped to OU /eng, and three target users placed in each
// department. Asserts:
//
//   - /eng-scoped actor → /sales target: blocked (404)
//   - /eng-scoped actor → /eng/backend target: allowed (204)
//   - NULL-scope (global) actor → /sales target: allowed (regression — reaches everyone)
//
// CRITICAL: this test MUST run against a real DB (DB_DSN). It uses
// testsupport.OpenTestPool which fails-closed when DB_DSN is absent AND
// REQUIRE_DB is set (CI). A t.Skip is only acceptable in local dev without Postgres.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/testsupport"
)

// ouTestState holds the seeded IDs for OU scope tests.
type ouTestState struct {
	domainID    int64
	engDeptID   int64 // /eng
	backDeptID  int64 // /eng/backend
	salesDeptID int64 // /sales
	roleGroupID int64 // any role the actor can hold and the membership covers

	actorEngOUScoped int64 // actor with OU-scoped assignment (/eng)
	actorGlobal      int64 // actor with global (NULL-scope) assignment
	userEng          int64 // user in /eng
	userEngBackend   int64 // user in /eng/backend (descendant)
	userSales        int64 // user in /sales (sibling — out of reach)
}

// seedOUTestState inserts the minimal rows needed for OU scope tests and registers
// cleanup. Uses fixed IDs in the 97xxx range (distinct from other test files).
func seedOUTestState(t *testing.T) *ouTestState {
	t.Helper()
	ctx := context.Background()
	pool := testsupport.OpenTestPool(t)

	// Use OVERRIDING SYSTEM VALUE to control IDs so cleanup is deterministic.
	// Any conflict means a prior run leaked rows — cleanup at end of test handles it.
	_, err := pool.Exec(ctx, `
		INSERT INTO public.domains (id, name, is_local) OVERRIDING SYSTEM VALUE VALUES
		  (97901, 'ou-test.example', TRUE)
		ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name`)
	if err != nil {
		t.Fatalf("seed domain: %v", err)
	}

	_, err = pool.Exec(ctx, `
		INSERT INTO public.departments (id, name, path, ldap_ou) OVERRIDING SYSTEM VALUE VALUES
		  (97901, 'Engineering',        '/eng',         'ou=eng,dc=ou-test,dc=example'),
		  (97902, 'Engineering Backend','/eng/backend', 'ou=back,ou=eng,dc=ou-test,dc=example'),
		  (97903, 'Sales',              '/sales',       'ou=sales,dc=ou-test,dc=example')
		ON CONFLICT (id) DO UPDATE SET path = EXCLUDED.path`)
	if err != nil {
		t.Fatalf("seed departments: %v", err)
	}

	_, err = pool.Exec(ctx, `
		INSERT INTO public.users (id, username, domain_id, department_id, email, display_name, enabled)
		  OVERRIDING SYSTEM VALUE VALUES
		  (97901, 'ou-actor-eng',  97901, NULL,  'actor-eng@ou-test.example',     'ActorEng',     TRUE),
		  (97902, 'ou-actor-glob', 97901, NULL,  'actor-glob@ou-test.example',    'ActorGlob',    TRUE),
		  (97903, 'ou-user-eng',   97901, 97901, 'user-eng@ou-test.example',      'UserEng',      TRUE),
		  (97904, 'ou-user-back',  97901, 97902, 'user-backend@ou-test.example',  'UserBackend',  TRUE),
		  (97905, 'ou-user-sales', 97901, 97903, 'user-sales@ou-test.example',    'UserSales',    TRUE)
		ON CONFLICT (id) DO UPDATE SET username = EXCLUDED.username, department_id = EXCLUDED.department_id`)
	if err != nil {
		t.Fatalf("seed users: %v", err)
	}

	// A role group that the actors can hold as their authority. Use the existing
	// "Help Desk" built-in role (permissions.AllPermissions are injected in claims
	// anyway; this just needs a valid role_group_id for the assignment FK).
	// We look it up dynamically to avoid depending on the built-in's exact ID.
	var helpDeskID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM admin_role_groups WHERE name = 'Help Desk' LIMIT 1`).Scan(&helpDeskID); err != nil {
		t.Fatalf("lookup Help Desk role: %v", err)
	}

	// Actor assignments:
	//   ou-actor-eng: role = Help Desk, scope_type='ou', scope_id=97901 (/eng)
	//   ou-actor-glob: role = Help Desk, scope_type=NULL (global)
	_, err = pool.Exec(ctx, `
		INSERT INTO public.admin_role_assignments (user_id, role_group_id, scope_type, scope_id, granted_by)
		  VALUES (97901, $1, 'ou', 97901, 97901)
		ON CONFLICT (user_id, role_group_id) DO UPDATE SET scope_type='ou', scope_id=97901`,
		helpDeskID)
	if err != nil {
		t.Fatalf("seed eng-actor assignment: %v", err)
	}

	_, err = pool.Exec(ctx, `
		INSERT INTO public.admin_role_assignments (user_id, role_group_id, scope_type, scope_id, granted_by)
		  VALUES (97902, $1, NULL, NULL, 97902)
		ON CONFLICT (user_id, role_group_id) DO UPDATE SET scope_type=NULL, scope_id=NULL`,
		helpDeskID)
	if err != nil {
		t.Fatalf("seed glob-actor assignment: %v", err)
	}

	// Assign targets to Help Desk WITH OU scope so their ou_reach is narrower-than or equal-to
	// the actor's (admin_protection_check requires actor to not be outranked by target).
	// /eng/backend ⊆ /eng → actor can manage backend user.
	// /sales ⊄ /eng → actor CANNOT manage sales user (admin_can_reach fires first → 404).
	_, err = pool.Exec(ctx, `
		INSERT INTO public.admin_role_assignments (user_id, role_group_id, scope_type, scope_id, granted_by)
		  VALUES (97904, $1, 'ou', 97902, 97901),
		         (97905, $1, 'ou', 97903, 97901)
		ON CONFLICT (user_id, role_group_id) DO UPDATE SET scope_type=EXCLUDED.scope_type, scope_id=EXCLUDED.scope_id`,
		helpDeskID)
	if err != nil {
		t.Fatalf("seed target assignments: %v", err)
	}

	t.Cleanup(func() {
		c := context.Background()
		// Clean assignments (security-critical: determines admin_can_reach results).
		pool.Exec(c, `DELETE FROM public.admin_role_assignments WHERE user_id IN (97901,97902,97903,97904,97905)`)
		// Users with audit log entries cannot be deleted (audit_log FK is ON DELETE SET NULL
		// but the append-only trigger blocks the cascade UPDATE). Leave them; ON CONFLICT DO
		// UPDATE in the seed handles reruns. ponytail: these rows accumulate but are isolated
		// by fixed IDs and never interfere with other tests.
		pool.Exec(c, `DELETE FROM public.users WHERE id IN (97901,97902,97903,97904,97905)`) //nolint:errcheck // may fail if audit rows exist; that's OK
		pool.Exec(c, `DELETE FROM public.departments WHERE id IN (97901,97902,97903)`)
		pool.Exec(c, `DELETE FROM public.domains WHERE id = 97901`)
	})

	return &ouTestState{
		domainID:         97901,
		engDeptID:        97901,
		backDeptID:       97902,
		salesDeptID:      97903,
		roleGroupID:      helpDeskID,
		actorEngOUScoped: 97901,
		actorGlobal:      97902,
		userEng:          97903,
		userEngBackend:   97904,
		userSales:        97905,
	}
}

// TestRemoveMember_OUScope verifies OU scope enforcement in RemoveMember.
func TestRemoveMember_OUScope(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedOUTestState(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())

	// ── Case 1: /eng-scoped actor → /sales target → 404 (out of reach) ──────
	req := httptest.NewRequest(http.MethodDelete, "/admin/roles/members", nil)
	req.SetPathValue("id", strconv.FormatInt(st.roleGroupID, 10))
	req.SetPathValue("userId", strconv.FormatInt(st.userSales, 10))
	ctx := auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID:      st.actorEngOUScoped,
		Email:       "actor-eng@ou-test.example",
		IsAdmin:     true,
		Permissions: permissions.AllPermissions,
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	h.RemoveMember(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("Case 1 (/eng-scoped → /sales): want 404, got %d (body=%s)", w.Code, w.Body.String())
	}

	// ── Case 2: /eng-scoped actor → /eng/backend target → 204 (allowed) ─────
	// Re-seed the target assignment (Case 1 may have tried to delete it; if it was
	// blocked by the scope check it should still be there — this is safe to re-insert).
	pool.Exec(context.Background(), `
		INSERT INTO public.admin_role_assignments (user_id, role_group_id, granted_by)
		  VALUES ($1, $2, $3)
		ON CONFLICT (user_id, role_group_id) DO NOTHING`,
		st.userEngBackend, st.roleGroupID, st.actorEngOUScoped)

	req2 := httptest.NewRequest(http.MethodDelete, "/admin/roles/members", nil)
	req2.SetPathValue("id", strconv.FormatInt(st.roleGroupID, 10))
	req2.SetPathValue("userId", strconv.FormatInt(st.userEngBackend, 10))
	ctx2 := auth.ContextWithUser(req2.Context(), &auth.Claims{
		UserID:      st.actorEngOUScoped,
		Email:       "actor-eng@ou-test.example",
		IsAdmin:     true,
		Permissions: permissions.AllPermissions,
	})
	req2 = req2.WithContext(ctx2)

	w2 := httptest.NewRecorder()
	h.RemoveMember(w2, req2)
	if w2.Code != http.StatusNoContent {
		t.Errorf("Case 2 (/eng-scoped → /eng/backend): want 204, got %d (body=%s)", w2.Code, w2.Body.String())
	}

	// ── Case 3: NULL-scope (global) actor → /sales target → 204 (regression) ─
	// Re-seed the /sales user assignment (Case 1 blocked it so it's still there).
	pool.Exec(context.Background(), `
		INSERT INTO public.admin_role_assignments (user_id, role_group_id, granted_by)
		  VALUES ($1, $2, $3)
		ON CONFLICT (user_id, role_group_id) DO NOTHING`,
		st.userSales, st.roleGroupID, st.actorGlobal)

	req3 := httptest.NewRequest(http.MethodDelete, "/admin/roles/members", nil)
	req3.SetPathValue("id", strconv.FormatInt(st.roleGroupID, 10))
	req3.SetPathValue("userId", strconv.FormatInt(st.userSales, 10))
	ctx3 := auth.ContextWithUser(req3.Context(), &auth.Claims{
		UserID:      st.actorGlobal,
		Email:       "actor-glob@ou-test.example",
		IsAdmin:     true,
		Permissions: permissions.AllPermissions,
	})
	req3 = req3.WithContext(ctx3)

	w3 := httptest.NewRecorder()
	h.RemoveMember(w3, req3)
	if w3.Code != http.StatusNoContent {
		t.Errorf("Case 3 (global → /sales): want 204, got %d (body=%s)", w3.Code, w3.Body.String())
	}
}

// TestRemoveMember_StackedDomainOU verifies that a domain+OU stacked actor is
// OU-confined even when the JWT carries a domain scope (scope > 0 branch).
//
// The gap: prior code only enforced domain_id=scope in the scope>0 branch and
// skipped admin_can_reach entirely — so a domain+OU admin could operate on any
// user in their domain, ignoring the OU narrowing. This test proves the fix.
//
// Actor: user 97901 — JWT domain scope = 97901 AND DB assignment scope_type='ou', scope_id=97901 (/eng).
// Targets:
//   - domain 97901, /sales dept (97903) → BLOCKED (in domain, outside /eng)
//   - domain 97901, /eng/backend dept (97902) → ALLOWED (in domain, inside /eng)
func TestRemoveMember_StackedDomainOU(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedOUTestState(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())

	domainID := st.domainID // 97901

	// ── Case 1: stacked actor → /sales target → 404 (in domain but outside /eng) ──
	// Re-seed the sales-user assignment so it can be the RemoveMember target.
	pool.Exec(context.Background(), `
		INSERT INTO public.admin_role_assignments (user_id, role_group_id, granted_by)
		  VALUES ($1, $2, $3)
		ON CONFLICT (user_id, role_group_id) DO NOTHING`,
		st.userSales, st.roleGroupID, st.actorEngOUScoped)

	req1 := httptest.NewRequest(http.MethodDelete, "/admin/roles/members", nil)
	req1.SetPathValue("id", strconv.FormatInt(st.roleGroupID, 10))
	req1.SetPathValue("userId", strconv.FormatInt(st.userSales, 10))
	// Inject JWT domain scope AND OU assignment. DomainScope in claims triggers scope>0 branch.
	scopeVal := domainID
	ctx1 := auth.ContextWithUser(req1.Context(), &auth.Claims{
		UserID:      st.actorEngOUScoped,
		Email:       "actor-eng@ou-test.example",
		IsAdmin:     true,
		Permissions: permissions.AllPermissions,
		DomainScope: &scopeVal,
	})
	ctx1 = middleware.ContextWithDomainScope(ctx1, domainID)
	req1 = req1.WithContext(ctx1)

	w1 := httptest.NewRecorder()
	h.RemoveMember(w1, req1)
	if w1.Code != http.StatusNotFound {
		t.Errorf("Stacked Case 1 (domain+OU/eng → /sales): want 404, got %d (body=%s)", w1.Code, w1.Body.String())
	}

	// ── Case 2: stacked actor → /eng/backend target → 204 (in domain AND inside /eng) ──
	pool.Exec(context.Background(), `
		INSERT INTO public.admin_role_assignments (user_id, role_group_id, granted_by)
		  VALUES ($1, $2, $3)
		ON CONFLICT (user_id, role_group_id) DO NOTHING`,
		st.userEngBackend, st.roleGroupID, st.actorEngOUScoped)

	req2 := httptest.NewRequest(http.MethodDelete, "/admin/roles/members", nil)
	req2.SetPathValue("id", strconv.FormatInt(st.roleGroupID, 10))
	req2.SetPathValue("userId", strconv.FormatInt(st.userEngBackend, 10))
	ctx2 := auth.ContextWithUser(req2.Context(), &auth.Claims{
		UserID:      st.actorEngOUScoped,
		Email:       "actor-eng@ou-test.example",
		IsAdmin:     true,
		Permissions: permissions.AllPermissions,
		DomainScope: &scopeVal,
	})
	ctx2 = middleware.ContextWithDomainScope(ctx2, domainID)
	req2 = req2.WithContext(ctx2)

	w2 := httptest.NewRecorder()
	h.RemoveMember(w2, req2)
	if w2.Code != http.StatusNoContent {
		t.Errorf("Stacked Case 2 (domain+OU/eng → /eng/backend): want 204, got %d (body=%s)", w2.Code, w2.Body.String())
	}
}
