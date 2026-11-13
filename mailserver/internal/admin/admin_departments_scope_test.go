package admin

// TestAssignUser_ReachCheck is a DB-backed TDD test verifying that OU-scoped
// admins cannot re-assign users to departments when the target user is outside
// their OU reach, and that a global actor succeeds.
//
// Uses seedOUTestState (admin_roles_ou_test.go):
//   actorEngOUScoped (97901): OU-scoped to /eng (dept 97901)
//   actorGlobal      (97902): unconfined (null scope)
//   userSales        (97905): in /sales — out of reach for eng-scoped actor
//   salesDeptID      (97903): the /sales department

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/testsupport"
)

// TestAssignUser_DeptScope verifies the admin_scope_within dept-path check in AssignUser.
//
// Three cases:
//
//	(a) OU-scoped actor reaches the target user (/eng) but the target dept is /sales
//	    (outside the actor's OU) → 403 (exercises the admin_scope_within dept path).
//	(b) domain-scoped actor (not OU-confined) assigns an in-domain user to an
//	    in-domain dept → 204 (proves the over-block fix: old nil-domain arg fires
//	    the domain arm and wrongly returns FALSE for any domain-scoped actor).
//	(c) OU-scoped actor assigns a reachable in-scope user to their own OU dept → 204.
//
// Seed note: user 97906 is the domain-scoped actor, inserted locally; all other
// IDs come from seedOUTestState (admin_roles_ou_test.go, 97xxx range).
func TestAssignUser_DeptScope(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedOUTestState(t)
	h := NewDepartmentsHandler(pool, testsupport.TestLogger())

	// Seed a domain-scoped actor: assignment with domain_override=97901, scope_type=NULL.
	// admin_effective_authority → scope=97901 (non-null), is_unconfined=TRUE.
	bgCtx := context.Background()
	_, err := pool.Exec(bgCtx, `
		INSERT INTO public.users (id, username, domain_id, department_id, email, display_name, enabled)
		  OVERRIDING SYSTEM VALUE VALUES
		  (97906, 'ou-actor-domain', 97901, NULL, 'actor-domain@ou-test.example', 'ActorDomain', TRUE)
		ON CONFLICT (id) DO UPDATE SET username = EXCLUDED.username`)
	if err != nil {
		t.Fatalf("seed domain actor user: %v", err)
	}
	_, err = pool.Exec(bgCtx, `
		INSERT INTO public.admin_role_assignments
		  (user_id, role_group_id, scope_type, scope_id, domain_override, granted_by)
		  VALUES (97906, $1, NULL, NULL, 97901, 97906)
		ON CONFLICT (user_id, role_group_id)
		  DO UPDATE SET scope_type=NULL, scope_id=NULL, domain_override=97901`,
		st.roleGroupID)
	if err != nil {
		t.Fatalf("seed domain actor assignment: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM public.admin_role_assignments WHERE user_id = 97906`) //nolint:errcheck
		pool.Exec(c, `DELETE FROM public.users WHERE id = 97906`)                       //nolint:errcheck
	})

	// ── (a) OU-scoped actor, reachable user, dept OUTSIDE scope → 403 ────────
	// actorEngOUScoped reaches userEng (both in /eng) but salesDeptID (/sales)
	// is outside the actor's OU → admin_scope_within returns FALSE.
	body_a, _ := json.Marshal(map[string]any{"userId": st.userEng, "departmentId": st.salesDeptID})
	req_a := httptest.NewRequest(http.MethodPost, "/admin/departments/assign-user", strings.NewReader(string(body_a)))
	req_a = req_a.WithContext(auth.ContextWithUser(req_a.Context(), &auth.Claims{
		UserID: st.actorEngOUScoped, IsAdmin: true, Permissions: permissions.AllPermissions,
	}))
	w_a := httptest.NewRecorder()
	h.AssignUser(w_a, req_a)
	if w_a.Code != http.StatusForbidden {
		t.Errorf("(a) OU-scoped → reachable user, out-of-scope dept: want 403, got %d (body=%s)", w_a.Code, w_a.Body.String())
	}

	// ── (b) domain-scoped actor, in-domain user, in-domain dept → 204 ────────
	// Proves the over-block fix: passing nil p_grant_domain wrongly triggers the
	// domain arm for any domain-scoped actor. With the fix, the actor's own domain
	// is passed → arm passes → is_unconfined=TRUE → RETURN TRUE.
	body_b, _ := json.Marshal(map[string]any{"userId": st.userEng, "departmentId": st.engDeptID})
	req_b := httptest.NewRequest(http.MethodPost, "/admin/departments/assign-user", strings.NewReader(string(body_b)))
	bCtx := auth.ContextWithUser(req_b.Context(), &auth.Claims{
		UserID: int64(97906), IsAdmin: true, Permissions: permissions.AllPermissions,
	})
	bCtx = middleware.ContextWithDomainScope(bCtx, int64(st.domainID))
	req_b = req_b.WithContext(bCtx)
	w_b := httptest.NewRecorder()
	h.AssignUser(w_b, req_b)
	if w_b.Code != http.StatusNoContent {
		t.Errorf("(b) domain-scoped → in-domain user, in-domain dept: want 204, got %d (body=%s)", w_b.Code, w_b.Body.String())
	}

	// ── (c) OU-scoped actor, in-reach user, in-scope dept → 204 ──────────────
	// actorEngOUScoped assigns userEng to engDeptID (/eng) — both reach and
	// scope satisfied → 204.
	body_c, _ := json.Marshal(map[string]any{"userId": st.userEng, "departmentId": st.engDeptID})
	req_c := httptest.NewRequest(http.MethodPost, "/admin/departments/assign-user", strings.NewReader(string(body_c)))
	req_c = req_c.WithContext(auth.ContextWithUser(req_c.Context(), &auth.Claims{
		UserID: st.actorEngOUScoped, IsAdmin: true, Permissions: permissions.AllPermissions,
	}))
	w_c := httptest.NewRecorder()
	h.AssignUser(w_c, req_c)
	if w_c.Code != http.StatusNoContent {
		t.Errorf("(c) OU-scoped → in-reach user, in-scope dept: want 204, got %d (body=%s)", w_c.Code, w_c.Body.String())
	}
}

// TestDepartmentsUpdate_ScopeCheck is the regression test for the privilege-
// escalation bug: Update accepted an arbitrary target department id and
// arbitrary parentId with ZERO scope check, so an OU-scoped admin could PUT
// {parentId: <their own dept>} on a department outside their scope, moving
// it (and its users) under their subtree — flipping admin_can_reach TRUE for
// every user in that department.
//
//	(a) OU-scoped actor (/eng) PUTs salesDeptID with {parentId: engDeptID} →
//	    403, and /sales's path is verified UNCHANGED afterward (no partial
//	    move happened before the 403).
//	(b) global/unconfined actor performs the identical PUT → 2xx (204),
//	    proving the guard isn't over-broad.
func TestDepartmentsUpdate_ScopeCheck(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedOUTestState(t)
	h := NewDepartmentsHandler(pool, testsupport.TestLogger())
	ctx := context.Background()

	var pathBefore string
	if err := pool.QueryRow(ctx, `SELECT path FROM departments WHERE id = $1`, st.salesDeptID).Scan(&pathBefore); err != nil {
		t.Fatalf("read sales path before: %v", err)
	}

	// (a) OU-scoped actor tries to move /sales under their own /eng subtree.
	bodyA, _ := json.Marshal(map[string]any{"parentId": st.engDeptID})
	reqA := httptest.NewRequest(http.MethodPut, "/admin/departments/"+itoa(st.salesDeptID), strings.NewReader(string(bodyA)))
	reqA.SetPathValue("id", itoa(st.salesDeptID))
	reqA = reqA.WithContext(auth.ContextWithUser(reqA.Context(), &auth.Claims{
		UserID: st.actorEngOUScoped, IsAdmin: true, Permissions: permissions.AllPermissions,
	}))
	wA := httptest.NewRecorder()
	h.Update(wA, reqA)
	if wA.Code != http.StatusForbidden {
		t.Errorf("(a) OU-scoped move of out-of-scope dept: want 403, got %d (body=%s)", wA.Code, wA.Body.String())
	}

	var pathAfter string
	if err := pool.QueryRow(ctx, `SELECT path FROM departments WHERE id = $1`, st.salesDeptID).Scan(&pathAfter); err != nil {
		t.Fatalf("read sales path after: %v", err)
	}
	if pathAfter != pathBefore {
		t.Errorf("(a) /sales path changed despite 403: before=%q after=%q", pathBefore, pathAfter)
	}

	// (b) Global actor performs the identical move → succeeds.
	bodyB, _ := json.Marshal(map[string]any{"parentId": st.engDeptID})
	reqB := httptest.NewRequest(http.MethodPut, "/admin/departments/"+itoa(st.salesDeptID), strings.NewReader(string(bodyB)))
	reqB.SetPathValue("id", itoa(st.salesDeptID))
	reqB = reqB.WithContext(auth.ContextWithUser(reqB.Context(), &auth.Claims{
		UserID: st.actorGlobal, IsAdmin: true, Permissions: permissions.AllPermissions,
	}))
	wB := httptest.NewRecorder()
	h.Update(wB, reqB)
	if wB.Code < 200 || wB.Code >= 300 {
		t.Errorf("(b) global actor move: want 2xx, got %d (body=%s)", wB.Code, wB.Body.String())
	}
}

// TestDepartmentsCreate_ScopeCheck verifies Create requires admin_scope_within
// on the parent OU: an OU-scoped actor cannot create a department under a
// parent outside their scope.
func TestDepartmentsCreate_ScopeCheck(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedOUTestState(t)
	h := NewDepartmentsHandler(pool, testsupport.TestLogger())

	body, _ := json.Marshal(map[string]any{"name": "Rogue", "parentId": st.salesDeptID})
	req := httptest.NewRequest(http.MethodPost, "/admin/departments", strings.NewReader(string(body)))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID: st.actorEngOUScoped, IsAdmin: true, Permissions: permissions.AllPermissions,
	}))
	w := httptest.NewRecorder()
	h.Create(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("Create under out-of-scope parent: want 403, got %d (body=%s)", w.Code, w.Body.String())
	}

	var exists bool
	pool.QueryRow(context.Background(),
		`SELECT EXISTS(SELECT 1 FROM departments WHERE name = 'Rogue' AND path LIKE '/sales%')`).Scan(&exists) //nolint:errcheck
	if exists {
		t.Errorf("Create under out-of-scope parent: department was created despite 403")
		pool.Exec(context.Background(), `DELETE FROM departments WHERE name = 'Rogue'`) //nolint:errcheck
	}
}

// TestDepartmentsDelete_ScopeCheck verifies Delete requires admin_scope_within
// on the department being removed: an OU-scoped actor cannot delete a
// department outside their scope.
func TestDepartmentsDelete_ScopeCheck(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedOUTestState(t)
	h := NewDepartmentsHandler(pool, testsupport.TestLogger())

	req := httptest.NewRequest(http.MethodDelete, "/admin/departments/"+itoa(st.salesDeptID), nil)
	req.SetPathValue("id", itoa(st.salesDeptID))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID: st.actorEngOUScoped, IsAdmin: true, Permissions: permissions.AllPermissions,
	}))
	w := httptest.NewRecorder()
	h.Delete(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("Delete of out-of-scope dept: want 403, got %d (body=%s)", w.Code, w.Body.String())
	}

	var exists bool
	if err := pool.QueryRow(context.Background(),
		`SELECT EXISTS(SELECT 1 FROM departments WHERE id = $1)`, st.salesDeptID).Scan(&exists); err != nil {
		t.Fatalf("check sales dept still exists: %v", err)
	}
	if !exists {
		t.Errorf("Delete of out-of-scope dept: department was actually deleted despite 403")
	}
}

func itoa(id int64) string {
	return strconv.FormatInt(id, 10)
}

func TestAssignUser_ReachCheck(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedOUTestState(t)
	h := NewDepartmentsHandler(pool, testsupport.TestLogger())

	// ── Case 1: OU-scoped actor → user in /sales → 403 (out of reach) ───────
	body1, _ := json.Marshal(map[string]any{"userId": st.userSales, "departmentId": st.salesDeptID})
	req1 := httptest.NewRequest(http.MethodPost, "/admin/departments/assign-user", strings.NewReader(string(body1)))
	req1 = req1.WithContext(auth.ContextWithUser(req1.Context(), &auth.Claims{
		UserID: st.actorEngOUScoped, IsAdmin: true, Permissions: permissions.AllPermissions,
	}))
	w1 := httptest.NewRecorder()
	h.AssignUser(w1, req1)
	if w1.Code != http.StatusForbidden {
		t.Errorf("Case 1 (OU-scoped → /sales user): want 403, got %d (body=%s)", w1.Code, w1.Body.String())
	}

	// ── Case 2: global actor → user in /sales → 204 (unconfined) ─────────────
	// Assigning userSales to the same department it's already in (idempotent UPDATE).
	body2, _ := json.Marshal(map[string]any{"userId": st.userSales, "departmentId": st.salesDeptID})
	req2 := httptest.NewRequest(http.MethodPost, "/admin/departments/assign-user", strings.NewReader(string(body2)))
	req2 = req2.WithContext(auth.ContextWithUser(req2.Context(), &auth.Claims{
		UserID: st.actorGlobal, IsAdmin: true, Permissions: permissions.AllPermissions,
	}))
	w2 := httptest.NewRecorder()
	h.AssignUser(w2, req2)
	if w2.Code != http.StatusNoContent {
		t.Errorf("Case 2 (global → /sales user): want 204, got %d (body=%s)", w2.Code, w2.Body.String())
	}
}
