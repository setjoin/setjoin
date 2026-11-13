package admin

// TestAssignMember_OUScope_Persist verifies that AssignMember with scopeType="ou"
// persists scope_type and scope_id to admin_role_assignments.
//
// TestAssignMember_ScopeType_Group_400 verifies scopeType="group" → 400.
// TestAssignMember_ScopeType_User_400 verifies scopeType="user" → 400.
// TestAssignMember_ScopeType_OU_NilScopeID_400 verifies scopeType="ou" without scopeId → 400.
// TestAssignMember_SelfBroaden_403 verifies a scoped actor granting a broader OU → 403 (Rule A).
//
// CRITICAL: DB-backed — uses testsupport.OpenTestPool(t). MUST run, not skip.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/testsupport"
)

// TestAssignMember_OUScope_Persist asserts that AssignMember with
// scopeType="ou", scopeId=<dept> writes both columns to the DB row.
func TestAssignMember_OUScope_Persist(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedOUTestState(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())

	// actorGlobal has NULL scope (no narrowing) → passes admin_scope_within for
	// any OU grant. Target = userEng (in /eng, same OU the scope points at).
	body, _ := json.Marshal(map[string]any{
		"userId":    st.userEng,
		"scopeType": "ou",
		"scopeId":   st.engDeptID,
	})
	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/admin/roles/%d/members", st.roleGroupID),
		bytes.NewReader(body))
	req.SetPathValue("id", fmt.Sprintf("%d", st.roleGroupID))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID:      st.actorGlobal,
		Email:       "actor-glob@ou-test.example",
		IsAdmin:     true,
		Permissions: permissions.AllPermissions,
	}))

	w := httptest.NewRecorder()
	h.AssignMember(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("OUScope persist: want 201, got %d (body=%s)", w.Code, w.Body.String())
	}

	// Verify the columns were persisted.
	var gotType *string
	var gotID *int64
	err := pool.QueryRow(context.Background(),
		`SELECT scope_type, scope_id FROM admin_role_assignments
		 WHERE user_id = $1 AND role_group_id = $2`,
		st.userEng, st.roleGroupID).Scan(&gotType, &gotID)
	if err != nil {
		t.Fatalf("read assignment: %v", err)
	}
	if gotType == nil || *gotType != "ou" {
		t.Errorf("scope_type: want 'ou', got %v", gotType)
	}
	if gotID == nil || *gotID != st.engDeptID {
		t.Errorf("scope_id: want %d, got %v", st.engDeptID, gotID)
	}
}

// TestAssignMember_ScopeType_Group_400 asserts scopeType="group" → 400
// "scope type not yet supported".
func TestAssignMember_ScopeType_Group_400(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedOUTestState(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())

	body, _ := json.Marshal(map[string]any{
		"userId":    st.userEng,
		"scopeType": "group",
		"scopeId":   st.engDeptID,
	})
	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/admin/roles/%d/members", st.roleGroupID),
		bytes.NewReader(body))
	req.SetPathValue("id", fmt.Sprintf("%d", st.roleGroupID))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID:      st.actorGlobal,
		Email:       "actor-glob@ou-test.example",
		IsAdmin:     true,
		Permissions: permissions.AllPermissions,
	}))

	w := httptest.NewRecorder()
	h.AssignMember(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("scopeType=group: want 400, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// TestAssignMember_ScopeType_User_400 asserts scopeType="user" → 400.
func TestAssignMember_ScopeType_User_400(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedOUTestState(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())

	body, _ := json.Marshal(map[string]any{
		"userId":    st.userEng,
		"scopeType": "user",
		"scopeId":   st.userEng,
	})
	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/admin/roles/%d/members", st.roleGroupID),
		bytes.NewReader(body))
	req.SetPathValue("id", fmt.Sprintf("%d", st.roleGroupID))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID:      st.actorGlobal,
		Email:       "actor-glob@ou-test.example",
		IsAdmin:     true,
		Permissions: permissions.AllPermissions,
	}))

	w := httptest.NewRecorder()
	h.AssignMember(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("scopeType=user: want 400, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// TestAssignMember_ScopeType_OU_NilScopeID_400 asserts scopeType="ou" without
// scopeId → 400.
func TestAssignMember_ScopeType_OU_NilScopeID_400(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedOUTestState(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())

	body, _ := json.Marshal(map[string]any{
		"userId":    st.userEng,
		"scopeType": "ou",
		// no scopeId
	})
	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/admin/roles/%d/members", st.roleGroupID),
		bytes.NewReader(body))
	req.SetPathValue("id", fmt.Sprintf("%d", st.roleGroupID))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID:      st.actorGlobal,
		Email:       "actor-glob@ou-test.example",
		IsAdmin:     true,
		Permissions: permissions.AllPermissions,
	}))

	w := httptest.NewRecorder()
	h.AssignMember(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("ou+nil scopeId: want 400, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// TestAssignMember_SelfBroaden_403 verifies that an OU-scoped actor cannot grant
// a broader scope than their own (Rule A scope arm). The /eng-scoped actor
// (97901) attempts to assign a NULL-scope grant (no scopeType/scopeId) — which
// is domain-wide and broader than /eng → 403.
func TestAssignMember_SelfBroaden_403(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedOUTestState(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())

	// OU-scoped actor (actorEngOUScoped, scope_type='ou', scope_id=/eng) grants
	// with no scope (NULL = domain-wide). admin_scope_within returns FALSE → 403.
	body, _ := json.Marshal(map[string]any{
		"userId": st.userEngBackend,
		// no scopeType / scopeId → null scope grant (broadening)
	})
	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/admin/roles/%d/members", st.roleGroupID),
		bytes.NewReader(body))
	req.SetPathValue("id", fmt.Sprintf("%d", st.roleGroupID))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID:      st.actorEngOUScoped,
		Email:       "actor-eng@ou-test.example",
		IsAdmin:     true,
		Permissions: permissions.AllPermissions,
	}))

	w := httptest.NewRecorder()
	h.AssignMember(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("self-broaden: want 403, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// TestBulkAssign_OUScope_NilScopeID_400 verifies bulk assign with scopeType="ou"
// but no scopeId → 400 (V040: scopeId is required when scopeType is 'ou').
func TestBulkAssign_OUScope_NilScopeID_400(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedOUTestState(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())

	body, _ := json.Marshal(map[string]any{
		"userIds":   []int64{st.userEng},
		"scopeType": "ou",
		// no scopeId
	})
	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/admin/roles/%d/members:bulk", st.roleGroupID),
		bytes.NewReader(body))
	req.SetPathValue("id", fmt.Sprintf("%d", st.roleGroupID))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID:      st.actorGlobal,
		Email:       "actor-glob@ou-test.example",
		IsAdmin:     true,
		Permissions: permissions.AllPermissions,
	}))

	w := httptest.NewRecorder()
	h.BulkAssign(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("bulk scopeType=ou + nil scopeId: want 400, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// TestBulkAssign_OUScope verifies V040: bulk assign with scopeType="ou" + valid scopeId
// enqueues successfully and persists both scope columns to bulk_role_jobs.
func TestBulkAssign_OUScope(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedOUTestState(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())

	body, _ := json.Marshal(map[string]any{
		"userIds":   []int64{st.userEng},
		"scopeType": "ou",
		"scopeId":   st.engDeptID,
	})
	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/admin/roles/%d/members:bulk", st.roleGroupID),
		bytes.NewReader(body))
	req.SetPathValue("id", fmt.Sprintf("%d", st.roleGroupID))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID:      st.actorGlobal,
		Email:       "actor-glob@ou-test.example",
		IsAdmin:     true,
		Permissions: permissions.AllPermissions,
	}))

	w := httptest.NewRecorder()
	h.BulkAssign(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("bulk ou scope: want 202, got %d (body=%s)", w.Code, w.Body.String())
	}

	var resp map[string]int64
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	jobID := resp["jobId"]
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM bulk_role_jobs WHERE id = $1`, jobID)
	})

	var gotType *string
	var gotID *int64
	err := pool.QueryRow(context.Background(),
		`SELECT scope_type, scope_id FROM bulk_role_jobs WHERE id = $1`, jobID,
	).Scan(&gotType, &gotID)
	if err != nil {
		t.Fatalf("read bulk_role_jobs: %v", err)
	}
	if gotType == nil || *gotType != "ou" {
		t.Errorf("scope_type: want 'ou', got %v", gotType)
	}
	if gotID == nil || *gotID != st.engDeptID {
		t.Errorf("scope_id: want %d, got %v", st.engDeptID, gotID)
	}
}

// TestBulkAssign_ScopeID_NoScopeType_400 verifies bulk assign with scopeId set but
// no scopeType → 400 (parity with single-assign; prevents V040 DB CHECK 500).
func TestBulkAssign_ScopeID_NoScopeType_400(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedOUTestState(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())

	body, _ := json.Marshal(map[string]any{
		"userIds": []int64{st.userEng},
		"scopeId": st.engDeptID,
		// no scopeType
	})
	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/admin/roles/%d/members:bulk", st.roleGroupID),
		bytes.NewReader(body))
	req.SetPathValue("id", fmt.Sprintf("%d", st.roleGroupID))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID:      st.actorGlobal,
		Email:       "actor-glob@ou-test.example",
		IsAdmin:     true,
		Permissions: permissions.AllPermissions,
	}))

	w := httptest.NewRecorder()
	h.BulkAssign(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("bulk scopeId+no scopeType: want 400, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// TestBulkRevoke_IgnoresScope verifies that a bulk REVOKE with scopeType="ou"
// and a valid scopeId is accepted (202) and persists NULL/NULL scope in the
// enqueued job row (scope is an assign-only concept; revoke drops it silently,
// matching how expiresAt is dropped for revoke).
func TestBulkRevoke_IgnoresScope(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedOUTestState(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())

	body, _ := json.Marshal(map[string]any{
		"userIds":   []int64{st.userEng},
		"scopeType": "ou",
		"scopeId":   st.engDeptID,
	})
	req := httptest.NewRequest(http.MethodDelete,
		fmt.Sprintf("/admin/roles/%d/members:bulk", st.roleGroupID),
		bytes.NewReader(body))
	req.SetPathValue("id", fmt.Sprintf("%d", st.roleGroupID))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID:      st.actorGlobal,
		Email:       "actor-glob@ou-test.example",
		IsAdmin:     true,
		Permissions: permissions.AllPermissions,
	}))

	w := httptest.NewRecorder()
	h.BulkRevoke(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("revoke with scope: want 202, got %d (body=%s)", w.Code, w.Body.String())
	}

	var resp map[string]int64
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	jobID := resp["jobId"]
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM bulk_role_jobs WHERE id = $1`, jobID)
	})

	var gotType *string
	var gotID *int64
	err := pool.QueryRow(context.Background(),
		`SELECT scope_type, scope_id FROM bulk_role_jobs WHERE id = $1`, jobID,
	).Scan(&gotType, &gotID)
	if err != nil {
		t.Fatalf("read bulk_role_jobs: %v", err)
	}
	if gotType != nil {
		t.Errorf("scope_type: want NULL (revoke drops scope), got %v", gotType)
	}
	if gotID != nil {
		t.Errorf("scope_id: want NULL (revoke drops scope), got %v", gotID)
	}
}

// TestBulkRevoke_MalformedScope_NoError verifies that a bulk REVOKE with
// scopeType="ou" but no scopeId returns 202, not 500 from the V040 DB CHECK.
// Pre-fix: the stray scope was passed to the INSERT and the paired-null CHECK
// on bulk_role_jobs fired. Post-fix: revoke zeroes both scope locals → NULL/NULL
// reaches the DB → CHECK passes.
func TestBulkRevoke_MalformedScope_NoError(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedOUTestState(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())

	body, _ := json.Marshal(map[string]any{
		"userIds":   []int64{st.userEng},
		"scopeType": "ou",
		// no scopeId — malformed pair that pre-fix 500s via DB CHECK
	})
	req := httptest.NewRequest(http.MethodDelete,
		fmt.Sprintf("/admin/roles/%d/members:bulk", st.roleGroupID),
		bytes.NewReader(body))
	req.SetPathValue("id", fmt.Sprintf("%d", st.roleGroupID))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID:      st.actorGlobal,
		Email:       "actor-glob@ou-test.example",
		IsAdmin:     true,
		Permissions: permissions.AllPermissions,
	}))

	w := httptest.NewRecorder()
	h.BulkRevoke(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("revoke malformed scope: want 202, got %d (body=%s)", w.Code, w.Body.String())
	}

	var resp map[string]int64
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	jobID := resp["jobId"]
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM bulk_role_jobs WHERE id = $1`, jobID)
	})

	// Scope columns must be NULL (not the stray client-sent scopeType).
	var gotType *string
	var gotID *int64
	err := pool.QueryRow(context.Background(),
		`SELECT scope_type, scope_id FROM bulk_role_jobs WHERE id = $1`, jobID,
	).Scan(&gotType, &gotID)
	if err != nil {
		t.Fatalf("read bulk_role_jobs: %v", err)
	}
	if gotType != nil {
		t.Errorf("scope_type: want NULL (revoke ignores scope), got %v", gotType)
	}
	if gotID != nil {
		t.Errorf("scope_id: want NULL (revoke ignores scope), got %v", gotID)
	}
}

// TestBulkAssign_ScopeType_Group_400 verifies bulk assign with scopeType="group" → 400.
func TestBulkAssign_ScopeType_Group_400(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedOUTestState(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())

	body, _ := json.Marshal(map[string]any{
		"userIds":   []int64{st.userEng},
		"scopeType": "group",
		"scopeId":   st.engDeptID,
	})
	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/admin/roles/%d/members:bulk", st.roleGroupID),
		bytes.NewReader(body))
	req.SetPathValue("id", fmt.Sprintf("%d", st.roleGroupID))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID:      st.actorGlobal,
		Email:       "actor-glob@ou-test.example",
		IsAdmin:     true,
		Permissions: permissions.AllPermissions,
	}))

	w := httptest.NewRecorder()
	h.BulkAssign(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("bulk scopeType=group: want 400, got %d (body=%s)", w.Code, w.Body.String())
	}
}
