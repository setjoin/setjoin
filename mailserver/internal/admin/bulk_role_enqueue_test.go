package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/testsupport"
)

// bulkActorCtx builds a context with an actor carrying the given permissions.
func bulkActorCtx(ctx context.Context, actorID int64, perms []string) context.Context {
	return auth.ContextWithUser(ctx, &auth.Claims{UserID: actorID, IsAdmin: true, Permissions: perms})
}

// TestBulkAssign_RuleA_MissingPerm_403 verifies that an actor missing one of
// the role's permissions gets 403 and NO job row is created.
func TestBulkAssign_RuleA_MissingPerm_403(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())

	// "Help Desk" role grants help_desk.manage; actor only holds audit.read.
	roleID := builtinRoleID(t, pool, "Help Desk")
	actorID := seedUser(t, pool)

	// Count jobs before.
	var before int
	pool.QueryRow(context.Background(), `SELECT count(*) FROM bulk_role_jobs`).Scan(&before)

	body := `{"userIds":[1,2,3]}`
	req := httptest.NewRequest("POST", fmt.Sprintf("/admin/roles/%d/members:bulk", roleID), strings.NewReader(body))
	req.SetPathValue("id", fmt.Sprintf("%d", roleID))
	req = req.WithContext(bulkActorCtx(req.Context(), actorID, []string{"audit.read"}))
	w := httptest.NewRecorder()
	h.BulkAssign(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("Rule A: want 403, got %d (body=%s)", w.Code, w.Body.String())
	}

	// No job row created.
	var after int
	pool.QueryRow(context.Background(), `SELECT count(*) FROM bulk_role_jobs`).Scan(&after)
	if after != before {
		t.Errorf("Rule A 403: expected no new job row; before=%d after=%d", before, after)
	}
}

// TestBulkAssign_EmptyUserIds_400 verifies empty userIds returns 400.
func TestBulkAssign_EmptyUserIds_400(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())

	roleID := builtinRoleID(t, pool, "Help Desk")
	actorID := seedUser(t, pool)

	body := `{"userIds":[]}`
	req := httptest.NewRequest("POST", fmt.Sprintf("/admin/roles/%d/members:bulk", roleID), strings.NewReader(body))
	req.SetPathValue("id", fmt.Sprintf("%d", roleID))
	req = req.WithContext(bulkActorCtx(req.Context(), actorID, permissions.AllPermissions))
	w := httptest.NewRecorder()
	h.BulkAssign(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("empty userIds: want 400, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// TestBulkAssign_TooManyUserIds_400 verifies >1000 userIds returns 400.
func TestBulkAssign_TooManyUserIds_400(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())

	roleID := builtinRoleID(t, pool, "Help Desk")
	actorID := seedUser(t, pool)

	ids := make([]string, 1001)
	for i := range ids {
		ids[i] = fmt.Sprintf("%d", i+1)
	}
	body := `{"userIds":[` + strings.Join(ids, ",") + `]}`
	req := httptest.NewRequest("POST", fmt.Sprintf("/admin/roles/%d/members:bulk", roleID), strings.NewReader(body))
	req.SetPathValue("id", fmt.Sprintf("%d", roleID))
	req = req.WithContext(bulkActorCtx(req.Context(), actorID, permissions.AllPermissions))
	w := httptest.NewRecorder()
	h.BulkAssign(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf(">1000 userIds: want 400, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// TestBulkAssign_PastExpiresAt_400 verifies a past expiresAt returns 400.
func TestBulkAssign_PastExpiresAt_400(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())

	roleID := builtinRoleID(t, pool, "Help Desk")
	actorID := seedUser(t, pool)

	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	body := fmt.Sprintf(`{"userIds":[1],"expiresAt":%q}`, past)
	req := httptest.NewRequest("POST", fmt.Sprintf("/admin/roles/%d/members:bulk", roleID), strings.NewReader(body))
	req.SetPathValue("id", fmt.Sprintf("%d", roleID))
	req = req.WithContext(bulkActorCtx(req.Context(), actorID, permissions.AllPermissions))
	w := httptest.NewRecorder()
	h.BulkAssign(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("past expiresAt: want 400, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// TestBulkAssign_Valid_202_CreatesJob verifies a valid assign creates a queued
// bulk_role_jobs row with the correct op, total, status, and actor_id.
func TestBulkAssign_Valid_202_CreatesJob(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())

	roleID := builtinRoleID(t, pool, "Help Desk")
	actorID := seedUser(t, pool)

	// userIds 1,2,3 — none need to exist (bulk enqueue validates actor/role only).
	body := `{"userIds":[1,2,3]}`
	req := httptest.NewRequest("POST", fmt.Sprintf("/admin/roles/%d/members:bulk", roleID), strings.NewReader(body))
	req.SetPathValue("id", fmt.Sprintf("%d", roleID))
	req = req.WithContext(bulkActorCtx(req.Context(), actorID, permissions.AllPermissions))
	w := httptest.NewRecorder()
	h.BulkAssign(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("valid assign: want 202, got %d (body=%s)", w.Code, w.Body.String())
	}

	var resp map[string]int64
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	jobID, ok := resp["jobId"]
	if !ok || jobID == 0 {
		t.Fatalf("response missing jobId: %s", w.Body.String())
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM bulk_role_jobs WHERE id = $1`, jobID)
	})

	// Verify the DB row.
	var op, status string
	var total int
	var actorIDGot int64
	err := pool.QueryRow(context.Background(),
		`SELECT op, status, total, actor_id FROM bulk_role_jobs WHERE id = $1`, jobID,
	).Scan(&op, &status, &total, &actorIDGot)
	if err != nil {
		t.Fatalf("read bulk_role_jobs: %v", err)
	}
	if op != "assign" {
		t.Errorf("op: want assign, got %q", op)
	}
	if status != "queued" {
		t.Errorf("status: want queued, got %q", status)
	}
	if total != 3 {
		t.Errorf("total: want 3, got %d", total)
	}
	if actorIDGot != actorID {
		t.Errorf("actor_id: want %d, got %d", actorID, actorIDGot)
	}
}

// TestBulkAssign_Dedup verifies duplicate userIds are deduped before insert.
func TestBulkAssign_Dedup(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())

	roleID := builtinRoleID(t, pool, "Help Desk")
	actorID := seedUser(t, pool)

	// 5 ids but only 3 unique: 1,2,3.
	body := `{"userIds":[1,2,3,2,1]}`
	req := httptest.NewRequest("POST", fmt.Sprintf("/admin/roles/%d/members:bulk", roleID), strings.NewReader(body))
	req.SetPathValue("id", fmt.Sprintf("%d", roleID))
	req = req.WithContext(bulkActorCtx(req.Context(), actorID, permissions.AllPermissions))
	w := httptest.NewRecorder()
	h.BulkAssign(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("dedup assign: want 202, got %d (body=%s)", w.Code, w.Body.String())
	}

	var resp map[string]int64
	json.Unmarshal(w.Body.Bytes(), &resp)
	jobID := resp["jobId"]
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM bulk_role_jobs WHERE id = $1`, jobID)
	})

	var total int
	pool.QueryRow(context.Background(), `SELECT total FROM bulk_role_jobs WHERE id = $1`, jobID).Scan(&total)
	if total != 3 {
		t.Errorf("dedup: want total=3, got %d", total)
	}
}

// TestBulkRevoke_Valid_202_CreatesJob verifies BulkRevoke enqueues a 'revoke' job.
func TestBulkRevoke_Valid_202_CreatesJob(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())

	roleID := builtinRoleID(t, pool, "Help Desk")
	actorID := seedUser(t, pool)

	body := `{"userIds":[10,20]}`
	req := httptest.NewRequest("DELETE", fmt.Sprintf("/admin/roles/%d/members:bulk", roleID), strings.NewReader(body))
	req.SetPathValue("id", fmt.Sprintf("%d", roleID))
	req = req.WithContext(bulkActorCtx(req.Context(), actorID, permissions.AllPermissions))
	w := httptest.NewRecorder()
	h.BulkRevoke(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("valid revoke: want 202, got %d (body=%s)", w.Code, w.Body.String())
	}

	var resp map[string]int64
	json.Unmarshal(w.Body.Bytes(), &resp)
	jobID := resp["jobId"]
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM bulk_role_jobs WHERE id = $1`, jobID)
	})

	var op string
	var expiresAt *time.Time
	pool.QueryRow(context.Background(),
		`SELECT op, expires_at FROM bulk_role_jobs WHERE id = $1`, jobID,
	).Scan(&op, &expiresAt)
	if op != "revoke" {
		t.Errorf("revoke op: want revoke, got %q", op)
	}
	if expiresAt != nil {
		t.Errorf("revoke expires_at: want NULL, got %v", expiresAt)
	}
}
