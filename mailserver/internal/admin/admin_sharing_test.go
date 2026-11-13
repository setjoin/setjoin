package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

// shCreateAdmin seeds a user holding a REAL sharing.manage role assignment —
// the write reducers check admin_effective_authority (DB rows), not claims.
func shCreateAdmin(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	userID := ssCreateUser(t, pool)
	suffix := rolesTestRandomSuffix(t)
	var rgID int64
	err := pool.QueryRow(context.Background(),
		`INSERT INTO admin_role_groups (name, permissions)
		 VALUES ($1, ARRAY['sharing.manage','sharing.read']) RETURNING id`,
		"sh-admin-"+suffix).Scan(&rgID)
	if err != nil {
		t.Fatalf("shCreateAdmin role group: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by)
		 VALUES ($1, $2, $1)`, userID, rgID); err != nil {
		t.Fatalf("shCreateAdmin assignment: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM admin_role_assignments WHERE role_group_id = $1`, rgID)
		pool.Exec(c, `DELETE FROM admin_role_groups WHERE id = $1`, rgID)
	})
	return userID
}

func shClaims(userID int64, perms ...string) *auth.Claims {
	return &auth.Claims{UserID: userID, IsAdmin: true, Permissions: perms}
}

func TestSharingDefaults_RequiresManagePerm(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewSharingHandler(pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())
	actorID := ssCreateUser(t, pool)

	var perms []string
	for _, p := range permissions.AllPermissions {
		if p != permissions.PermSharingManage {
			perms = append(perms, p)
		}
	}
	noPerm := shClaims(actorID, perms...)

	for _, tc := range []struct {
		method, path, body string
		handler            http.HandlerFunc
		idParam            string
	}{
		{"POST", "/admin/sharing/defaults", `{"ownerScope":"org","ownerRef":1,"audience":"everyone","audienceRef":1,"level":"freebusy"}`, h.CreateDefault, ""},
		{"DELETE", "/admin/sharing/defaults/1", "", h.DeleteDefault, "1"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		req = req.WithContext(auth.ContextWithUser(req.Context(), noPerm))
		if tc.idParam != "" {
			req.SetPathValue("id", tc.idParam)
		}
		rec := httptest.NewRecorder()
		tc.handler(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s: want 403, got %d (%s)", tc.method, tc.path, rec.Code, rec.Body.String())
		}
	}
}

func TestSharingReads_RequireViewPerm(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewSharingHandler(pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())
	actorID := ssCreateUser(t, pool)
	noPerm := shClaims(actorID)

	for _, tc := range []struct {
		name    string
		path    string
		handler http.HandlerFunc
		idParam string
	}{
		{"list", "/admin/sharing/defaults", h.ListDefaults, ""},
		{"oversight", "/admin/sharing/users/1", h.UserOversight, "1"},
		{"audit", "/admin/sharing/audit", h.Audit, ""},
	} {
		req := httptest.NewRequest("GET", tc.path, nil)
		req = req.WithContext(auth.ContextWithUser(req.Context(), noPerm))
		if tc.idParam != "" {
			req.SetPathValue("id", tc.idParam)
		}
		rec := httptest.NewRecorder()
		tc.handler(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: want 403, got %d (%s)", tc.name, rec.Code, rec.Body.String())
		}
	}
}

func TestSharingDefaults_CRUDFlow(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewSharingHandler(pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())
	adminID := shCreateAdmin(t, pool)
	claims := shClaims(adminID, permissions.PermSharingManage)

	var domainID int64
	if err := pool.QueryRow(context.Background(),
		`SELECT domain_id FROM users WHERE id = $1`, adminID).Scan(&domainID); err != nil {
		t.Fatalf("resolve domain: %v", err)
	}

	// create (org default: freebusy for everyone in the domain)
	body := fmt.Sprintf(`{"ownerScope":"org","ownerRef":%d,"audience":"everyone","audienceRef":%d,"level":"freebusy"}`, domainID, domainID)
	req := httptest.NewRequest("POST", "/admin/sharing/defaults", strings.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	rec := httptest.NewRecorder()
	h.CreateDefault(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("create: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var created struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.ID == 0 {
		t.Fatalf("create response: %v (%s)", err, rec.Body.String())
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM sharing_defaults WHERE id = $1`, created.ID)
	})

	// invalid level → 400 (BZ117 through the wire contract)
	req = httptest.NewRequest("POST", "/admin/sharing/defaults",
		strings.NewReader(fmt.Sprintf(`{"ownerScope":"org","ownerRef":%d,"audience":"everyone","audienceRef":%d,"level":"admin"}`, domainID, domainID)))
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	rec = httptest.NewRecorder()
	h.CreateDefault(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid level: want 400, got %d (%s)", rec.Code, rec.Body.String())
	}

	// list contains the row
	req = httptest.NewRequest("GET", "/admin/sharing/defaults", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	rec = httptest.NewRecorder()
	h.ListDefaults(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var listed []struct {
		ID    int64  `json:"id"`
		Level string `json:"level"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("list decode: %v", err)
	}
	found := false
	for _, row := range listed {
		if row.ID == created.ID && row.Level == "freebusy" {
			found = true
		}
	}
	if !found {
		t.Fatalf("created row %d not in list: %s", created.ID, rec.Body.String())
	}

	// audit view has the set action
	req = httptest.NewRequest("GET", fmt.Sprintf("/admin/sharing/audit?user_id=%d", adminID), nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	rec = httptest.NewRecorder()
	h.Audit(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "sharing_default_set") {
		t.Fatalf("audit: want 200 with sharing_default_set, got %d (%s)", rec.Code, rec.Body.String())
	}

	// delete
	req = httptest.NewRequest("DELETE", "/admin/sharing/defaults/x", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	req.SetPathValue("id", fmt.Sprint(created.ID))
	rec = httptest.NewRecorder()
	h.DeleteDefault(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: want 204, got %d (%s)", rec.Code, rec.Body.String())
	}

	// delete again → 404 (BZ114)
	req = httptest.NewRequest("DELETE", "/admin/sharing/defaults/x", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	req.SetPathValue("id", fmt.Sprint(created.ID))
	rec = httptest.NewRecorder()
	h.DeleteDefault(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("re-delete: want 404, got %d (%s)", rec.Code, rec.Body.String())
	}
}

func TestSharingUserOversight_DomainScope404(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewSharingHandler(pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())
	adminID := ssCreateUser(t, pool)
	targetID := ssCreateUser(t, pool)
	claims := shClaims(adminID, permissions.PermSharingRead)

	var targetDomain int64
	if err := pool.QueryRow(context.Background(),
		`SELECT domain_id FROM users WHERE id = $1`, targetID).Scan(&targetDomain); err != nil {
		t.Fatalf("resolve target domain: %v", err)
	}

	// global admin (scope 0) → 200
	req := httptest.NewRequest("GET", "/admin/sharing/users/x", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	req.SetPathValue("id", fmt.Sprint(targetID))
	rec := httptest.NewRecorder()
	h.UserOversight(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("global oversight: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}

	// admin scoped to a DIFFERENT domain → 404 (indistinguishable, D7)
	req = httptest.NewRequest("GET", "/admin/sharing/users/x", nil)
	ctx := auth.ContextWithUser(req.Context(), claims)
	ctx = middleware.ContextWithDomainScope(ctx, targetDomain+999999)
	req = req.WithContext(ctx)
	req.SetPathValue("id", fmt.Sprint(targetID))
	rec = httptest.NewRecorder()
	h.UserOversight(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("out-of-scope oversight: want 404, got %d (%s)", rec.Code, rec.Body.String())
	}
}
