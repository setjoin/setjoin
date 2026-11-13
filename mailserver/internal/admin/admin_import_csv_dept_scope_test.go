package admin

// Regression test for D-MAILSERVER-INTERNAL-ADMIN-F-007: CSV bulk import must
// enforce Rule B narrowing on department placement. Before the fix, an
// OU-narrowed users.create holder could provision users into ANY in-domain
// department outside their OU subtree — the only create/update path without
// the admin_scope_within guard AssignUser and DepartmentsHandler enforce.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

func TestImportCSV_DepartmentScope(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedOUTestState(t)
	h := NewUsersHandler(pool, pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger(), nil, "", "")

	// Both rows resolve as local (ou-test.example is seeded is_local=TRUE).
	// Row A lands in /eng — INSIDE the OU-scoped actor's reach. Row B points
	// at /sales — a sibling subtree OUTSIDE the actor's reach.
	suffix := mailboxRandomSuffix(t)
	emailIn := "csvdept-in-" + suffix + "@ou-test.example"
	emailOut := "csvdept-out-" + suffix + "@ou-test.example"
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `ALTER TABLE mailboxes DISABLE TRIGGER ALL`)
		pool.Exec(c, `DELETE FROM mailboxes WHERE email IN ($1, $2)`, emailIn, emailOut)
		pool.Exec(c, `ALTER TABLE mailboxes ENABLE TRIGGER ALL`)
		pool.Exec(c, `DELETE FROM users WHERE email IN ($1, $2)`, emailIn, emailOut)
	})

	csv := "email,password,department_id\n" +
		emailIn + ",Sup3r-Str0ng-Pw!," + strconv.FormatInt(st.engDeptID, 10) + "\n" +
		emailOut + ",Sup3r-Str0ng-Pw!," + strconv.FormatInt(st.salesDeptID, 10) + "\n"
	body, contentType := buildCSVUpload(t, csv)

	req := httptest.NewRequest(http.MethodPost, "/admin/users/import", body)
	req.Header.Set("Content-Type", contentType)
	// The /eng-OU-confined actor (97901) drives the import within its own domain.
	req = adminClaimsCtx(req, st.actorEngOUScoped, st.domainID)

	rec := httptest.NewRecorder()
	h.ImportCSV(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ImportCSV: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	var result struct {
		Created int `json:"created"`
		Failed  []struct {
			Row   int    `json:"row"`
			Email string `json:"email"`
			Error string `json:"error"`
		} `json:"failed"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// Partial success preserved: in-reach row created, out-of-reach row rejected.
	if result.Created != 1 {
		t.Errorf("ImportCSV created = %d, want 1 (only the in-reach department row)", result.Created)
	}
	var sawOutReject bool
	for _, f := range result.Failed {
		if f.Email == emailOut && f.Error == "department not within your administrative scope" {
			sawOutReject = true
		}
	}
	if !sawOutReject {
		t.Errorf("out-of-reach department row not rejected with the scope error; failed=%+v", result.Failed)
	}
}
