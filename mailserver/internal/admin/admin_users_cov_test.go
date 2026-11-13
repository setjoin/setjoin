package admin

// Final-wave changed-lines coverage for admin_users.go ImportCSV: the
// department scope-check DB-fault arm (D-MAILSERVER-INTERNAL-ADMIN-F-007
// guard) — a faulting admin_scope_within read fails exactly that row
// ("department scope check failed"), preserving partial-success semantics
// instead of creating the user or aborting the import.
//
// Note on AddAlias's non-ValidationError 400 arm: it is unreachable through
// the current identity seam — identity.ValidateAndCanonicalizeEmail only ever
// returns fmt-wrapped *validate.ValidationError values, which errors.As always
// unwraps to — so only the ImportCSV arm is exercised here.

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

// TestImportCSV_DeptScopeCheckDBFailureFailsRow drives the scope-check query
// with a dead (canceled) request context: the row lands in `failed` with the
// dedicated scope-check message and nothing is provisioned.
func TestImportCSV_DeptScopeCheckDBFailureFailsRow(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewUsersHandler(pool, pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger(), nil, "", "")
	actor := seedUser(t, pool)

	email := "csvdept-fault-" + mailboxRandomSuffix(t) + "@rolestest.example"
	csv := "email,password,department_id\n" +
		email + ",Sup3r-Str0ng-Pw!," + strconv.FormatInt(424242424, 10) + "\n"
	body, contentType := buildCSVUpload(t, csv)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodPost, "/admin/users/import", body)
	req.Header.Set("Content-Type", contentType)
	req = req.WithContext(ctx)
	req = adminClaimsCtx(req, actor, 0)

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
	if result.Created != 0 {
		t.Fatalf("a row whose scope check faulted must not be provisioned, created=%d", result.Created)
	}
	if len(result.Failed) != 1 || result.Failed[0].Email != email ||
		result.Failed[0].Error != "department scope check failed" {
		t.Fatalf("expected the department-scope-check-failed row error, got %+v", result.Failed)
	}
}
