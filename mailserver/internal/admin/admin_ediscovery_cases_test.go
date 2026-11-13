package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/testsupport"
)

// TestEDiscoveryCaseCRUD drives the mutating case handlers (Create/Get/Update/
// Close) against the real DB, plus the DeleteCase NOT-EXISTS-searches guard.
// These handlers previously had only JSON-struct unit coverage, never the
// handler write path.
func TestEDiscoveryCaseCRUD(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	h := NewEDiscoveryCaseHandler(pool, testsupport.TestLogger())

	userID := ssCreateUser(t, pool)
	authCtx := auth.ContextWithUser(ctx, &auth.Claims{UserID: userID, IsAdmin: true})

	// Track any case rows created so cleanup does not leak across runs.
	cleanupCase := func(id int64) {
		t.Cleanup(func() {
			c := context.Background()
			pool.Exec(c, `DELETE FROM ediscovery_searches WHERE case_id = $1`, id) //nolint:errcheck
			pool.Exec(c, `DELETE FROM ediscovery_cases WHERE id = $1`, id)         //nolint:errcheck
		})
	}

	// Create.
	createReq := httptest.NewRequest(http.MethodPost, "/admin/ediscovery/cases",
		strings.NewReader(`{"name":"Case Alpha","description":"initial"}`)).WithContext(authCtx)
	createRec := httptest.NewRecorder()
	h.CreateCase(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("CreateCase: want 201, got %d (%s)", createRec.Code, createRec.Body.String())
	}
	var created struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil || created.ID == 0 {
		t.Fatalf("CreateCase response: %v (%s)", err, createRec.Body.String())
	}
	cleanupCase(created.ID)
	idStr := strconv.FormatInt(created.ID, 10)

	// Missing name -> 400.
	badReq := httptest.NewRequest(http.MethodPost, "/admin/ediscovery/cases",
		strings.NewReader(`{"description":"no name"}`)).WithContext(authCtx)
	badRec := httptest.NewRecorder()
	h.CreateCase(badRec, badReq)
	if badRec.Code != http.StatusBadRequest {
		t.Errorf("CreateCase missing name: want 400, got %d", badRec.Code)
	}

	// Get.
	getReq := httptest.NewRequest(http.MethodGet, "/admin/ediscovery/cases/"+idStr, nil).WithContext(authCtx)
	getReq.SetPathValue("id", idStr)
	getRec := httptest.NewRecorder()
	h.GetCase(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GetCase: want 200, got %d (%s)", getRec.Code, getRec.Body.String())
	}
	var getBody struct {
		Case ediscoveryCase `json:"case"`
	}
	if err := json.Unmarshal(getRec.Body.Bytes(), &getBody); err != nil {
		t.Fatalf("decode GetCase: %v", err)
	}
	if getBody.Case.Name != "Case Alpha" || getBody.Case.Status != "active" || getBody.Case.CreatedBy != userID {
		t.Errorf("GetCase shape wrong: %+v", getBody.Case)
	}

	// Update.
	updReq := httptest.NewRequest(http.MethodPut, "/admin/ediscovery/cases/"+idStr,
		strings.NewReader(`{"name":"Case Alpha Renamed"}`)).WithContext(authCtx)
	updReq.SetPathValue("id", idStr)
	updRec := httptest.NewRecorder()
	h.UpdateCase(updRec, updReq)
	if updRec.Code != http.StatusNoContent {
		t.Fatalf("UpdateCase: want 204, got %d (%s)", updRec.Code, updRec.Body.String())
	}
	var gotName string
	if err := pool.QueryRow(ctx, `SELECT name FROM ediscovery_cases WHERE id = $1`, created.ID).Scan(&gotName); err != nil {
		t.Fatalf("read case name: %v", err)
	}
	if gotName != "Case Alpha Renamed" {
		t.Errorf("update did not persist: name = %q", gotName)
	}

	// Close.
	closeReq := httptest.NewRequest(http.MethodPost, "/admin/ediscovery/cases/"+idStr+"/close",
		strings.NewReader(`{"reason":"done"}`)).WithContext(authCtx)
	closeReq.SetPathValue("id", idStr)
	closeRec := httptest.NewRecorder()
	h.CloseCase(closeRec, closeReq)
	if closeRec.Code != http.StatusNoContent {
		t.Fatalf("CloseCase: want 204, got %d (%s)", closeRec.Code, closeRec.Body.String())
	}
	var status string
	var closedBy *int64
	if err := pool.QueryRow(ctx, `SELECT status, closed_by FROM ediscovery_cases WHERE id = $1`, created.ID).Scan(&status, &closedBy); err != nil {
		t.Fatalf("read case status: %v", err)
	}
	if status != "closed" || closedBy == nil || *closedBy != userID {
		t.Errorf("close did not persist: status=%q closedBy=%v", status, closedBy)
	}

	// DeleteCase: blocked when a search references the case, allowed otherwise.
	var refCaseID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO ediscovery_cases (name, created_by) VALUES ('Referenced Case', $1) RETURNING id`,
		userID).Scan(&refCaseID); err != nil {
		t.Fatalf("seed referenced case: %v", err)
	}
	cleanupCase(refCaseID)
	if _, err := pool.Exec(ctx,
		`INSERT INTO ediscovery_searches (name, created_by, query, case_id)
		 VALUES ('s1', $1, '{}'::jsonb, $2)`, userID, refCaseID); err != nil {
		t.Fatalf("seed search: %v", err)
	}

	refIDStr := strconv.FormatInt(refCaseID, 10)
	delBlockedReq := httptest.NewRequest(http.MethodDelete, "/admin/ediscovery/cases/"+refIDStr, nil).WithContext(authCtx)
	delBlockedReq.SetPathValue("id", refIDStr)
	delBlockedRec := httptest.NewRecorder()
	h.DeleteCase(delBlockedRec, delBlockedReq)
	if delBlockedRec.Code != http.StatusConflict {
		t.Errorf("DeleteCase with search: want 409, got %d", delBlockedRec.Code)
	}

	// Remove the search, delete now allowed.
	if _, err := pool.Exec(ctx, `DELETE FROM ediscovery_searches WHERE case_id = $1`, refCaseID); err != nil {
		t.Fatalf("delete search: %v", err)
	}
	delReq := httptest.NewRequest(http.MethodDelete, "/admin/ediscovery/cases/"+refIDStr, nil).WithContext(authCtx)
	delReq.SetPathValue("id", refIDStr)
	delRec := httptest.NewRecorder()
	h.DeleteCase(delRec, delReq)
	if delRec.Code != http.StatusNoContent {
		t.Errorf("DeleteCase clean: want 204, got %d (%s)", delRec.Code, delRec.Body.String())
	}
}
