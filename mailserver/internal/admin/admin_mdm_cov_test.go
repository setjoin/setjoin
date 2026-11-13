package admin

// Coverage suite for the changed MDM policy endpoints the handler/perms/scope
// suites do not reach: the DB-backed bodies of ListPolicies, CreatePolicy,
// UpdatePolicy, DeletePolicy (including the last-global-policy 409 guard and
// the V254 FORCE-RLS GUC pairing) and ReorderPolicies, plus their checked
// error branches against a shadow schema.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// mdmPolicyReq builds a policy-endpoint request with admin claims.
func mdmPolicyReq(method, target, policyID, body string) *http.Request {
	r := httptest.NewRequest(method, target, stringReader(body))
	if policyID != "" {
		r.SetPathValue("id", policyID)
	}
	return adminClaimsCtx(r, 1, 0)
}

// mdmCovDeletePolicyRow removes a policy row the test created.
func mdmCovDeletePolicyRow(t *testing.T, pool *pgxpool.Pool, id int64) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `DELETE FROM mdm_policies WHERE id = $1`, id); err != nil {
		t.Errorf("mdm cov cleanup policy %d: %v", id, err)
	}
}

// mdmCovQuiesceEnabledGlobals temporarily disables every pre-existing enabled
// global policy so the last-global-policy guard is deterministic on the shared
// test database, registering restoration.
func mdmCovQuiesceEnabledGlobals(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	rows, err := pool.Query(ctx, `SELECT id FROM mdm_policies WHERE scope_type = 'global' AND enabled`)
	if err != nil {
		t.Fatalf("scan enabled globals: %v", err)
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	for _, id := range ids {
		if _, err := pool.Exec(ctx, `UPDATE mdm_policies SET enabled = FALSE WHERE id = $1`, id); err != nil {
			t.Fatalf("quiesce global %d: %v", id, err)
		}
	}
	if len(ids) > 0 {
		t.Cleanup(func() {
			c := context.Background()
			for _, id := range ids {
				_, _ = pool.Exec(c, `UPDATE mdm_policies SET enabled = TRUE WHERE id = $1`, id)
			}
		})
	}
}

// TestMDMPolicies_CRUD_Lifecycle drives the full policy lifecycle against the
// real database: the last-global-policy 409 guard, create (201) → list (row
// present) → update (row changed) → update unknown id (404) → delete (row
// gone) → delete unknown id (404), and the reorder endpoint's priority
// assignment.
func TestMDMPolicies_CRUD_Lifecycle(t *testing.T) {
	pool := mailboxTestPool(t)
	h := NewMDMHandler(pool, mailboxTestLogger())
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	mdmCovQuiesceEnabledGlobals(t, pool)

	// ── Last-global guard: a global target is refused while the enabled
	// global count is <= 1 (zero here — the guard reads <=1, not ==1). The
	// row must survive the refused delete.
	var disabledID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO mdm_policies (name, scope_type, enabled) VALUES ($1, 'global', FALSE) RETURNING id`,
		"mdm-cov-last-global-"+suffix,
	).Scan(&disabledID); err != nil {
		t.Fatalf("seed target global policy: %v", err)
	}
	t.Cleanup(func() { mdmCovDeletePolicyRow(t, pool, disabledID) })

	rec := httptest.NewRecorder()
	h.DeletePolicy(rec, mdmPolicyReq(http.MethodDelete, "/admin/mdm/policies/"+fmt.Sprint(disabledID), fmt.Sprint(disabledID), ""))
	if rec.Code != http.StatusConflict {
		t.Fatalf("delete global with enabled count 0: want 409, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM mdm_policies WHERE id = $1`, disabledID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("409 delete disturbed the row: n=%d err=%v", n, err)
	}

	// ── Create two enabled globals: with two enabled globals the same target
	// class deletes fine (the guard is about the LAST global).
	rec = httptest.NewRecorder()
	h.CreatePolicy(rec, mdmPolicyReq(http.MethodPost, "/admin/mdm/policies", "",
		fmt.Sprintf(`{"name":"mdm-cov-a-%s","description":"first","priority":5,"scope_type":"global","enabled":true,"passcode_min_length":8}`, suffix)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create policy A: want 201, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var createdA struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &createdA); err != nil {
		t.Fatalf("decode create A: %v", err)
	}
	t.Cleanup(func() { mdmCovDeletePolicyRow(t, pool, createdA.ID) })

	rec = httptest.NewRecorder()
	h.CreatePolicy(rec, mdmPolicyReq(http.MethodPost, "/admin/mdm/policies", "",
		fmt.Sprintf(`{"name":"mdm-cov-b-%s","description":"second","priority":7,"scope_type":"global","enabled":true}`, suffix)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create policy B: want 201, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var createdB struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &createdB); err != nil {
		t.Fatalf("decode create B: %v", err)
	}
	t.Cleanup(func() { mdmCovDeletePolicyRow(t, pool, createdB.ID) })

	// Create validation: missing name is a 400 before any DB work.
	rec = httptest.NewRecorder()
	h.CreatePolicy(rec, mdmPolicyReq(http.MethodPost, "/admin/mdm/policies", "", `{"description":"no name"}`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create without name: want 400, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	// ── List: both created rows are projected with their policy fields.
	rec = httptest.NewRecorder()
	h.ListPolicies(rec, mdmPolicyReq(http.MethodGet, "/admin/mdm/policies", "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("list policies: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var listed struct {
		Policies []struct {
			ID          int64  `json:"id"`
			Name        string `json:"name"`
			Description string `json:"description"`
			Priority    int    `json:"priority"`
			ScopeType   string `json:"scope_type"`
			Enabled     bool   `json:"enabled"`
		} `json:"policies"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	foundA := false
	for _, p := range listed.Policies {
		if p.ID == createdA.ID {
			foundA = true
			if p.Description != "first" || p.Priority != 5 || p.ScopeType != "global" || !p.Enabled {
				t.Errorf("listed policy A projection drifted: %+v", p)
			}
		}
	}
	if !foundA {
		t.Errorf("created policy A missing from listing (%d rows)", listed.Total)
	}

	// ── Update: patch A's name; verify persisted.
	rec = httptest.NewRecorder()
	h.UpdatePolicy(rec, mdmPolicyReq(http.MethodPut, "/admin/mdm/policies/"+fmt.Sprint(createdA.ID),
		fmt.Sprint(createdA.ID), fmt.Sprintf(`{"name":"mdm-cov-a2-%s"}`, suffix)))
	if rec.Code != http.StatusOK {
		t.Fatalf("update policy A: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var name string
	if err := pool.QueryRow(ctx, `SELECT name FROM mdm_policies WHERE id = $1`, createdA.ID).Scan(&name); err != nil {
		t.Fatalf("read updated policy: %v", err)
	}
	if name != "mdm-cov-a2-"+suffix {
		t.Errorf("update did not persist: name=%q", name)
	}

	// Update unknown id → 404 over the zero-rows result.
	rec = httptest.NewRecorder()
	h.UpdatePolicy(rec, mdmPolicyReq(http.MethodPut, "/admin/mdm/policies/999999", "999999", `{"name":"ghost"}`))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("update unknown policy: want 404, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	// ── Reorder: B first (highest priority), then A.
	rec = httptest.NewRecorder()
	h.ReorderPolicies(rec, mdmPolicyReq(http.MethodPut, "/admin/mdm/policies/reorder", "",
		fmt.Sprintf(`{"ids":[%d,%d]}`, createdB.ID, createdA.ID)))
	if rec.Code != http.StatusOK {
		t.Fatalf("reorder: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var prioB, prioA int
	if err := pool.QueryRow(ctx, `SELECT priority FROM mdm_policies WHERE id = $1`, createdB.ID).Scan(&prioB); err != nil {
		t.Fatalf("read B priority: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT priority FROM mdm_policies WHERE id = $1`, createdA.ID).Scan(&prioA); err != nil {
		t.Fatalf("read A priority: %v", err)
	}
	if prioB != 2 || prioA != 1 {
		t.Errorf("reorder priorities = (B:%d, A:%d), want (2, 1)", prioB, prioA)
	}

	// ── Delete: with two enabled globals the delete of A succeeds.
	rec = httptest.NewRecorder()
	h.DeletePolicy(rec, mdmPolicyReq(http.MethodDelete, "/admin/mdm/policies/"+fmt.Sprint(createdA.ID), fmt.Sprint(createdA.ID), ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("delete policy A: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM mdm_policies WHERE id = $1`, createdA.ID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("delete did not persist: n=%d err=%v", n, err)
	}

	// Delete unknown id → 404.
	rec = httptest.NewRecorder()
	h.DeletePolicy(rec, mdmPolicyReq(http.MethodDelete, "/admin/mdm/policies/999999", "999999", ""))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("delete unknown policy: want 404, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	// Reorder guards: empty ids and invalid JSON are 400.
	rec = httptest.NewRecorder()
	h.ReorderPolicies(rec, mdmPolicyReq(http.MethodPut, "/admin/mdm/policies/reorder", "", `{"ids":[]}`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("reorder empty ids: want 400, got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ReorderPolicies(rec, mdmPolicyReq(http.MethodPut, "/admin/mdm/policies/reorder", "", `{`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("reorder invalid JSON: want 400, got %d", rec.Code)
	}
}

// TestMDMPolicies_ErrorBranches_5xx proves every policy endpoint's checked
// database branch: the shadow schema carries a truncated mdm_policies whose
// shape fails each statement (missing projection columns, text id vs the
// int64 bind), so every handler answers 5xx — never a silent success.
func TestMDMPolicies_ErrorBranches_5xx(t *testing.T) {
	shadowPool := openMAMListFixturePool(t, `
		CREATE TABLE __SCHEMA__.mdm_policies(id text);`)
	h := NewMDMHandler(shadowPool, mailboxTestLogger())

	rec := httptest.NewRecorder()
	h.ListPolicies(rec, mdmPolicyReq(http.MethodGet, "/admin/mdm/policies", "", ""))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("list policies: want 500, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.CreatePolicy(rec, mdmPolicyReq(http.MethodPost, "/admin/mdm/policies", "",
		`{"name":"mdm-cov-shadow","scope_type":"global"}`))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("create policy: want 500, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.UpdatePolicy(rec, mdmPolicyReq(http.MethodPut, "/admin/mdm/policies/1", "1", `{"name":"x"}`))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("update policy: want 500, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.DeletePolicy(rec, mdmPolicyReq(http.MethodDelete, "/admin/mdm/policies/1", "1", ""))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("delete policy: want 500, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ReorderPolicies(rec, mdmPolicyReq(http.MethodPut, "/admin/mdm/policies/reorder", "", `{"ids":[1,2]}`))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("reorder policies: want 500, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestMDMUpdatePolicy_ValidationErrors covers the shared policyRequest
// validate arms through UpdatePolicy: each invalid field is a 400 naming the
// field, before any database work.
func TestMDMUpdatePolicy_ValidationErrors(t *testing.T) {
	h := NewMDMHandler(nil, mailboxTestLogger()) // nil pool: validation must fire first

	for _, tc := range []struct {
		name  string
		field string
		body  string
	}{
		{"empty name", "name", `{"name":""}`},
		{"bad scope_type", "scope_type", `{"scope_type":"everyone"}`},
		{"bad passcode_complexity", "passcode_complexity", `{"passcode_complexity":"hunter2"}`},
		{"bad jailbreak_action", "jailbreak_action", `{"jailbreak_action":"brick"}`},
		{"negative passcode_min_length", "passcode_min_length", `{"passcode_min_length":-1}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.UpdatePolicy(rec, mdmPolicyReq(http.MethodPut, "/admin/mdm/policies/1", "1", tc.body))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%s: want 400, got %d (body=%s)", tc.field, rec.Code, rec.Body.String())
			}
			var resp map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode validation error: %v", err)
			}
			if resp["field"] != tc.field {
				t.Errorf("validation field = %q, want %q", resp["field"], tc.field)
			}
		})
	}
}
