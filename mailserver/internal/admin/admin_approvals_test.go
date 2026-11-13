package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/testsupport"
)

func TestApprovalPolicies_RequiresManagePerm(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewApprovalsHandler(pool, testsupport.TestLogger())

	actorID := ssCreateUser(t, pool)

	// Build a perms slice that has every permission EXCEPT approvals.manage.
	var perms []string
	for _, p := range permissions.AllPermissions {
		if p != permissions.PermApprovalsManage {
			perms = append(perms, p)
		}
	}
	noPerm := &auth.Claims{UserID: actorID, IsAdmin: true, Permissions: perms}

	for _, tc := range []struct {
		method  string
		path    string
		body    string
		handler func(w http.ResponseWriter, r *http.Request)
		idParam string
	}{
		{
			"POST", "/admin/approval-policies",
			`{"consumerType":"rbac.jit_activation","name":"test","conditions":{},"requiresApproval":true,"approverSpec":{"kind":"default_admin"},"enabled":true}`,
			h.CreatePolicy, "",
		},
		{
			"PUT", "/admin/approval-policies/1",
			`{"name":"updated"}`,
			h.UpdatePolicy, "1",
		},
		{
			"DELETE", "/admin/approval-policies/1",
			"",
			h.DeletePolicy, "1",
		},
		{
			"POST", "/admin/approval-policies/reorder",
			`{"consumerType":"rbac.jit_activation","orderedIds":[1]}`,
			h.ReorderPolicies, "",
		},
	} {
		tc := tc
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req = req.WithContext(auth.ContextWithUser(req.Context(), noPerm))
			if tc.idParam != "" {
				req.SetPathValue("id", tc.idParam)
			}
			rec := httptest.NewRecorder()
			tc.handler(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s %s: want 403, got %d (body=%s)", tc.method, tc.path, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestApprovalAudit_RequiresViewPerm(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewApprovalsHandler(pool, testsupport.TestLogger())

	actorID := ssCreateUser(t, pool)
	noPerm := &auth.Claims{UserID: actorID, IsAdmin: true, Permissions: []string{}}

	req := httptest.NewRequest("GET", "/admin/approval-requests/audit", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), noPerm))
	rec := httptest.NewRecorder()
	h.ListAudit(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("ListAudit: want 403 without view perm, got %d", rec.Code)
	}
}

func TestApprovalPolicies_ListRequiresView(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewApprovalsHandler(pool, testsupport.TestLogger())

	actorID := ssCreateUser(t, pool)
	noPerm := &auth.Claims{UserID: actorID, IsAdmin: true, Permissions: []string{}}

	req := httptest.NewRequest("GET", "/admin/approval-policies", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), noPerm))
	rec := httptest.NewRecorder()
	h.ListPolicies(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("ListPolicies: want 403 without view perm, got %d", rec.Code)
	}
}

// TestApprovalPolicies_HRConsumerTypesAccepted pins the V110 admin-console
// requirement: validConsumerTypes (the Go-side mirror of the DB CHECK
// constraint) must accept hr.leave/hr.expense, or the new admin tabs 400 on
// every list/create/reorder call despite the DB happily allowing the rows.
func TestApprovalPolicies_HRConsumerTypesAccepted(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewApprovalsHandler(pool, testsupport.TestLogger())

	actorID := ssCreateUser(t, pool)
	viewer := &auth.Claims{UserID: actorID, IsAdmin: true, Permissions: []string{permissions.PermApprovalsView}}

	for _, ct := range []string{"hr.leave", "hr.expense"} {
		t.Run(ct, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/admin/approval-policies?consumer_type="+ct, nil)
			req = req.WithContext(auth.ContextWithUser(req.Context(), viewer))
			rec := httptest.NewRecorder()
			h.ListPolicies(rec, req)
			if rec.Code != http.StatusOK {
				t.Errorf("ListPolicies consumer_type=%s: want 200, got %d (body=%s)", ct, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestApprovalPolicies_DriveConsumerTypesAccepted pins the V116 admin-console
// requirement (Drive P5): validConsumerTypes must accept drive.export/
// drive.share so the shipped approvals console can edit their policies with
// zero new UI, and must still reject an unknown consumer type.
func TestApprovalPolicies_DriveConsumerTypesAccepted(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewApprovalsHandler(pool, testsupport.TestLogger())

	actorID := ssCreateUser(t, pool)
	viewer := &auth.Claims{UserID: actorID, IsAdmin: true, Permissions: []string{permissions.PermApprovalsView}}

	for _, ct := range []string{"drive.export", "drive.share"} {
		t.Run(ct, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/admin/approval-policies?consumer_type="+ct, nil)
			req = req.WithContext(auth.ContextWithUser(req.Context(), viewer))
			rec := httptest.NewRecorder()
			h.ListPolicies(rec, req)
			if rec.Code != http.StatusOK {
				t.Errorf("ListPolicies consumer_type=%s: want 200, got %d (body=%s)", ct, rec.Code, rec.Body.String())
			}
		})
	}

	t.Run("drive.bogus rejected", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/admin/approval-policies?consumer_type=drive.bogus", nil)
		req = req.WithContext(auth.ContextWithUser(req.Context(), viewer))
		rec := httptest.NewRecorder()
		h.ListPolicies(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("ListPolicies consumer_type=drive.bogus: want 400, got %d (body=%s)", rec.Code, rec.Body.String())
		}
	})
}
