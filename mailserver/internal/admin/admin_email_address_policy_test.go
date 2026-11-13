package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"setjoin.com/shared/testsupport"
)

// TestValidateEAPTemplate exercises the template validator.
func TestValidateEAPTemplate(t *testing.T) {
	cases := []struct {
		name    string
		tmpl    string
		wantErr bool
	}{
		{
			name:    "valid with known vars",
			tmpl:    "{first_initial}{surname}@{domain}",
			wantErr: false,
		},
		{
			name:    "valid full name template",
			tmpl:    "{given_name}.{surname}@{domain}",
			wantErr: false,
		},
		{
			name:    "valid username template",
			tmpl:    "{user_name}@{domain}",
			wantErr: false,
		},
		{
			name:    "valid department template",
			tmpl:    "{given_name}.{department}@{domain}",
			wantErr: false,
		},
		{
			name:    "reject: no at sign",
			tmpl:    "no-at-sign",
			wantErr: true,
		},
		{
			name:    "reject: unknown variable",
			tmpl:    "{bogus}@x.com",
			wantErr: true,
		},
		{
			name:    "reject: plain address with no var",
			tmpl:    "plain@x.com",
			wantErr: true,
		},
		{
			name:    "reject: empty string",
			tmpl:    "",
			wantErr: true,
		},
		{
			name:    "reject: missing at but has var",
			tmpl:    "{user_name}domain.com",
			wantErr: true,
		},
		{
			name:    "reject: unknown var mixed with known",
			tmpl:    "{given_name}.{middle_name}@{domain}",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateEAPTemplate(tc.tmpl)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateEAPTemplate(%q) error = %v, wantErr %v", tc.tmpl, err, tc.wantErr)
			}
		})
	}
}

// TestEAPHandler_Delete_InvalidID verifies that invalid IDs return 400 before any DB call.
func TestEAPHandler_Delete_InvalidID(t *testing.T) {
	h := &EmailAddressPolicyHandler{pool: nil, logger: nil}

	req := httptest.NewRequest(http.MethodDelete, "/admin/email-address-policies/not-a-number", nil)
	req.SetPathValue("id", "not-a-number")
	w := httptest.NewRecorder()
	h.Delete(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid policy ID, got %d", w.Code)
	}
}

// TestEAPHandler_Update_InvalidID verifies that invalid IDs return 400 before any DB call.
func TestEAPHandler_Update_InvalidID(t *testing.T) {
	h := &EmailAddressPolicyHandler{pool: nil, logger: nil}

	body := strings.NewReader(`{"name":"test","primaryTemplate":"{user_name}@{domain}"}`)
	req := httptest.NewRequest(http.MethodPut, "/admin/email-address-policies/bad", body)
	req.SetPathValue("id", "bad")
	w := httptest.NewRecorder()
	h.Update(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid policy ID, got %d", w.Code)
	}
}

// TestEAPHandler_Create_MissingName verifies that missing name returns 400.
func TestEAPHandler_Create_MissingName(t *testing.T) {
	h := &EmailAddressPolicyHandler{pool: nil, logger: nil}

	body := strings.NewReader(`{"primaryTemplate":"{user_name}@{domain}"}`)
	req := httptest.NewRequest(http.MethodPost, "/admin/email-address-policies", body)
	w := httptest.NewRecorder()
	h.Create(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing name, got %d", w.Code)
	}
}

// TestEAPHandler_Create_InvalidTemplate verifies template validation on create.
func TestEAPHandler_Create_InvalidTemplate(t *testing.T) {
	h := &EmailAddressPolicyHandler{pool: nil, logger: nil}

	body := strings.NewReader(`{"name":"test","primaryTemplate":"no-at-sign"}`)
	req := httptest.NewRequest(http.MethodPost, "/admin/email-address-policies", body)
	w := httptest.NewRecorder()
	h.Create(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid template, got %d", w.Code)
	}
}

// TestEAPHandler_Reorder_EmptyOrder verifies that empty order array returns 400.
func TestEAPHandler_Reorder_EmptyOrder(t *testing.T) {
	h := &EmailAddressPolicyHandler{pool: nil, logger: nil}

	body := strings.NewReader(`{"order":[]}`)
	req := httptest.NewRequest(http.MethodPost, "/admin/email-address-policies/reorder", body)
	w := httptest.NewRecorder()
	h.Reorder(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty order, got %d", w.Code)
	}
}

// TestEAPHandler_ApplyStatus_InvalidJobID verifies that invalid job IDs return 400.
func TestEAPHandler_ApplyStatus_InvalidJobID(t *testing.T) {
	h := &EmailAddressPolicyHandler{pool: nil, logger: nil}

	req := httptest.NewRequest(http.MethodGet, "/admin/email-address-policies/apply/bad", nil)
	req.SetPathValue("jobId", "bad")
	w := httptest.NewRecorder()
	h.ApplyStatus(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid job ID, got %d", w.Code)
	}
}

// TestEAPHandler_Update_DB covers DB-backed Update scenarios.
func TestEAPHandler_Update_DB(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	logger := testsupport.TestLogger()
	h := NewEmailAddressPolicyHandler(pool, logger)
	ctx := context.Background()

	// Helper: create an enabled EAP with given priority.
	createPolicy := func(t *testing.T, priority int, name string) int64 {
		t.Helper()
		var id int64
		err := pool.QueryRow(ctx,
			`INSERT INTO email_address_policies
			   (priority, name, enabled, primary_template, duplicate_resolution)
			 VALUES ($1, $2, TRUE, '{user_name}@{domain}', 'numeric_suffix')
			 RETURNING id`,
			priority, name,
		).Scan(&id)
		if err != nil {
			t.Fatalf("createPolicy: %v", err)
		}
		t.Cleanup(func() {
			pool.Exec(context.Background(), `DELETE FROM email_address_policies WHERE id = $1`, id) //nolint:errcheck
		})
		return id
	}

	t.Run("partial update no name succeeds", func(t *testing.T) {
		id := createPolicy(t, 9901, "PartialUpdateTest")
		body := strings.NewReader(`{"enabled":false}`)
		req := httptest.NewRequest(http.MethodPut, "/admin/email-address-policies/"+strconv.FormatInt(id, 10), body)
		req.SetPathValue("id", strconv.FormatInt(id, 10))
		w := httptest.NewRecorder()
		h.Update(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("partial update (no name): expected 200, got %d body=%s", w.Code, w.Body.String())
		}
		var p eapPolicyResponse
		if err := json.NewDecoder(w.Body).Decode(&p); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if p.Enabled {
			t.Errorf("expected enabled=false after partial update, got true")
		}
		if p.Name != "PartialUpdateTest" {
			t.Errorf("expected name preserved, got %q", p.Name)
		}
	})

	t.Run("priority collision returns 409", func(t *testing.T) {
		_ = createPolicy(t, 9902, "PriorityA")
		idB := createPolicy(t, 9903, "PriorityB")
		// Try to move B onto A's priority — should conflict on eap_priority_unique_idx (enabled)
		body := strings.NewReader(`{"priority":9902}`)
		req := httptest.NewRequest(http.MethodPut, "/admin/email-address-policies/"+strconv.FormatInt(idB, 10), body)
		req.SetPathValue("id", strconv.FormatInt(idB, 10))
		w := httptest.NewRecorder()
		h.Update(w, req)
		if w.Code != http.StatusConflict {
			t.Fatalf("priority collision: expected 409, got %d body=%s", w.Code, w.Body.String())
		}
	})

	t.Run("unknown id returns 404", func(t *testing.T) {
		body := strings.NewReader(`{"name":"Ghost"}`)
		req := httptest.NewRequest(http.MethodPut, "/admin/email-address-policies/999999999", body)
		req.SetPathValue("id", "999999999")
		w := httptest.NewRecorder()
		h.Update(w, req)
		if w.Code != http.StatusNotFound {
			t.Fatalf("unknown id: expected 404, got %d body=%s", w.Code, w.Body.String())
		}
	})
}

// TestApplyStatusSurfacesError asserts ApplyStatus returns the eap_apply_jobs.error
// text (it was previously dropped; the UI showed a hardcoded "Apply job failed").
func TestApplyStatusSurfacesError(t *testing.T) {
	pool := testsupport.OpenTestPool(t) // skips if DB_DSN unset
	logger := testsupport.TestLogger()
	ctx := context.Background()
	var jobID int64
	err := pool.QueryRow(ctx,
		`INSERT INTO eap_apply_jobs (status, total, applied, error)
		 VALUES ('error', 3, 1, 'template render failed: unknown var {bogus}')
		 RETURNING id`).Scan(&jobID)
	if err != nil {
		t.Fatalf("seed job: %v", err)
	}
	t.Cleanup(func() { pool.Exec(ctx, `DELETE FROM eap_apply_jobs WHERE id=$1`, jobID) }) //nolint:errcheck

	h := NewEmailAddressPolicyHandler(pool, logger)
	req := httptest.NewRequest(http.MethodGet, "/admin/email-address-policies/apply/"+strconv.FormatInt(jobID, 10), nil)
	req.SetPathValue("jobId", strconv.FormatInt(jobID, 10))
	rec := httptest.NewRecorder()
	h.ApplyStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Status string  `json:"status"`
		Error  *string `json:"error"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error == nil || !strings.Contains(*resp.Error, "unknown var {bogus}") {
		t.Errorf("error not surfaced: %+v", resp)
	}
}
