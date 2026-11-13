package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/shared/testsupport"
)

// newTestCADoctorHandler opens the test pool and returns a CADoctorHandler.
func newTestCADoctorHandler(t *testing.T) *CADoctorHandler {
	t.Helper()
	pool := testsupport.OpenTestPool(t)
	return NewCADoctorHandler(pool, testsupport.TestLogger())
}

// TestCADoctor_ReturnsScoreAndChecks verifies the doctor endpoint returns the
// {score, total, checks, hygiene, time_to_first_policy_sec} shape.
// DB-backed; skips without TEST_DB_DSN.
func TestCADoctor_ReturnsScoreAndChecks(t *testing.T) {
	h := newTestCADoctorHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/conditional-access/doctor", nil)
	req = withAdminClaims(req, 1)
	w := httptest.NewRecorder()
	h.Doctor(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Doctor: got %d, want 200; body=%s", w.Code, w.Body.String())
	}

	var resp doctorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Doctor: invalid JSON: %v; body=%s", err, w.Body.String())
	}

	// total must be 4 (the four checks we define).
	if resp.Total != 4 {
		t.Errorf("Doctor: total = %d, want 4", resp.Total)
	}
	// score must be in [0, total].
	if resp.Score < 0 || resp.Score > resp.Total {
		t.Errorf("Doctor: score %d out of range [0, %d]", resp.Score, resp.Total)
	}
	// checks must have exactly total entries, each with a name.
	if len(resp.Checks) != resp.Total {
		t.Errorf("Doctor: len(checks) = %d, want %d", len(resp.Checks), resp.Total)
	}
	for i, c := range resp.Checks {
		if c.Name == "" {
			t.Errorf("Doctor: checks[%d].name is empty", i)
		}
	}
	// hygiene stale_report_only must be an array (never null).
	if resp.Hygiene.StaleReportOnly == nil {
		t.Error("Doctor: hygiene.stale_report_only must be [] not null")
	}
}

// TestCADoctor_CheckNames verifies each expected check name is present.
func TestCADoctor_CheckNames(t *testing.T) {
	h := newTestCADoctorHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/conditional-access/doctor", nil)
	req = withAdminClaims(req, 1)
	w := httptest.NewRecorder()
	h.Doctor(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Doctor: got %d, want 200; body=%s", w.Code, w.Body.String())
	}

	var resp doctorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Doctor: invalid JSON: %v", err)
	}

	want := map[string]bool{
		"feature_on":             false,
		"break_glass_configured": false,
		"has_report_only_policy": false,
		"no_coverage_gaps":       false,
	}
	for _, c := range resp.Checks {
		want[c.Name] = true
	}
	for name, found := range want {
		if !found {
			t.Errorf("Doctor: check %q missing from response", name)
		}
	}
}

// TestCADoctor_PassedChecksHaveNoNextAction verifies passed checks omit next_action.
func TestCADoctor_PassedChecksHaveNoNextAction(t *testing.T) {
	h := newTestCADoctorHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/conditional-access/doctor", nil)
	req = withAdminClaims(req, 1)
	w := httptest.NewRecorder()
	h.Doctor(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Doctor: got %d, want 200; body=%s", w.Code, w.Body.String())
	}

	var resp doctorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Doctor: invalid JSON: %v", err)
	}

	for _, c := range resp.Checks {
		if c.Passed && c.NextAction != "" {
			t.Errorf("Doctor: check %q is passed but has next_action=%q", c.Name, c.NextAction)
		}
		if !c.Passed && c.NextAction == "" {
			t.Errorf("Doctor: check %q is not passed but has empty next_action", c.Name)
		}
	}
}
