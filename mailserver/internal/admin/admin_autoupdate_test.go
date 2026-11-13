package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"setjoin.com/shared/httputil"
)

func TestLegacyAutoUpdateRoutesReturnGoneBeforeParsingInput(t *testing.T) {
	h := NewAutoUpdateHandler(nil, nil)
	tests := []struct {
		name    string
		method  string
		target  string
		handler http.HandlerFunc
	}{
		{name: "read auto-update", method: http.MethodGet, target: "/admin/system/auto-update", handler: h.GetAutoUpdateConfig},
		{name: "write auto-update", method: http.MethodPut, target: "/admin/system/auto-update", handler: h.SaveAutoUpdateConfig},
		{name: "read maintenance window", method: http.MethodGet, target: "/admin/system/maintenance-window", handler: h.GetMaintenanceWindow},
		{name: "write maintenance window", method: http.MethodPut, target: "/admin/system/maintenance-window", handler: h.SaveMaintenanceWindow},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The malformed body and attacker-selected path prove that the
			// compatibility interlock runs before parsing or persistence.
			req := httptest.NewRequest(tt.method, tt.target, strings.NewReader(`{"source_path":"/tmp/untrusted","broken":`))
			rr := httptest.NewRecorder()

			tt.handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusGone {
				t.Fatalf("status = %d, want %d", rr.Code, http.StatusGone)
			}
			if got := rr.Header().Get("Content-Type"); got != "application/problem+json" {
				t.Fatalf("Content-Type = %q", got)
			}
			var problem httputil.Problem
			if err := json.Unmarshal(rr.Body.Bytes(), &problem); err != nil {
				t.Fatalf("decode problem: %v", err)
			}
			if problem.Type != legacyAutoUpdateRetiredType || problem.Instance != tt.target {
				t.Fatalf("problem = %#v", problem)
			}
			if !strings.Contains(problem.Remediation, "/admin/updates/server") ||
				!strings.Contains(problem.Remediation, "UPGRADE.md") {
				t.Fatalf("remediation does not name the transactional console and runbook: %q", problem.Remediation)
			}
		})
	}
}
