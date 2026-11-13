package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"setjoin.com/shared/testsupport"
)

// TestDLPUpdatePatterns drives the global (unscoped) admin replace-all path of
// UpdatePatterns against the real DB and asserts the severity<->action mapping
// round-trips through GetPatterns. The scoped-admin 403 path is covered by
// TestDomainScope_DLP in admin_domains_test.go.
//
// ponytail: UpdatePatterns replaces ALL is_pattern rows globally; cleanup wipes
// is_pattern rows rather than restoring a snapshot (test DB, sequential tests).
func TestDLPUpdatePatterns(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewDLPHandler(pool)

	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM dlp_policies WHERE is_pattern = TRUE`) //nolint:errcheck
	})

	body := `[{"name":"SSN","regex":"\\d{3}-\\d{2}-\\d{4}","severity":"critical","enabled":true},` +
		`{"name":"CC","regex":"\\d{16}","severity":"high","enabled":true}]`
	putReq := httptest.NewRequest(http.MethodPut, "/admin/dlp/patterns", strings.NewReader(body))
	putRec := httptest.NewRecorder()
	h.UpdatePatterns(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("UpdatePatterns: want 200, got %d (%s)", putRec.Code, putRec.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/admin/dlp/patterns", nil)
	getRec := httptest.NewRecorder()
	h.GetPatterns(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GetPatterns: want 200, got %d", getRec.Code)
	}
	var got []dlpPatternRow
	if err := json.Unmarshal(getRec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode GetPatterns: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 patterns, got %d: %+v", len(got), got)
	}
	byName := map[string]dlpPatternRow{}
	for _, p := range got {
		byName[p.Name] = p
	}
	if p, ok := byName["SSN"]; !ok || p.Severity != "critical" || p.Regex != `\d{3}-\d{2}-\d{4}` {
		t.Errorf("SSN pattern wrong: %+v", p)
	}
	if p, ok := byName["CC"]; !ok || p.Severity != "high" {
		t.Errorf("CC pattern wrong: %+v", p)
	}
}
