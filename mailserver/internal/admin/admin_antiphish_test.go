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

// TestAntiPhishConfigRoundTrip drives SetConfig -> GetConfig against the real DB
// and asserts the written system_config values round-trip. This mutating
// handler previously had zero coverage.
func TestAntiPhishConfigRoundTrip(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewAntiPhishHandler(pool, testsupport.TestLogger())

	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM system_config WHERE key LIKE 'antiphish_%'`) //nolint:errcheck
	})

	body := `{"display_name_enabled":false,"lookalike_enabled":true,"contact_graph_enabled":false,` +
		`"strict_mode":true,"exclusion_domains":["partner.example"],"exclusion_users":["vip@corp.example"]}`
	setReq := httptest.NewRequest(http.MethodPut, "/admin/antiphish/config", strings.NewReader(body))
	setRec := httptest.NewRecorder()
	h.SetConfig(setRec, setReq)
	if setRec.Code != http.StatusNoContent {
		t.Fatalf("SetConfig: want 204, got %d (%s)", setRec.Code, setRec.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/admin/antiphish/config", nil)
	getRec := httptest.NewRecorder()
	h.GetConfig(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GetConfig: want 200, got %d", getRec.Code)
	}
	var cfg antiPhishConfig
	if err := json.Unmarshal(getRec.Body.Bytes(), &cfg); err != nil {
		t.Fatalf("decode GetConfig: %v", err)
	}
	if cfg.DisplayNameEnabled || !cfg.LookalikeEnabled || cfg.ContactGraphEnabled || !cfg.StrictMode {
		t.Errorf("bool config did not round-trip: %+v", cfg)
	}
	if len(cfg.ExclusionDomains) != 1 || cfg.ExclusionDomains[0] != "partner.example" {
		t.Errorf("exclusion_domains did not round-trip: %+v", cfg.ExclusionDomains)
	}
	if len(cfg.ExclusionUsers) != 1 || cfg.ExclusionUsers[0] != "vip@corp.example" {
		t.Errorf("exclusion_users did not round-trip: %+v", cfg.ExclusionUsers)
	}

	// Invalid body -> 400.
	badReq := httptest.NewRequest(http.MethodPut, "/admin/antiphish/config", strings.NewReader(`{bad`))
	badRec := httptest.NewRecorder()
	h.SetConfig(badRec, badReq)
	if badRec.Code != http.StatusBadRequest {
		t.Errorf("SetConfig invalid body: want 400, got %d", badRec.Code)
	}
}
