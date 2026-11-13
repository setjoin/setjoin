package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/shared/testsupport"
)

// newTestCACoverageHandler opens the test pool and returns a CACoverageHandler.
func newTestCACoverageHandler(t *testing.T) *CACoverageHandler {
	t.Helper()
	pool := testsupport.OpenTestPool(t)
	return NewCACoverageHandler(pool, testsupport.TestLogger())
}

// TestCACoverage_ReturnsGapsAndShadowed verifies the coverage endpoint returns the
// {gaps, shadowed} shape with always-array (never null) values (HTTP 200).
// DB-backed; skips without TEST_DB_DSN.
func TestCACoverage_ReturnsGapsAndShadowed(t *testing.T) {
	h := newTestCACoverageHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/conditional-access/coverage", nil)
	req = withAdminClaims(req, 1)
	w := httptest.NewRecorder()
	h.Coverage(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Coverage: got %d, want 200; body=%s", w.Code, w.Body.String())
	}

	var resp struct {
		Gaps     []json.RawMessage `json:"gaps"`
		Shadowed []json.RawMessage `json:"shadowed"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Coverage: invalid JSON: %v; body=%s", err, w.Body.String())
	}
	// gaps and shadowed must be arrays (never null) — UI relies on this for ALL-CLEAR state.
	if resp.Gaps == nil {
		t.Fatalf("Coverage: gaps must be [] not null")
	}
	if resp.Shadowed == nil {
		t.Fatalf("Coverage: shadowed must be [] not null")
	}
}

// TestCACoverage_GapHasSeverity verifies each gap carries a severity field.
// DB-backed; skips without TEST_DB_DSN.
func TestCACoverage_GapHasSeverity(t *testing.T) {
	h := newTestCACoverageHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/conditional-access/coverage", nil)
	req = withAdminClaims(req, 1)
	w := httptest.NewRecorder()
	h.Coverage(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Coverage: got %d, want 200", w.Code)
	}

	var resp struct {
		Gaps []struct {
			Kind     string `json:"kind"`
			Detail   string `json:"detail"`
			Severity string `json:"severity"`
		} `json:"gaps"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Coverage: invalid JSON: %v", err)
	}
	for i, g := range resp.Gaps {
		if g.Severity == "" {
			t.Errorf("gap[%d]: missing severity (kind=%s detail=%s)", i, g.Kind, g.Detail)
		}
		if g.Severity != "danger" && g.Severity != "warning" {
			t.Errorf("gap[%d]: unexpected severity %q (want danger or warning)", i, g.Severity)
		}
		if g.Kind == "" {
			t.Errorf("gap[%d]: missing kind", i)
		}
		if g.Detail == "" {
			t.Errorf("gap[%d]: missing detail", i)
		}
	}
}
