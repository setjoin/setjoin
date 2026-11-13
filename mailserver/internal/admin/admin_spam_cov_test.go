package admin

// Final-wave changed-lines coverage for admin_spam.go: the batch-load counter
// wiring (SetBatchLoadStats, feature.spam_model_batch_load owner decision A6)
// and its GetDashboard surface — the dashboard must report the process-wide
// counters it was wired with, alongside the model aggregate reads.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/mailserver/internal/spam"
	"setjoin.com/shared/testsupport"
)

// TestSpamDashboardSurfacesBatchLoadStats pins the A6 contract: with the
// batch-stats source wired, the dashboard JSON carries the resident footprint
// (models/bytes) and the lifetime loads/hits verbatim.
func TestSpamDashboardSurfacesBatchLoadStats(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewSpamHandler(pool, testsupport.TestLogger())
	h.SetBatchLoadStats(func() spam.BatchLoadStats {
		return spam.BatchLoadStats{Loads: 11, Hits: 7, ResidentModels: 3, ResidentBytes: 75_161_928}
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/spam", nil)
	rec := httptest.NewRecorder()
	h.GetDashboard(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GetDashboard: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	var d struct {
		BatchLoadResidentModels int64           `json:"batch_load_resident_models"`
		BatchLoadResidentBytes  int64           `json:"batch_load_resident_bytes"`
		BatchLoadLoads          int64           `json:"batch_load_loads"`
		BatchLoadHits           int64           `json:"batch_load_hits"`
		TopUsers                []userModelStat `json:"top_users"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
		t.Fatalf("decode dashboard: %v", err)
	}
	if d.BatchLoadLoads != 11 || d.BatchLoadHits != 7 ||
		d.BatchLoadResidentModels != 3 || d.BatchLoadResidentBytes != 75_161_928 {
		t.Fatalf("batch-load counters not surfaced verbatim: %+v", d)
	}
	if d.TopUsers == nil {
		t.Fatal("top_users must default to an empty list, never null")
	}
}
