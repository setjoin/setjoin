package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/shared/testsupport"
)

// TestQueueSummary_DBErrorReturns500 proves the Summary handler surfaces a DB
// failure as 500 instead of silently returning all-zero stats with 200 (the
// old code ignored every QueryRow scan error). A closed pool makes the query
// fail deterministically.
func TestQueueSummary_DBErrorReturns500(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	pool.Close() // force the summary query to fail
	h := NewQueueHandler(pool, testsupport.TestLogger())

	req := httptest.NewRequest(http.MethodGet, "/admin/queue/summary", nil)
	w := httptest.NewRecorder()
	h.Summary(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("Summary on closed pool: want 500, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// TestQueueSummary_OK proves the happy path still returns 200 with all five stat
// keys present.
func TestQueueSummary_OK(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewQueueHandler(pool, testsupport.TestLogger())

	req := httptest.NewRequest(http.MethodGet, "/admin/queue/summary", nil)
	w := httptest.NewRecorder()
	h.Summary(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Summary: want 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	var got map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, k := range []string{"pending", "deferred", "bouncedToday", "stuck", "oldestMinutes"} {
		if _, ok := got[k]; !ok {
			t.Errorf("missing key %q in summary response", k)
		}
	}
}
