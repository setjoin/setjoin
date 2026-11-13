package admin

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

func newJobsTestHandler(t *testing.T) *JobsHandler {
	pool := testsupport.OpenTestPool(t) // skips if DB_DSN unset
	return NewJobsHandler(pgxutil.WorkerPool{Pool: pool}, slog.New(slog.NewTextHandler(os.Stderr, nil)))
}

// Summary returns the five normalized counts for a known queue.
func TestJobs_Summary_KnownQueue(t *testing.T) {
	h := newJobsTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/admin/jobs/journal/summary", nil)
	req.SetPathValue("queue", "journal")
	rec := httptest.NewRecorder()

	h.Summary(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Summary: expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]int
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"active", "failed", "dead", "done", "total"} {
		if _, ok := resp[k]; !ok {
			t.Errorf("summary missing key %q (body=%s)", k, rec.Body.String())
		}
	}
}

// An unknown queue is a 400, not a 500.
func TestJobs_Summary_UnknownQueue(t *testing.T) {
	h := newJobsTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/admin/jobs/nope/summary", nil)
	req.SetPathValue("queue", "nope")
	rec := httptest.NewRecorder()

	h.Summary(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("Summary(unknown queue): expected 400, got %d", rec.Code)
	}
}

// List returns a JSON array (possibly empty) for a known queue.
func TestJobs_List_ReturnsArray(t *testing.T) {
	h := newJobsTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/admin/jobs/journal?status=dead&limit=10", nil)
	req.SetPathValue("queue", "journal")
	rec := httptest.NewRecorder()

	h.List(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("List: expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var rows []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatalf("List: body is not a JSON array: %v body=%s", err, rec.Body.String())
	}
}

// RetryJournal on a non-existent / non-dead row returns 404 (idempotent no-op).
func TestJobs_RetryJournal_NotFound(t *testing.T) {
	h := newJobsTestHandler(t)
	ctx := context.Background()
	// Ensure no row with this id exists.
	_, _ = h.pool.Exec(ctx, `DELETE FROM journal_queue WHERE id = 987654321`)

	req := httptest.NewRequest(http.MethodPost, "/admin/jobs/journal/987654321/retry", nil)
	req.SetPathValue("id", "987654321")
	rec := httptest.NewRecorder()

	h.RetryJournal(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("RetryJournal(missing): expected 404, got %d body=%s", rec.Code, rec.Body.String())
	}
}
