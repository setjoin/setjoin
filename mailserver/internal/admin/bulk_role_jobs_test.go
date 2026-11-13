package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/testsupport"
)

// bulkJobActorCtx builds a context with a minimal actor (needed for audit log).
func bulkJobActorCtx(ctx context.Context, actorID int64) context.Context {
	return auth.ContextWithUser(ctx, &auth.Claims{UserID: actorID, IsAdmin: true})
}

func newBulkJobsTestHandler(t *testing.T) *BulkRoleJobsHandler {
	pool := testsupport.OpenTestPool(t)
	return NewBulkRoleJobsHandler(pool, testsupport.TestLogger())
}

// TestBulkRoleJob_Detail_OK verifies JobDetail returns the full row JSON incl. results.
func TestBulkRoleJob_Detail_OK(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewBulkRoleJobsHandler(pool, testsupport.TestLogger())
	ctx := context.Background()

	// Insert a job row with known results.
	var jobID int64
	err := pool.QueryRow(ctx,
		`INSERT INTO bulk_role_jobs (op, role_id, actor_id, user_ids, total, status, processed, results)
		 VALUES ('assign', 1, 1, '{1,2}', 2, 'done', 2, '[{"user_id":1,"status":"assigned"},{"user_id":2,"status":"assigned"}]')
		 RETURNING id`,
	).Scan(&jobID)
	if err != nil {
		t.Fatalf("seed job: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM bulk_role_jobs WHERE id = $1`, jobID)
	})

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/admin/jobs/bulk_role/%d", jobID), nil)
	req.SetPathValue("id", fmt.Sprintf("%d", jobID))
	rec := httptest.NewRecorder()
	h.JobDetail(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("JobDetail: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var row map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &row); err != nil {
		t.Fatalf("JobDetail: body not JSON: %v (body=%s)", err, rec.Body.String())
	}
	if row["id"] == nil {
		t.Errorf("JobDetail: missing 'id' in response")
	}
	if row["results"] == nil {
		t.Errorf("JobDetail: missing 'results' in response (body=%s)", rec.Body.String())
	}
	if row["status"] != "done" {
		t.Errorf("JobDetail: want status=done, got %v", row["status"])
	}
}

// TestBulkRoleJob_Detail_NotFound verifies 404 for an unknown id.
func TestBulkRoleJob_Detail_NotFound(t *testing.T) {
	h := newBulkJobsTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/jobs/bulk_role/999999999", nil)
	req.SetPathValue("id", "999999999")
	rec := httptest.NewRecorder()
	h.JobDetail(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("JobDetail(unknown): want 404, got %d", rec.Code)
	}
}

// TestBulkRoleJob_Retry_ErrorJob_Queued verifies RetryJob on an 'error' job sets
// status='queued' and leaves processed/results unchanged (resume semantics, NOT reset).
func TestBulkRoleJob_Retry_ErrorJob_Queued(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewBulkRoleJobsHandler(pool, testsupport.TestLogger())
	ctx := context.Background()
	actorID := seedUser(t, pool)

	// Seed an error job with partial progress: processed=1, results has one entry.
	var jobID int64
	err := pool.QueryRow(ctx,
		`INSERT INTO bulk_role_jobs (op, role_id, actor_id, user_ids, total, status, processed, results, error)
		 VALUES ('assign', 1, $1, '{10,20}', 2, 'error', 1, '[{"user_id":10,"status":"assigned"}]', 'crash')
		 RETURNING id`,
		actorID,
	).Scan(&jobID)
	if err != nil {
		t.Fatalf("seed error job: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM bulk_role_jobs WHERE id = $1`, jobID)
	})

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/admin/jobs/bulk_role/%d/retry", jobID), nil)
	req.SetPathValue("id", fmt.Sprintf("%d", jobID))
	req = req.WithContext(bulkJobActorCtx(req.Context(), actorID))
	rec := httptest.NewRecorder()
	h.RetryJob(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("RetryJob(error): want 204, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	// Verify: status='queued', processed and results UNCHANGED.
	var status string
	var processed int
	var results []byte
	err = pool.QueryRow(ctx,
		`SELECT status, processed, results FROM bulk_role_jobs WHERE id = $1`, jobID,
	).Scan(&status, &processed, &results)
	if err != nil {
		t.Fatalf("read after retry: %v", err)
	}
	if status != "queued" {
		t.Errorf("RetryJob: want status=queued, got %q", status)
	}
	if processed != 1 {
		t.Errorf("RetryJob: processed must be UNCHANGED (1), got %d — resume not reset", processed)
	}
	var resultRows []map[string]any
	if err := json.Unmarshal(results, &resultRows); err != nil || len(resultRows) != 1 {
		t.Errorf("RetryJob: results must be UNCHANGED (1 entry), got %s", string(results))
	}
}

// TestBulkRoleJob_Retry_DoneJob_409 verifies RetryJob on a 'done' job returns 409.
func TestBulkRoleJob_Retry_DoneJob_409(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewBulkRoleJobsHandler(pool, testsupport.TestLogger())
	ctx := context.Background()
	actorID := seedUser(t, pool)

	var jobID int64
	err := pool.QueryRow(ctx,
		`INSERT INTO bulk_role_jobs (op, role_id, actor_id, user_ids, total, status, processed, results)
		 VALUES ('assign', 1, $1, '{10}', 1, 'done', 1, '[{"user_id":10,"status":"assigned"}]')
		 RETURNING id`,
		actorID,
	).Scan(&jobID)
	if err != nil {
		t.Fatalf("seed done job: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM bulk_role_jobs WHERE id = $1`, jobID)
	})

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/admin/jobs/bulk_role/%d/retry", jobID), nil)
	req.SetPathValue("id", fmt.Sprintf("%d", jobID))
	req = req.WithContext(bulkJobActorCtx(req.Context(), actorID))
	rec := httptest.NewRecorder()
	h.RetryJob(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("RetryJob(done): want 409, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}
