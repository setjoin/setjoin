package bulkroles

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

// TestProcessOnce_DrainsSingleJob inserts a queued bulk_role_jobs row, calls
// processOnce, and asserts the row reaches status='done'.
// Uses the shared testsupport pool (DB_DSN env var; skips when unset).
func TestProcessOnce_DrainsSingleJob(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	logger := testsupport.TestLogger()
	ctx := context.Background()

	// Use op='revoke' so the Rule A checks (perms-superset + scope-containment) are
	// skipped — both arms only fire for op='assign'. role_id must be a REAL role
	// (the reducer sets status='error' 'role no longer exists' for a missing role —
	// bulk_role_jobs.role_id has no FK); with user_ids='{}' (empty) the loop body
	// never executes, so the reducer exits cleanly → worker sets status='done'.
	var jobID int64
	err := pool.QueryRow(ctx,
		`INSERT INTO bulk_role_jobs (op, role_id, actor_id, user_ids, total, status)
		 VALUES ('revoke', (SELECT id FROM admin_role_groups ORDER BY id LIMIT 1), 1, '{}', 0, 'queued') RETURNING id`,
	).Scan(&jobID)
	if err != nil {
		t.Fatalf("insert job: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM bulk_role_jobs WHERE id = $1`, jobID) //nolint:errcheck
	})

	// processOnce claims ONE arbitrary queued job per call — on the shared
	// test DB another test's leaked queued row (lower id) can be claimed
	// first, leaving ours 'queued' (the CI flake). Drain until OUR job is
	// processed or the queue is empty; the contract under test is unchanged.
	w := NewWorker(pgxutil.WorkerPool{Pool: pool}, logger)
	var status string
	for i := 0; i < 20; i++ {
		claimed, err := w.processOnce(ctx)
		if err != nil {
			t.Fatalf("processOnce returned error: %v", err)
		}
		if err := pool.QueryRow(ctx,
			`SELECT status FROM bulk_role_jobs WHERE id = $1`, jobID,
		).Scan(&status); err != nil {
			t.Fatalf("select job status: %v", err)
		}
		if status != "queued" {
			break
		}
		if !claimed {
			t.Fatal("processOnce: queue drained but our job was never picked up")
		}
	}
	if status != "done" {
		t.Errorf("expected status 'done', got %q", status)
	}
	t.Logf("job %d finished with status=%s", jobID, status)
}

// TestProcessOnce_ReclaimsRunningJob verifies that the startup reclaim flips
// a stale 'running' row back to 'queued'.
func TestProcessOnce_ReclaimsRunningJob(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	logger := testsupport.TestLogger()
	ctx := context.Background()

	var jobID int64
	err := pool.QueryRow(ctx,
		`INSERT INTO bulk_role_jobs (op, role_id, actor_id, user_ids, total, status) VALUES ('assign', 999999, 1, '{}', 0, 'running') RETURNING id`,
	).Scan(&jobID)
	if err != nil {
		t.Fatalf("insert running job: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM bulk_role_jobs WHERE id = $1`, jobID) //nolint:errcheck
	})

	w := NewWorker(pgxutil.WorkerPool{Pool: pool}, logger)
	if err = w.reclaim(ctx); err != nil {
		t.Fatalf("reclaim: %v", err)
	}

	var status string
	err = pool.QueryRow(ctx,
		`SELECT status FROM bulk_role_jobs WHERE id = $1`, jobID,
	).Scan(&status)
	if err != nil {
		t.Fatalf("select job status after reclaim: %v", err)
	}
	if status != "queued" {
		t.Errorf("expected status 'queued' after reclaim, got %q", status)
	}
}

// TestApplyFailureIsCancellation pins the terminal-mark classification
// (D-MAILSERVER-INTERNAL-BULKROLES-001): shutdown/cancellation failures must be
// retryable (left queued by processOnce's rollback), while any other failure —
// including a wrapped reducer-authored rejection — proceeds to the terminal
// 'error' mark.
func TestApplyFailureIsCancellation(t *testing.T) {
	if !applyFailureIsCancellation(context.Canceled) {
		t.Error("context.Canceled must classify as retryable cancellation")
	}
	if !applyFailureIsCancellation(context.DeadlineExceeded) {
		t.Error("context.DeadlineExceeded must classify as retryable cancellation")
	}
	wrapped := fmt.Errorf("bulk_role_job_apply: %w", context.Canceled)
	if !applyFailureIsCancellation(wrapped) {
		t.Error("a wrapped cancellation must still classify as retryable")
	}
	if applyFailureIsCancellation(errors.New("role no longer exists")) {
		t.Error("a reducer-authored rejection must NOT classify as cancellation — it is terminal")
	}
	var pgErr *pgconn.PgError
	pgErr = &pgconn.PgError{Message: "BZ-something"}
	if applyFailureIsCancellation(pgErr) {
		t.Error("a SQL error must NOT classify as cancellation — it is terminal")
	}
}
