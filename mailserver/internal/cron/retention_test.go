package cron

import (
	"context"
	"testing"
	"time"

	"setjoin.com/shared/testsupport"
)

// TestBulkRoleRetention_TaskRegistered verifies the sweep task is in AllTasks().
func TestBulkRoleRetention_TaskRegistered(t *testing.T) {
	const wantName = "prune-bulk-role-jobs"
	const wantSQL = `DELETE FROM bulk_role_jobs WHERE status IN ('done','error') AND updated_at < now() - interval '30 days'`
	for _, task := range AllTasks() {
		if task.Name == wantName {
			if task.SQL != wantSQL {
				t.Errorf("task %q SQL = %q, want %q", wantName, task.SQL, wantSQL)
			}
			return
		}
	}
	t.Errorf("task %q not found in AllTasks()", wantName)
}

// TestBulkRoleRetention seeds bulk_role_jobs rows and verifies the 30-day
// retention sweep DELETE: old terminal rows go, queued/running and recent
// terminal rows survive.
func TestBulkRoleRetention(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	// Minimal valid bulk_role_jobs INSERT: role_id + actor_id must reference
	// real rows if there are FK constraints. Check first.
	// The table has no FK on role_id/actor_id (admin data, bypass RLS), so
	// we can insert arbitrary bigint values.

	now := time.Now().UTC()
	old := now.Add(-31 * 24 * time.Hour)   // 31 days ago — should be swept
	recent := now.Add(-1 * 24 * time.Hour) // 1 day ago — must survive

	type seedRow struct {
		status    string
		updatedAt time.Time
		wantGone  bool
	}
	seeds := []seedRow{
		// old terminal → swept
		{"done", old, true},
		{"error", old, true},
		// recent terminal → survive
		{"done", recent, false},
		{"error", recent, false},
		// active → survive regardless of age
		{"queued", old, false},
		{"running", old, false},
	}

	var ids []int64
	for _, s := range seeds {
		var id int64
		err := pool.QueryRow(ctx,
			`INSERT INTO bulk_role_jobs
			  (op, role_id, actor_id, user_ids, status, total, updated_at)
			 VALUES ('assign', 1, 1, ARRAY[1]::bigint[], $1, 1, $2)
			 RETURNING id`,
			s.status, s.updatedAt,
		).Scan(&id)
		if err != nil {
			t.Fatalf("seed insert (status=%s): %v", s.status, err)
		}
		ids = append(ids, id)
	}

	// Cleanup regardless of test outcome.
	t.Cleanup(func() {
		for _, id := range ids {
			pool.Exec(ctx, `DELETE FROM bulk_role_jobs WHERE id = $1`, id) //nolint:errcheck
		}
	})

	// Run the exact sweep SQL from the cron task.
	const sweepSQL = `DELETE FROM bulk_role_jobs WHERE status IN ('done','error') AND updated_at < now() - interval '30 days'`
	_, err := pool.Exec(ctx, sweepSQL)
	if err != nil {
		t.Fatalf("sweep exec: %v", err)
	}

	// Assert survivors.
	for i, s := range seeds {
		id := ids[i]
		var exists bool
		err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM bulk_role_jobs WHERE id = $1)`, id).Scan(&exists)
		if err != nil {
			t.Fatalf("check id=%d: %v", id, err)
		}
		if s.wantGone && exists {
			t.Errorf("id=%d (status=%s, updated_at=%s): expected DELETED but still present", id, s.status, s.updatedAt)
		}
		if !s.wantGone && !exists {
			t.Errorf("id=%d (status=%s, updated_at=%s): expected SURVIVING but was deleted", id, s.status, s.updatedAt)
		}
	}
}
