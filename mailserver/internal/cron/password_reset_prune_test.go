package cron

import (
	"context"
	"testing"
	"time"

	"setjoin.com/shared/testsupport"
)

// TestPasswordResetTokenRetention_TaskRegistered verifies the consumed
// forgot-password tombstone sweep is registered in AllTasks() (med-shard3-003:
// the pruner was promised but never registered anywhere — a registry that
// drops this task fails this named assertion).
func TestPasswordResetTokenRetention_TaskRegistered(t *testing.T) {
	const wantName = "prune-used-password-reset-tokens"
	const wantSQL = "SELECT prune_used_password_reset_tokens()"
	for _, task := range AllTasks() {
		if task.Name == wantName {
			if task.SQL != wantSQL {
				t.Errorf("task %q SQL = %q, want %q", wantName, task.SQL, wantSQL)
			}
			if !task.enabled {
				t.Errorf("task %q must be enabled", wantName)
			}
			return
		}
	}
	t.Errorf("task %q not found in AllTasks()", wantName)
}

// TestPasswordResetTokenRetention runs the EXACT registered task SQL against
// the managed schema: consumed reset-token hashes past the 10-minute default
// window are pruned while fresh tombstones survive (their JWTs may still be
// inside the 5-minute validity). This is the registered-prune-path evidence
// the superseded forgot_password.pg inline DELETE never had. Resolve drift
// (missing function / changed signature) is separately gated at startup and
// in tests by ValidateRegistrations (tasks_resolve_test.go).
func TestPasswordResetTokenRetention(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	const oldHash = "medshard3003-old-consumed-hash"
	const freshHash = "medshard3003-fresh-consumed-hash"
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM used_password_reset_tokens WHERE token_hash IN ($1, $2)`, oldHash, freshHash) //nolint:errcheck
	})

	// Pre-clean any residue from an earlier interrupted run, then seed one
	// tombstone past the 10-minute window and one inside it.
	if _, err := pool.Exec(ctx,
		`DELETE FROM used_password_reset_tokens WHERE token_hash IN ($1, $2)`, oldHash, freshHash,
	); err != nil {
		t.Fatalf("pre-clean: %v", err)
	}
	now := time.Now().UTC()
	if _, err := pool.Exec(ctx,
		`INSERT INTO used_password_reset_tokens (token_hash, created_at) VALUES ($1, $2), ($3, $4)`,
		oldHash, now.Add(-11*time.Minute), freshHash, now.Add(-2*time.Minute),
	); err != nil {
		t.Fatalf("seed inserts: %v", err)
	}

	// The exact SQL the registered cron task executes.
	const sweepSQL = "SELECT prune_used_password_reset_tokens()"
	if _, err := pool.Exec(ctx, sweepSQL); err != nil {
		t.Fatalf("registered sweep exec: %v", err)
	}

	var oldGone, freshKept bool
	if err := pool.QueryRow(ctx,
		`SELECT NOT EXISTS(SELECT 1 FROM used_password_reset_tokens WHERE token_hash = $1),
		        EXISTS(SELECT 1 FROM used_password_reset_tokens WHERE token_hash = $2)`,
		oldHash, freshHash,
	).Scan(&oldGone, &freshKept); err != nil {
		t.Fatalf("sweep verification: %v", err)
	}
	if !oldGone {
		t.Errorf("consumed hash past the retention window was not pruned")
	}
	if !freshKept {
		t.Errorf("fresh tombstone inside the window was deleted")
	}
}
