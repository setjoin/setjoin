package cron

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAllTasks_ParseAll(t *testing.T) {
	tasks := AllTasks()
	// 27: c11-bug replaced the three dead monthly partition tasks (they called
	// functions that no longer exist post-ARCH-007) with one rotator (27), then
	// mark-orphaned-blobs was removed (it called a SQL function that was never
	// implemented and, being pure SQL, could never delete a SeaweedFS object
	// anyway — the drain moved to blob.Handler.processOrphanedBlobs) (26), then
	// Chat A4a Task 6 added chat-purge-expired (inert until
	// feature.chat_compliance flips ON) (27), then Task 9 added chat-chain-anchor
	// at 02:40, before chat-purge-expired's 02:50 (28), then arch review #A5
	// folded the former internal/approvaljobs package's bare 3s ticker in as
	// "approval-expire-due" (29), then the auth_lockouts lifecycle job landed
	// as "prune-auth-lockouts" — the Go-registry replacement the documented
	// pg_cron schedule never had (30), then the used-password-reset-token
	// prune joined as "prune-used-password-reset-tokens" (31).
	if len(tasks) != 31 {
		t.Errorf("AllTasks() = %d tasks, want 31", len(tasks))
	}
	for _, task := range tasks {
		interval, cronExpr, err := parseSchedule(task.Schedule)
		if err != nil {
			t.Errorf("task %q: invalid schedule %q: %v", task.Name, task.Schedule, err)
		}
		if interval == 0 && cronExpr == "" {
			t.Errorf("task %q: neither interval nor cron parsed from %q", task.Name, task.Schedule)
		}
		if task.Timeout <= 0 {
			t.Errorf("task %q: timeout not set", task.Name)
		}
		if task.SQL == "" {
			t.Errorf("task %q: SQL not set", task.Name)
		}
	}
}

func TestAllTasks_UniqueNames(t *testing.T) {
	tasks := AllTasks()
	seen := make(map[string]bool)
	for _, task := range tasks {
		if seen[task.Name] {
			t.Errorf("duplicate task name: %q", task.Name)
		}
		seen[task.Name] = true
	}
}

// TestAllTasks_ScheduledActions asserts the A6 deferred-action cron wiring:
// the dispatcher + reminder scan are present, and the three legacy timer tasks
// they replace are gone.
func TestAllTasks_ScheduledActions(t *testing.T) {
	tasks := AllTasks()
	byName := make(map[string]*Task, len(tasks))
	for _, task := range tasks {
		byName[task.Name] = task
	}

	dispatch, ok := byName["dispatch-scheduled-actions"]
	if !ok {
		t.Fatal("dispatch-scheduled-actions task missing")
	}
	if dispatch.SQL != "SELECT dispatch_scheduled_actions('cron')" {
		t.Errorf("dispatch-scheduled-actions SQL = %q, want SELECT dispatch_scheduled_actions('cron')", dispatch.SQL)
	}

	scan, ok := byName["scan-due-reminders"]
	if !ok {
		t.Fatal("scan-due-reminders task missing")
	}
	if scan.SQL != "SELECT scan_due_reminders()" {
		t.Errorf("scan-due-reminders SQL = %q, want SELECT scan_due_reminders()", scan.SQL)
	}

	for _, legacy := range []string{"process-snoozed", "process-scheduled", "process-message-timers"} {
		if _, present := byName[legacy]; present {
			t.Errorf("legacy timer task %q must be removed (subsumed by dispatch-scheduled-actions)", legacy)
		}
	}
}

// TestAllTasks_NoMarkOrphanedBlobs is the regression guard for the dead cron
// entry: mark-orphaned-blobs called SELECT mark_orphaned_blobs(), a SQL
// function that never existed. Since draining orphaned_message_blobs requires
// deleting an object from SeaweedFS/MinIO — impossible from pure PL/pgSQL run
// through this cron worker's pool.Exec — the drain was moved to
// blob.Handler.processOrphanedBlobs (same ticker as blob_cleanup_queue), not
// reintroduced as a SQL cron task.
func TestAllTasks_NoMarkOrphanedBlobs(t *testing.T) {
	for _, task := range AllTasks() {
		if task.Name == "mark-orphaned-blobs" {
			t.Fatal("mark-orphaned-blobs must stay removed — it calls a nonexistent SQL function; the drain lives in internal/blob (processOrphanedBlobs)")
		}
	}
}

// TestAllTasks_LockoutPruneRegistered pins the auth_lockouts lifecycle job
// (D-AUTHSERVER-SQL-REDUCERS-002): the documented pg_cron schedule never
// landed a replacement in this registry, so in deployed systems even expired
// auth_lockouts rows were never removed and attacker-seeded rows grew the
// table without bound. Without this registration the reducer-side retention
// and recovery semantics in prune_old_lockouts are dead code.
func TestAllTasks_LockoutPruneRegistered(t *testing.T) {
	var prune *Task
	for _, task := range AllTasks() {
		if task.Name == "prune-auth-lockouts" {
			prune = task
			break
		}
	}
	if prune == nil {
		t.Fatal("prune-auth-lockouts task missing: auth_lockouts has no working cleanup schedule")
	}
	if !prune.enabled {
		t.Error("prune-auth-lockouts must be enabled — a disabled schedule is the never-ran defect this task exists to fix")
	}
	if prune.Schedule != "@every 5m" {
		t.Errorf("prune-auth-lockouts Schedule = %q, want @every 5m (the documented prune cadence)", prune.Schedule)
	}
	if prune.SQL != "SELECT prune_old_lockouts()" {
		t.Errorf("prune-auth-lockouts SQL = %q, want SELECT prune_old_lockouts()", prune.SQL)
	}
}

// lockoutPruneTestPool returns a pool over the managed test schema (DB_DSN).
// Self-contained so this DB arm does not couple to other files' helpers.
func lockoutPruneTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN not set; lockout prune execution needs the managed schema")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("cannot connect to test DB: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// TestLockoutPruneTaskExecutes proves the registered SQL is not merely
// parseable but RUNNABLE: the exact task statement executes against the
// managed schema and returns the deleted-row count (the reducer is a plain
// idempotent INT function, safe to run on the shared test fixture DB).
func TestLockoutPruneTaskExecutes(t *testing.T) {
	pool := lockoutPruneTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var deleted int
	if err := pool.QueryRow(ctx, "SELECT prune_old_lockouts()").Scan(&deleted); err != nil {
		t.Fatalf("registered task SQL %q failed to execute: %v", "SELECT prune_old_lockouts()", err)
	}
	if deleted < 0 {
		t.Errorf("prune_old_lockouts() = %d deleted, must not be negative", deleted)
	}
}
