//go:build integration
// +build integration

package cron

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"log/slog"

	"setjoin.com/shared/pgxutil"
)

func TestCronWorker_Integration(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		dsn = "postgres://mail@127.0.0.1:5432/mailserver?sslmode=disable"
	}

	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Skipf("cannot connect to test DB: %v", err)
	}
	defer pool.Close()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Create worker with 5 fast tasks
	worker := New(pgxutil.WorkerPool{Pool: pool}, logger)
	if err := worker.Register(
		&Task{Name: "test-health-check", Schedule: "@every 3s", SQL: "SELECT health_check()", Timeout: 5 * time.Second, enabled: true},
		&Task{Name: "test-prune-ws", Schedule: "@every 3s", SQL: "SELECT prune_ws_subscriptions()", Timeout: 5 * time.Second, enabled: true},
		&Task{Name: "test-dispatch", Schedule: "@every 3s", SQL: "SELECT dispatch_scheduled_actions('test')", Timeout: 5 * time.Second, enabled: true},
		&Task{Name: "test-prune-logs", Schedule: "@every 3s", SQL: "SELECT prune_log_tables()", Timeout: 5 * time.Second, enabled: true},
		&Task{Name: "test-disabled", Schedule: "@every 1s", SQL: "SELECT 1", Timeout: 1 * time.Second, enabled: false},
	); err != nil {
		t.Fatalf("register: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Run worker in background
	go worker.Run(ctx)

	// Wait for at least 2 cycles
	time.Sleep(7 * time.Second)
	cancel()

	// Verify each enabled task ran at least once
	snap := worker.metrics.Snapshot()
	for _, task := range worker.Tasks() {
		if !task.enabled {
			continue // disabled tasks shouldn't run and won't have metrics
		}
		m, ok := snap[task.Name]
		if !ok || m.SuccessCount < 1 {
			t.Errorf("task %q: expected at least 1 success, got %d. Last error: %q",
				task.Name, m.SuccessCount, m.LastError)
			continue
		}
		t.Logf("task %q: %d successes, avg duration %v", task.Name, m.SuccessCount, m.AvgDuration)
	}
}

func TestCronWorker_AllTasksParse(t *testing.T) {
	tasks := AllTasks()
	// Pre-existing drift found while adding Chat A4a Task 6's chat-purge-expired
	// task: this build-tag-gated ("integration") count had already fallen behind
	// tasks_test.go's (25 vs the real 26) before this change; repinned to the
	// true count (27) rather than compounding the drift further. Task 9 added
	// chat-chain-anchor (28).
	if len(tasks) != 29 {
		t.Errorf("AllTasks() = %d, want 29", len(tasks))
	}
	seen := make(map[string]bool)
	for _, task := range tasks {
		if seen[task.Name] {
			t.Errorf("duplicate task: %s", task.Name)
		}
		seen[task.Name] = true
		if task.SQL == "" {
			t.Errorf("task %q: empty SQL", task.Name)
		}
		if task.Timeout <= 0 {
			t.Errorf("task %q: timeout not set", task.Name)
		}
		interval, cronExpr, err := parseSchedule(task.Schedule)
		if err != nil {
			t.Errorf("task %q: invalid schedule %q: %v", task.Name, task.Schedule, err)
		}
		if interval == 0 && cronExpr == "" {
			t.Errorf("task %q: schedule %q not parsed", task.Name, task.Schedule)
		}
	}
}
