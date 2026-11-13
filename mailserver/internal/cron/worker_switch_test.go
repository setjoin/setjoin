package cron

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

// Observe actual committed PostgreSQL notifications at the worker seam. Both
// tasks are due on the first tick; only the enabled task may emit an effect.
func TestGoWorkersOffSuppressesOneCronTask(t *testing.T) {
	t.Setenv("GO_WORKERS_OFF", "unknown, cron:transferred-task ,cron:transferred-task")
	pool := testsupport.OpenTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	listener, err := pgx.Connect(ctx, pool.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close(context.Background()) }()
	channel := fmt.Sprintf("gofree_t8_cron_%d", time.Now().UnixNano())
	if _, err := listener.Exec(ctx, "LISTEN "+pgx.Identifier{channel}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	worker := New(pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())
	if err := worker.Register(
		&Task{Name: "transferred-task", Schedule: "@every 1h", SQL: fmt.Sprintf("SELECT pg_notify('%s', 'disabled')", channel), enabled: true},
		&Task{Name: "retained-task", Schedule: "@every 1h", SQL: fmt.Sprintf("SELECT pg_notify('%s', 'enabled')", channel), enabled: true},
	); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); worker.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("cron worker did not join")
		}
	})
	notification, err := listener.WaitForNotification(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if notification.Payload != "enabled" {
		t.Fatalf("disabled task ran: %s", notification.Payload)
	}
	cancel()
	<-done // completion joins every task, so all their effects are observable
	quiet, stop := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer stop()
	if n, err := listener.WaitForNotification(quiet); err == nil {
		t.Fatalf("unexpected task effect after join: %s", n.Payload)
	} else if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("notification observation failed: %v", err)
	}
}
