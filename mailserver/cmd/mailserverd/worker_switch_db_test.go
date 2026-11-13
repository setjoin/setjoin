package main

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"setjoin.com/mailserver/internal/cron"
	"setjoin.com/mailserver/internal/metrics"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

// Use the real named scheduler and formerly direct metrics collector. Observe
// their external effects, not launcher logs: a committed notification from one
// scheduler tick and the collector's published Prometheus sample.
func TestGoWorkersOffAtWorkerSeam(t *testing.T) {
	for _, tc := range []struct {
		name, off string
		enabled   bool
	}{
		{"default", "", true},
		{"transferred", " cron, identity-metrics ,cron", false},
		{"exact-names-only", "cron-extra,identity-metrics-extra,unknown", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GO_WORKERS_OFF", tc.off)
			pool := testsupport.OpenTestPool(t)
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			listener, err := pgx.Connect(ctx, pool.Config().ConnString())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close(context.Background()) }()
			channel := fmt.Sprintf("gofree_t8_switch_%d", time.Now().UnixNano())
			if _, err := listener.Exec(ctx, "LISTEN "+pgx.Identifier{channel}.Sanitize()); err != nil {
				t.Fatal(err)
			}
			scheduler := cron.New(pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())
			task := cron.AllTasks()[0]
			// The fixture replaces one task's reducer with an observable tick;
			// scheduling, startup validation, singleton lock and joins stay real.
			task.SQL = fmt.Sprintf("SELECT pg_notify('%s', 'tick')", channel)
			task.Schedule = "@every 1h"
			if err := scheduler.Register(task); err != nil {
				t.Fatal(err)
			}
			collector := metrics.NewHandler()
			schedulerDone, collectorDone := make(chan struct{}), make(chan struct{})
			launchWorker(ctx, testsupport.TestLogger(), "cron", func(ctx context.Context) {
				defer close(schedulerDone)
				scheduler.Run(ctx)
			})
			launchWorker(ctx, testsupport.TestLogger(), "identity-metrics", func(ctx context.Context) {
				defer close(collectorDone)
				collector.RunIdentityCollector(ctx, pool, testsupport.TestLogger())
			})
			t.Cleanup(func() {
				cancel()
				if tc.enabled {
					for _, done := range []<-chan struct{}{schedulerDone, collectorDone} {
						select {
						case <-done:
						case <-time.After(3 * time.Second):
							t.Error("worker failed to stop")
						}
					}
				}
			})
			observeCtx, stopObserve := context.WithTimeout(ctx, 1500*time.Millisecond)
			defer stopObserve()
			notification, err := listener.WaitForNotification(observeCtx)
			if tc.enabled {
				if err != nil {
					t.Fatalf("enabled scheduler produced no tick: %v", err)
				}
				if notification.Payload != "tick" {
					t.Fatalf("unexpected effect: %s", notification.Payload)
				}
			} else if err == nil {
				t.Fatalf("disabled scheduler produced an effect: %s", notification.Payload)
			} else if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("notification observation failed: %v", err)
			}
			response := httptest.NewRecorder()
			collector.ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
			want := "gateway_identity_collector_success 0\n"
			if tc.enabled {
				want = "gateway_identity_collector_success 1\n"
			}
			if !strings.Contains(response.Body.String(), want) {
				t.Fatalf("collector sample missing %q", want)
			}
		})
	}
}
