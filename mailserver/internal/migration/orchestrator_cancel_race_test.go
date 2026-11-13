package migration

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"io"

	"setjoin.com/shared/testsupport"
)

// Regression for D-MAILSERVER-INTERNAL-MIGRATION-F-003 (state-machine race /
// TOCTOU on the control handle): StartJob must publish the job's REAL cancel
// under the orchestrator mutex, so a CancelJob that lands immediately after
// the job becomes visible cancels the live context — never a do-nothing
// placeholder — and the unsynchronized js.cancel write (a data race against
// CancelJob's read) cannot happen. Run with -race: the old post-Unlock
// assignment trips the detector under this interleaving.
func TestStartJobPublishesCancelBeforeVisible(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	o := NewOrchestrator(pool, nil, "", "cancel-race-root", logger, context.Background(), nil)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		jobID := int64(990000 + i)
		wg.Add(2)
		go func() {
			defer wg.Done()
			// The job row does not exist, so runJob fails fast after the
			// control-handle publish — which is exactly the window raced here.
			_ = o.StartJob(context.Background(), jobID)
		}()
		go func() {
			defer wg.Done()
			// Cancelling a job that may not be (or no longer be) in the map is
			// a legitimate racing caller; the outcome must be error-or-cancel,
			// never a race on js.cancel.
			_ = o.CancelJob(jobID)
		}()
	}
	wg.Wait()

	// Every started job must have carried a real cancel func, and no state may
	// remain once the runs finish: runJob's defer deletes each entry even when
	// loadJob fails fast on the missing row. The wg above joins only the
	// StartJob/CancelJob callers — the 50 runJob goroutines are still draining
	// (each needs a DB roundtrip before its deferred delete), so the emptiness
	// check must poll with a deadline instead of racing the goroutines it
	// cannot join.
	deadline := time.Now().Add(30 * time.Second)
	for {
		o.mu.Lock()
		remaining := len(o.activeJobs)
		o.mu.Unlock()
		if remaining == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d jobs leaked in activeJobs after failed runs", remaining)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
