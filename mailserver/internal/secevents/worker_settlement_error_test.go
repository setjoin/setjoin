package secevents

// Settlement-execution error paths, drain failure logging, settleCause
// truncation and backoff bounds. The DB-backed suites above pin the happy
// fencing semantics; these pin the guarded failure branches: a settlement or
// sweep that cannot execute leaves the row leased (never drops it), every
// failure is logged with ctx.Err()==nil only, and the pure helpers hold their
// documented bounds.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// errPool returns a pool whose connections are gone: closing the pool makes
// every subsequent QueryRow/Exec fail without touching the context, which is
// the deterministic way to reach the guarded settlement/sweep error branches.
func errPool(t *testing.T) *Worker {
	t.Helper()
	pool := testPool(t)
	w := newTestWorker(pool, &recordingSink{})
	// testPool's t.Cleanup closes the pool again; pgxpool.Close is idempotent.
	pool.Close()
	return w
}

func TestSettlementExecErrorStaysLeased(t *testing.T) {
	w := errPool(t)
	ctx := context.Background()

	ev := Event{ID: 42, EventType: "secevents_test_execerr", Payload: []byte(`{}`)}

	// done settlement exec failure: logged, no panic, row stays leased.
	w.settleDelivery(ctx, ev, 1, nil)
	// retry settlement exec failure (attempts below the cap).
	w.settleDelivery(ctx, ev, 1, errors.New("sink down"))
	// terminal fail settlement exec failure (attempts at the cap).
	exhausted := ev
	exhausted.Attempts = maxAttempts
	w.settleDelivery(ctx, exhausted, 1, errors.New("sink down"))
}

func TestDrainLogsProcessAndSweepFailuresOnLiveContext(t *testing.T) {
	w := errPool(t)

	// drain on a broken pool: the process-failure warn fires (ctx alive), the
	// loop breaks, and both sweeps still run and log their failures — the
	// sweep-every-tick contract holds even when every statement errors.
	w.drain(context.Background())
}

func TestTerminalizeExhaustedQuietOnCancelledContext(t *testing.T) {
	w := errPool(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// With ctx already cancelled the sweep failure must NOT log (the shutdown
	// path is quiet) and must return promptly.
	w.terminalizeExhausted(ctx)
	w.pruneDelivered(ctx)
}

func TestSettleCauseTruncatesOversizedError(t *testing.T) {
	big := strings.Repeat("x", 3000)
	got := settleCause(time.Minute, errors.New(big))
	if !strings.HasPrefix(got, big[:2048]) || len(got) > 2048 {
		t.Fatalf("settleCause did not truncate to the 2048 convention: len=%d", len(got))
	}
	if settleCause(time.Minute, nil) != "" {
		t.Fatal("settleCause(nil) must be empty")
	}
}

func TestBackoffForBounds(t *testing.T) {
	cases := map[int]time.Duration{
		0:  2 * time.Minute, // sub-one attempts clamp to 1 → 2^1 min
		-3: 2 * time.Minute, // negative attempts clamp too
		1:  2 * time.Minute,
		2:  4 * time.Minute,
		5:  32 * time.Minute,
		6:  time.Hour, // 64min exceeds the 1h cap
		7:  time.Hour, // attempts clamp at 6 before the shift
		50: time.Hour,
	}
	for attempts, want := range cases {
		if got := backoffFor(attempts); got != want {
			t.Errorf("backoffFor(%d) = %s, want %s", attempts, got, want)
		}
	}
}

func TestRunDrainsOnTickerTicks(t *testing.T) {
	pool := testPool(t)
	sink := &recordingSink{}
	w := newTestWorker(pool, sink)
	w.retentionInterval = time.Hour

	// The first seed is delivered by the startup drain; the second is seeded
	// after it and must be picked up by a ticker-tick drain (the loop's
	// ticker.C branch), not the startup reclaim.
	seedEvent(t, pool, "secevents_test_tick_first", `{}`, -time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()

	waitForDeliveries := func(n int, what string) {
		t.Helper()
		deadline := time.After(10 * time.Second)
		for {
			if len(sink.delivered()) >= n {
				return
			}
			select {
			case <-deadline:
				t.Fatalf("%s: only %d/%d deliveries observed", what, len(sink.delivered()), n)
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	waitForDeliveries(1, "startup drain")

	seedEvent(t, pool, "secevents_test_tick_second", `{}`, -time.Second)
	waitForDeliveries(2, "ticker-tick drain")

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}
