package mailboxlifecycle

import (
	"context"
	"testing"
	"time"

	"setjoin.com/mailserver/internal/mediaevict"
	"setjoin.com/shared/pgxutil"
)

type countingRemover struct {
	calls int
	err   error
}

func (r *countingRemover) RemoveParticipant(context.Context, string, string) error {
	r.calls++
	return r.err
}

// fakeTimer is one wait the eviction loop scheduled on the fake clock.
type fakeTimer struct {
	wait time.Duration
	ch   chan time.Time
}

func (t *fakeTimer) C() <-chan time.Time { return t.ch }

func (t *fakeTimer) Stop() {}

// fakeClock is the test clock threaded into the shared eviction loop. It
// publishes every scheduled wait, so a test can observe an established wait
// instead of guessing one with a sleep.
type fakeClock struct {
	now    time.Time
	timers chan *fakeTimer
}

func newFakeClock(now time.Time) *fakeClock {
	return &fakeClock{now: now, timers: make(chan *fakeTimer, 4)}
}

func (c *fakeClock) Now() time.Time { return c.now }

func (c *fakeClock) NewTimer(d time.Duration) mediaevict.Timer {
	ft := &fakeTimer{wait: d, ch: make(chan time.Time, 1)}
	c.timers <- ft
	return ft
}

// awaitTimer blocks until the eviction loop schedules its wait, proving the
// first attempt completed and the loop is parked in that wait before the
// test cancels.
func (c *fakeClock) awaitTimer(tb testing.TB) *fakeTimer {
	tb.Helper()
	select {
	case ft := <-c.timers:
		if ft.wait <= 0 {
			tb.Fatalf("established wait = %v, want a positive bounded wait", ft.wait)
		}
		return ft
	case <-time.After(2 * time.Second):
		tb.Fatal("eviction loop never established its wait")
		return nil
	}
}

// TestWorkerCancelledHorizonFailsEffectWithoutAckingTarget proves the drain
// routing for a ctx-cancelled horizon (AR-07 r2): the claimed evict_media
// effect lands on the mailbox_lifecycle_effect_fail sink and is never acked
// — no per-target completion, no effect completion. The cancellation fires
// only after the eviction loop's wait is observed established, so delayed
// scheduling cannot race the cancel. Recording sinks, no database, no skip
// path.
func TestWorkerCancelledHorizonFailsEffectWithoutAckingTarget(t *testing.T) {
	t.Parallel()
	base := time.Now()
	fc := newFakeClock(base)
	worker := NewWorker(pgxutil.WorkerPool{}, &countingRemover{}, nil, nil)
	settlements := &settlementRecorder{}
	worker.settlements = settlements
	worker.clock = fc

	until := base.Add(10 * time.Second)
	e := effect{
		IDText: "9", OperationID: "op-9", Kind: "evict_media", Attempt: 1,
		Targets: []target{{Room: "room", Identity: "u:7", EvictUntil: &until}},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		worker.settle(ctx, e)
	}()
	fc.awaitTimer(t) // the eviction loop is parked in its established wait
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("settle did not return after cancellation")
	}

	if len(settlements.fail) != 1 || settlements.fail[0].effectID != "9" {
		t.Fatalf("fail settlements=%+v, want the claimed effect routed to fail", settlements.fail)
	}
	if settlements.fail[0].detail != context.Canceled.Error() {
		t.Fatalf("fail detail=%q, want the cancellation error", settlements.fail[0].detail)
	}
	if len(settlements.complete) != 0 {
		t.Fatalf("complete settlements=%v, want none", settlements.complete)
	}
	if len(settlements.targetComplete) != 0 {
		t.Fatalf("target acks=%v, want the cancelled target never acked", settlements.targetComplete)
	}
}

func TestParsePositiveID(t *testing.T) {
	t.Parallel()
	if got, err := parsePositiveID("42"); err != nil || got != 42 {
		t.Fatalf("parsePositiveID(42)=%d,%v", got, err)
	}
	for _, bad := range []string{"", "0", "-1", "1x"} {
		if _, err := parsePositiveID(bad); err == nil {
			t.Fatalf("parsePositiveID(%q) succeeded", bad)
		}
	}
}
