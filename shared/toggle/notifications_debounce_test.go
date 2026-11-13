package toggle

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

// Edge coverage for the debounced reloader and the BindNotifications cleanup
// and reload-failure arms.

// TestDebouncedReloaderCoalescesBurstsLastWins pins the debounce contract:
// N notifications inside one window arm it once, the LAST payload wins, and
// run executes exactly once when the window closes.
func TestDebouncedReloaderCoalescesBurstsLastWins(t *testing.T) {
	d := newDebouncedReloader(40 * time.Millisecond)
	var calls int32
	var last atomic.Value
	last.Store("")
	done := make(chan struct{})
	run := func(n Notification) {
		atomic.AddInt32(&calls, 1)
		last.Store(n.Key)
		close(done)
	}

	d.schedule(Notification{Key: "first"}, run)
	d.schedule(Notification{Key: "second"}, run)
	d.schedule(Notification{Key: "third"}, run)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("debounced run never executed")
	}
	time.Sleep(60 * time.Millisecond) // allow any improper second firing
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("run calls = %d, want exactly 1", got)
	}
	if last.Load().(string) != "third" {
		t.Fatalf("last payload = %q, want third (last wins)", last.Load())
	}

	// A later notification re-arms the window after it closed.
	d.schedule(Notification{Key: "fourth"}, func(n Notification) {})
	time.Sleep(100 * time.Millisecond)
}

// TestDebouncedReloaderStopCancelsPending pins stop(): a pending window that
// is stopped never hands its payload to run.
func TestDebouncedReloaderStopCancelsPending(t *testing.T) {
	d := newDebouncedReloader(30 * time.Millisecond)
	var called int32
	d.schedule(Notification{Key: "pending"}, func(n Notification) {
		atomic.AddInt32(&called, 1)
	})
	d.stop()
	time.Sleep(80 * time.Millisecond)
	if atomic.LoadInt32(&called) != 0 {
		t.Fatalf("run fired %d times after stop, want 0", called)
	}
	// Stop is idempotent.
	d.stop()
}

// TestBindNotificationsCleanupOnContextDone pins the lifecycle cleanup: when
// the bound context is cancelled the reloader is stopped, the reconnect hook
// is removed, and the durable subscription is released exactly once.
func TestBindNotificationsCleanupOnContextDone(t *testing.T) {
	withDebounceInterval(t, 20*time.Millisecond)
	listener := &notificationTestListener{}
	flags := &notificationTestFlags{}
	ctx, cancel := context.WithCancel(context.Background())

	if err := BindNotifications(ctx, listener, flags, ObserverFunc(func(context.Context, Notification) {}), slog.Default()); err != nil {
		t.Fatalf("bind: %v", err)
	}
	cancel()
	<-ctx.Done()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, _, unsubscribed, _, reconnRemoved := listener.snapshot()
		if len(unsubscribed) == 1 && reconnRemoved {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	_, _, unsubscribed, reconnRegistered, reconnRemoved := listener.snapshot()
	t.Fatalf("cleanup incomplete: unsubscribed=%v reconnRegistered=%v reconnRemoved=%v",
		unsubscribed, reconnRegistered, reconnRemoved)
}

// TestBindNotificationsReloadFailureFailsBind pins the startup arm: a failing
// authoritative reload after a successful subscribe cleans up and surfaces
// the error to the caller.
func TestBindNotificationsReloadFailureFailsBind(t *testing.T) {
	withDebounceInterval(t, 20*time.Millisecond)
	listener := &notificationTestListener{}
	flags := &notificationTestFlags{reloadError: errors.New("snapshot store unavailable")}
	err := BindNotifications(context.Background(), listener, flags,
		ObserverFunc(func(context.Context, Notification) {}), slog.Default())
	if err == nil {
		t.Fatal("BindNotifications with failing reload: want error")
	}
	_, _, unsubscribed, _, reconnRemoved := listener.snapshot()
	if len(unsubscribed) != 1 || !reconnRemoved {
		t.Fatalf("cleanup after reload failure: unsubscribed=%v reconnRemoved=%v", unsubscribed, reconnRemoved)
	}
}
