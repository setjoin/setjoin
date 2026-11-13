package mediaevict

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/twitchtv/twirp"
)

// fakeClock steps fake time; the shared set asserts against fake-time steps
// and never against real durations (scheduling delay must not be able to
// invalidate a call count).
type fakeClock struct {
	now    time.Time
	timers chan *fakeTimer
}

type fakeTimer struct {
	clock   *fakeClock
	wait    time.Duration
	ch      chan time.Time
	stopped bool
}

func newFakeClock(start time.Time) *fakeClock {
	return &fakeClock{now: start, timers: make(chan *fakeTimer, 32)}
}

func (c *fakeClock) Now() time.Time { return c.now }

func (c *fakeClock) NewTimer(d time.Duration) Timer {
	t := &fakeTimer{clock: c, wait: d, ch: make(chan time.Time, 1)}
	c.timers <- t
	return t
}

func (t *fakeTimer) C() <-chan time.Time { return t.ch }

func (t *fakeTimer) Stop() { t.stopped = true }

// nextTimer receives the next timer the loop schedules. It doubles as the
// synchronization point proving the loop created its wait.
func (c *fakeClock) nextTimer(t *testing.T) *fakeTimer {
	t.Helper()
	select {
	case ft := <-c.timers:
		return ft
	case <-time.After(2 * time.Second):
		t.Fatal("eviction loop never scheduled a wait")
		return nil
	}
}

// fire steps fake time forward and releases the established wait.
func (t *fakeTimer) fire(d time.Duration) {
	t.clock.now = t.clock.now.Add(d)
	t.ch <- t.clock.now
}

// expectNoTimer proves the loop scheduled no wait.
func (c *fakeClock) expectNoTimer(t *testing.T) {
	t.Helper()
	select {
	case ft := <-c.timers:
		t.Fatalf("unexpected wait of %v scheduled", ft.wait)
	default:
	}
}

type recordingRemover struct {
	calls chan struct{}
	err   error
}

func (r *recordingRemover) RemoveParticipant(context.Context, string, string) error {
	r.calls <- struct{}{}
	return r.err
}

func waitResult(t *testing.T, errc <-chan error) error {
	t.Helper()
	select {
	case err := <-errc:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("eviction loop did not return")
		return nil
	}
}

// TestEvictParticipantThroughKicksOncePerTimerFireThroughHorizon pins the
// cadence: exactly one RemoveParticipant per timer fire, each wait exactly
// min(5s, remaining) in fake time, and a final attempt exactly on the
// horizon before returning nil.
func TestEvictParticipantThroughKicksOncePerTimerFireThroughHorizon(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	fc := newFakeClock(base)
	rooms := &recordingRemover{calls: make(chan struct{}, 16)}
	until := base.Add(12 * time.Second)

	errc := make(chan error, 1)
	go func() {
		errc <- evictThrough(context.Background(), rooms, "room", "u:7", &until, fc)
	}()

	// While the horizon is ahead the waits are exactly 5s, 5s, then the
	// 2s remainder.
	for i, want := range []time.Duration{5 * time.Second, 5 * time.Second, 2 * time.Second} {
		<-rooms.calls
		ft := fc.nextTimer(t)
		if ft.wait != want {
			t.Fatalf("wait %d = %v, want exactly %v", i+1, ft.wait, want)
		}
		ft.fire(want)
	}
	// The horizon-boundary attempt runs, then the loop stops without
	// scheduling another wait.
	<-rooms.calls
	fc.expectNoTimer(t)
	if err := waitResult(t, errc); err != nil {
		t.Fatalf("eviction through horizon = %v, want nil", err)
	}
	select {
	case <-rooms.calls:
		t.Fatal("extra eviction attempt after horizon")
	default:
	}
}

// TestEvictParticipantThroughNilHorizonClassifiesOnce pins the nil-horizon
// one-shot across the remover-result classification: success and NotFound
// both settle nil (absence is success for the attempt) while any other error
// surfaces immediately — every case with exactly one call and no wait
// scheduled. A nil-horizon shortcut that returned the raw remover error or
// scheduled a timer cannot pass.
func TestEvictParticipantThroughNilHorizonClassifiesOnce(t *testing.T) {
	t.Parallel()
	notFound := twirp.NewError(twirp.NotFound, "participant absent")
	ordinary := errors.New("sfu unavailable")
	tests := []struct {
		name    string
		err     error
		wantErr error
	}{
		{"success", nil, nil},
		{"notFound", notFound, nil},
		{"ordinaryError", ordinary, ordinary},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fc := newFakeClock(time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC))
			rooms := &recordingRemover{calls: make(chan struct{}, 4), err: test.err}

			errc := make(chan error, 1)
			go func() {
				errc <- evictThrough(context.Background(), rooms, "room", "u:7", nil, fc)
			}()

			<-rooms.calls
			if err := waitResult(t, errc); !errors.Is(err, test.wantErr) {
				t.Fatalf("nil-horizon eviction = %v, want %v", err, test.wantErr)
			}
			// Assert only after the loop has fully returned: the remover
			// publishes its call before returning, so an earlier check could
			// observe an empty timer queue before a buggy loop schedules one.
			fc.expectNoTimer(t)
			select {
			case <-rooms.calls:
				t.Fatal("nil horizon produced more than one attempt")
			default:
			}
		})
	}
}

// TestEvictParticipantThroughNotFoundKeepsKickingThroughHorizon pins the
// repeated-NotFound contract: every attempt classifying as absent still
// returns nil and the loop keeps kicking through the horizon. An early-exit
// optimization on NotFound would fail here.
func TestEvictParticipantThroughNotFoundKeepsKickingThroughHorizon(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	fc := newFakeClock(base)
	rooms := &recordingRemover{
		calls: make(chan struct{}, 16),
		err:   twirp.NewError(twirp.NotFound, "participant absent"),
	}
	until := base.Add(10 * time.Second)

	errc := make(chan error, 1)
	go func() {
		errc <- evictThrough(context.Background(), rooms, "room", "u:7", &until, fc)
	}()

	for i, want := range []time.Duration{5 * time.Second, 5 * time.Second} {
		<-rooms.calls
		ft := fc.nextTimer(t)
		if ft.wait != want {
			t.Fatalf("wait %d = %v, want exactly %v despite NotFound", i+1, ft.wait, want)
		}
		ft.fire(want)
	}
	<-rooms.calls
	fc.expectNoTimer(t)
	if err := waitResult(t, errc); err != nil {
		t.Fatalf("persistent NotFound = %v, want nil through the horizon", err)
	}
}

// TestEvictParticipantThroughExpiredHorizonAttemptsOnce pins terminal
// attempts: an expired or past horizon yields exactly one attempt, no wait.
func TestEvictParticipantThroughExpiredHorizonAttemptsOnce(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	fc := newFakeClock(base)
	rooms := &recordingRemover{calls: make(chan struct{}, 4)}
	past := base.Add(-time.Second)

	errc := make(chan error, 1)
	go func() {
		errc <- evictThrough(context.Background(), rooms, "room", "u:7", &past, fc)
	}()

	<-rooms.calls
	fc.expectNoTimer(t)
	if err := waitResult(t, errc); err != nil {
		t.Fatalf("expired-horizon eviction = %v, want nil", err)
	}
	select {
	case <-rooms.calls:
		t.Fatal("expired horizon produced more than one attempt")
	default:
	}
}

// TestEvictParticipantThroughSurfacesNonNotFoundErrorsImmediately pins error
// surfacing: a non-NotFound error is returned immediately, with no in-loop
// retry and no wait scheduled, even while the horizon is still ahead.
func TestEvictParticipantThroughSurfacesNonNotFoundErrorsImmediately(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	fc := newFakeClock(base)
	want := errors.New("sfu unavailable")
	rooms := &recordingRemover{calls: make(chan struct{}, 4), err: want}
	until := base.Add(time.Hour)

	errc := make(chan error, 1)
	go func() {
		errc <- evictThrough(context.Background(), rooms, "room", "u:7", &until, fc)
	}()

	<-rooms.calls
	fc.expectNoTimer(t)
	if err := waitResult(t, errc); !errors.Is(err, want) {
		t.Fatalf("eviction error = %v, want %v surfaced immediately", err, want)
	}
}

// TestEvictParticipantThroughCancelDuringEstablishedWaitStopsTimer pins
// cancellation during an established wait: ctx.Err() is returned promptly,
// the timer is stopped, and nothing is left waiting.
func TestEvictParticipantThroughCancelDuringEstablishedWaitStopsTimer(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	fc := newFakeClock(base)
	rooms := &recordingRemover{calls: make(chan struct{}, 4)}
	until := base.Add(time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		errc <- evictThrough(ctx, rooms, "room", "u:7", &until, fc)
	}()

	<-rooms.calls
	ft := fc.nextTimer(t)
	cancel()
	if err := waitResult(t, errc); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled eviction error = %v, want context.Canceled", err)
	}
	if !ft.stopped {
		t.Fatal("established wait was not stopped on cancellation")
	}
}

// TestParticipantNotFoundClassifiesTwirpNotFoundOnly pins the twirp
// classification: NotFound (including wrapped) is absence, everything else —
// including nil — is not.
func TestParticipantNotFoundClassifiesTwirpNotFoundOnly(t *testing.T) {
	t.Parallel()
	notFound := twirp.NewError(twirp.NotFound, "participant absent")
	if !ParticipantNotFound(notFound) {
		t.Fatal("twirp NotFound was not classified as absence")
	}
	if !ParticipantNotFound(fmt.Errorf("kick: %w", notFound)) {
		t.Fatal("wrapped twirp NotFound was not classified as absence")
	}
	if ParticipantNotFound(errors.New("absent")) {
		t.Fatal("plain error was classified as absence")
	}
	if ParticipantNotFound(twirp.NewError(twirp.Internal, "boom")) {
		t.Fatal("non-NotFound twirp code was classified as absence")
	}
	if ParticipantNotFound(nil) {
		t.Fatal("nil error was classified as absence")
	}
}

// TestEvictParticipantThroughTerminalAttemptsViaExportedDefaultClock smokes
// the exported entrypoint and its default system clock on the deterministic
// terminal attempts (nil and already-past horizons), which involve no wait.
func TestEvictParticipantThroughTerminalAttemptsViaExportedDefaultClock(t *testing.T) {
	t.Parallel()
	past := time.Now().Add(-time.Second)
	oneShot := &countingRemover{}
	if err := EvictParticipantThrough(context.Background(), oneShot, "room", "u:7", nil); err != nil {
		t.Fatalf("nil-horizon eviction = %v", err)
	}
	if err := EvictParticipantThrough(context.Background(), oneShot, "room", "u:7", &past); err != nil {
		t.Fatalf("expired-horizon eviction = %v", err)
	}
	if oneShot.calls != 2 {
		t.Fatalf("terminal eviction calls=%d, want 2", oneShot.calls)
	}
}

type countingRemover struct {
	calls int
	err   error
}

func (r *countingRemover) RemoveParticipant(context.Context, string, string) error {
	r.calls++
	return r.err
}
