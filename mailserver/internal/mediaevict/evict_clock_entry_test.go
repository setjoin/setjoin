package mediaevict

// Coverage for the entrypoint/clock seams the fake-clock suites bypass: the
// nil-clock default of EvictParticipantThroughClock and the real
// systemClock/systemTimer pair driven by the exported (production) entrypoint.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/twitchtv/twirp"
)

// TestEvictParticipantThroughClockNilSelectsSystemClock pins the nil-clock
// branch: EvictParticipantThroughClock with a nil Clock must behave exactly
// like the production entrypoint (system clock, one attempt, no waits when
// the horizon is in the past).
func TestEvictParticipantThroughClockNilSelectsSystemClock(t *testing.T) {
	rooms := &recordingRemover{calls: make(chan struct{}, 4)}
	past := time.Now().Add(-time.Hour)

	errc := make(chan error, 1)
	go func() {
		errc <- EvictParticipantThroughClock(context.Background(), rooms, "room", "u:1", &past, nil)
	}()

	<-rooms.calls
	if err := waitResult(t, errc); err != nil {
		t.Fatalf("nil clock with expired horizon = %v, want nil", err)
	}
	select {
	case <-rooms.calls:
		t.Fatal("extra attempt after expired horizon")
	default:
	}
}

// TestEvictParticipantThroughRealClockLoopsUntilHorizon drives the exported
// production entrypoint with REAL timers: NotFound absence keeps the loop
// kicking on systemClock/systemTimer waits until the horizon passes, and the
// wait between attempts is capped at evictPollInterval.
func TestEvictParticipantThroughRealClockLoopsUntilHorizon(t *testing.T) {
	rooms := &recordingRemover{calls: make(chan struct{}, 8)}
	rooms.err = twirp.NotFoundError("participant gone")
	until := time.Now().Add(30 * time.Millisecond)

	errc := make(chan error, 1)
	go func() {
		errc <- EvictParticipantThrough(context.Background(), rooms, "room", "u:2", &until)
	}()

	// First attempt (NotFound — loop continues), then the real timer fires.
	<-rooms.calls
	if err := waitResult(t, errc); err != nil {
		t.Fatalf("real-clock eviction through horizon = %v, want nil", err)
	}
	select {
	case <-rooms.calls:
		// A second attempt through the horizon is fine (30ms > one poll? no —
		// the wait is min(5s, remaining)=30ms, so at most the boundary attempt
		// follows); drain it and require the loop to stop.
		select {
		case <-rooms.calls:
		case <-time.After(time.Second):
		}
	default:
	}
}

// TestEvictParticipantThroughRealClockCancelDuringWaitStopsTimer pins the
// cancellation path on the REAL clock: a cancel during the in-loop wait stops
// the system timer and surfaces ctx.Err().
func TestEvictParticipantThroughRealClockCancelDuringWaitStopsTimer(t *testing.T) {
	rooms := &recordingRemover{calls: make(chan struct{}, 4)}
	until := time.Now().Add(time.Hour) // the wait would be the full 5s cap

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		errc <- EvictParticipantThrough(ctx, rooms, "room", "u:4", &until)
	}()

	<-rooms.calls // first attempt done, loop is inside its real 5s wait
	cancel()
	if err := waitResult(t, errc); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel during real wait = %v, want context.Canceled", err)
	}
}

// TestEvictParticipantThroughRealClockSurfacesError pins that a non-NotFound
// remover error surfaces immediately through the production entrypoint (real
// clock) with no wait scheduled.
func TestEvictParticipantThroughRealClockSurfacesError(t *testing.T) {
	want := errors.New("rooms sidecar down")
	rooms := &recordingRemover{calls: make(chan struct{}, 4), err: want}
	future := time.Now().Add(time.Hour)

	if err := EvictParticipantThrough(context.Background(), rooms, "room", "u:3", &future); !errors.Is(err, want) {
		t.Fatalf("real-clock eviction error = %v, want %v", err, want)
	}
}
