// Package mediaevict owns the one shared participant-eviction side effect
// loop used by the durable-effect workers. It has no database access and no
// domain knowledge: a horizon and a participant remover are its entire
// world. Claims, leases, acknowledgements and retry ledgers stay with the
// calling workers and their reducers, which remain the business authority.
package mediaevict

import (
	"context"
	"errors"
	"time"

	"github.com/twitchtv/twirp"
)

// ParticipantRemover is the consumer-side view of the meet-provided rooms
// value. It is satisfied by the same concrete rooms the composition root
// already wires into every eviction consumer; the meet package is unmodified.
type ParticipantRemover interface {
	RemoveParticipant(ctx context.Context, room, identity string) error
}

// evictPollInterval caps one in-loop wait between eviction attempts.
const evictPollInterval = 5 * time.Second

// EvictParticipantThrough kicks RemoveParticipant until the reducer-supplied
// horizon has passed, blocking its caller for up to that horizon. It never
// claims, acks or records anything; the domain ledger owns retry. The
// semantics are shared verbatim by every consumer:
//
//   - a twirp NotFound classifies as success for that attempt but does NOT
//     stop the loop; attempts continue until the horizon passes;
//   - a nil horizon (or one already in the past) yields exactly one attempt;
//   - any non-NotFound error is returned immediately, with no in-loop retry
//     and no wait scheduled;
//   - each wait is exactly min(evictPollInterval, time remaining);
//   - cancellation during a wait stops the timer and returns ctx.Err().
func EvictParticipantThrough(
	ctx context.Context,
	rooms ParticipantRemover,
	room, identity string,
	until *time.Time,
) error {
	return evictThrough(ctx, rooms, room, identity, until, systemClock{})
}

// EvictParticipantThroughClock behaves exactly like EvictParticipantThrough
// but runs the loop on the supplied clock; nil selects the system clock. It
// exists so calling workers can thread a test clock down to the shared loop
// and let their tests observe an established wait; production wiring always
// uses EvictParticipantThrough and never constructs a Clock.
func EvictParticipantThroughClock(
	ctx context.Context,
	rooms ParticipantRemover,
	room, identity string,
	until *time.Time,
	c Clock,
) error {
	if c == nil {
		c = systemClock{}
	}
	return evictThrough(ctx, rooms, room, identity, until, c)
}

// Clock is the time seam of the eviction loop. The exported entrypoint always
// passes the system clock, so production callers and wiring never construct
// one; the clock-carrying entrypoint exists for calling workers' tests. Tests
// inject fake-time implementations and assert against fake-time steps, never
// real durations.
type Clock interface {
	Now() time.Time
	NewTimer(d time.Duration) Timer
}

// Timer is one wait handle between eviction attempts.
type Timer interface {
	C() <-chan time.Time
	Stop()
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func (systemClock) NewTimer(d time.Duration) Timer {
	return systemTimer{t: time.NewTimer(d)}
}

type systemTimer struct{ t *time.Timer }

func (s systemTimer) C() <-chan time.Time { return s.t.C }

func (s systemTimer) Stop() { s.t.Stop() }

func evictThrough(
	ctx context.Context,
	rooms ParticipantRemover,
	room, identity string,
	until *time.Time,
	c Clock,
) error {
	for {
		err := rooms.RemoveParticipant(ctx, room, identity)
		if err != nil && !ParticipantNotFound(err) {
			return err
		}
		if until == nil || !c.Now().Before(*until) {
			return nil
		}
		t := c.NewTimer(min(evictPollInterval, until.Sub(c.Now())))
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C():
		}
	}
}

// ParticipantNotFound reports whether err is a twirp NotFound: the
// participant (or its room) is already gone. This module is the single
// place that decides what "absent" means on the wire; callers treat it as
// success for the attempt.
func ParticipantNotFound(err error) bool {
	var twerr twirp.Error
	return errors.As(err, &twerr) && twerr.Code() == twirp.NotFound
}
