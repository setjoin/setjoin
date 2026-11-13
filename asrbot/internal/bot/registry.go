// Package bot is the room-bot's control surface: the loopback-only HTTP API
// the gateway drives and the per-room LiveKit session that streams captions.
package bot

import (
	"context"
	"sort"
	"sync"
)

// RoomRunner is the LiveKit adapter behind RoomRegistry. Run blocks until the
// room disconnects or ctx is cancelled. Capacity, identity and cancellation
// remain registry decisions; the runner only owns the media lifecycle.
type RoomRunner interface {
	Run(ctx context.Context, room, token string)
}

// RoomRegistry is the single process-local authority for room admission,
// capacity, cancellation, identity-safe release and status.
type RoomRegistry struct {
	mu       sync.Mutex
	max      int
	runner   RoomRunner
	sessions map[string]*roomSession
}

type roomSession struct {
	room     string
	ctx      context.Context
	cancel   context.CancelFunc
	stopping bool // guarded by RoomRegistry.mu
}

// NewRoomRegistry returns a registry capped at max concurrent rooms.
func NewRoomRegistry(max int, runner RoomRunner) *RoomRegistry {
	return &RoomRegistry{
		max:      max,
		runner:   runner,
		sessions: make(map[string]*roomSession),
	}
}

// Start atomically reserves room before asynchronously starting its runner.
// It returns true for both a new admission and an idempotent active repeat.
// It returns false when capacity is full or the same identity is stopping; a
// stopping start must not be acknowledged and then disappear on old cleanup.
func (r *RoomRegistry) Start(room, token string) bool {
	session, admitted, ok := r.admit(room)
	if !ok || !admitted {
		return ok
	}
	go r.execute(session, token)
	return true
}

// admit is split from Start only so the admission-to-runner race can be
// exercised deterministically. It returns the current identity, whether this
// call created it, and whether the room was accepted.
func (r *RoomRegistry) admit(room string) (*roomSession, bool, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if session := r.sessions[room]; session != nil {
		if session.stopping {
			return nil, false, false
		}
		return session, false, true
	}
	if len(r.sessions) >= r.max {
		return nil, false, false
	}
	ctx, cancel := context.WithCancel(context.Background())
	session := &roomSession{room: room, ctx: ctx, cancel: cancel}
	r.sessions[room] = session
	return session, true, true
}

func (r *RoomRegistry) execute(session *roomSession, token string) {
	defer r.release(session)
	// Stop may win after admission but before this goroutine is scheduled.
	// A cancelled identity must never be handed to the LiveKit adapter.
	select {
	case <-session.ctx.Done():
		return
	default:
	}
	r.runner.Run(session.ctx, session.room, token)
}

// Stop cancels the current identity for room. It is idempotent. The identity
// remains admitted until execute returns and compare-releases it, so a slow
// runner drain cannot let replacement work exceed the configured capacity.
func (r *RoomRegistry) Stop(room string) {
	r.mu.Lock()
	session := r.sessions[room]
	if session != nil {
		session.stopping = true
	}
	r.mu.Unlock()
	if session != nil {
		session.cancel()
	}
}

// release removes only the exact identity whose runner ended. An old runner
// can therefore never release a newer session admitted for the same room.
func (r *RoomRegistry) release(session *roomSession) bool {
	r.mu.Lock()
	same := r.sessions[session.room] == session
	if same {
		delete(r.sessions, session.room)
	}
	r.mu.Unlock()
	if same {
		session.cancel()
	}
	return same
}

// Rooms returns all admitted room ids in stable order for GET /status.
func (r *RoomRegistry) Rooms() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.sessions))
	for room := range r.sessions {
		out = append(out, room)
	}
	sort.Strings(out)
	return out
}
