package meet

import (
	"context"
	"fmt"
	"sync"
)

// fakeRooms is the RoomController test double every meet package test uses
// to prove the eviction invariant (spike §2 finding 1 / DES-011: every
// revocation path terminates in a RoomService call, never just a DB
// update): it never touches a real SFU, only records every call so a test
// can assert exactly which authority-revoking calls fired, in what order,
// with what arguments — and can inject a failure for one specific call to
// exercise the 502-and-log path (Task 10).
type fakeRooms struct {
	mu    sync.Mutex
	calls []string
	// errs maps a recorded call string (e.g. "DeleteRoom:room-a") to an
	// error that call should return — the injection seam Task 10's
	// controller-error tests need.
	errs map[string]error
	// rooms is what ListRooms returns — the Task 12 reconcile worker's seam
	// for simulating "the SFU still lists this room" vs. "the SFU has
	// forgotten it entirely" (both reconcile legs branch on ListRooms'
	// result). Defaults to nil/empty, which every Task 9/10/11 test already
	// implicitly relies on (none of them populate it).
	rooms []string
	// participants is what ListParticipants reports per room — the Task 5
	// breakout assignment↔presence worker arm's test seam (the setRooms
	// genre). Defaults to nil/empty, which every pre-Task-5 test implicitly
	// relies on (none of them populate it, so ListParticipants keeps
	// returning nil exactly as before).
	participants map[string][]string
	// createTimeouts records the (emptyTimeout, departureTimeout) pair the
	// most recent CreateRoom/CreateRoomWithTimeouts call used for a given
	// room — the eng retro finding-1 regression seam: a test can prove a
	// call site used the breakout D12 pair (86400/86400) vs. the main-room
	// pair (300/20) via timeoutsFor, without touching the "CreateRoom:
	// {room}" call-string format every existing sawCall assertion in this
	// package already relies on.
	createTimeouts map[string][2]uint32
}

func newFakeRooms() *fakeRooms {
	return &fakeRooms{errs: map[string]error{}, participants: map[string][]string{}, createTimeouts: map[string][2]uint32{}}
}

func (f *fakeRooms) record(call string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
	return f.errs[call]
}

func (f *fakeRooms) CreateRoom(_ context.Context, room string) error {
	f.mu.Lock()
	f.createTimeouts[room] = [2]uint32{300, 20}
	f.mu.Unlock()
	return f.record(fmt.Sprintf("CreateRoom:%s", room))
}

// CreateRoomWithTimeouts records identically to CreateRoom (plan delta 6):
// the timeouts are a real-SFU-only concern (lkRooms), so no test asserting
// "CreateRoom:{room}" needs to change when a call site switches from
// CreateRoom to CreateRoomWithTimeouts (the breakout open/join-mint paths).
// The actual (empty, departure) pair used is still recorded separately —
// see createTimeouts/timeoutsFor.
func (f *fakeRooms) CreateRoomWithTimeouts(_ context.Context, room string, empty, departure uint32) error {
	f.mu.Lock()
	f.createTimeouts[room] = [2]uint32{empty, departure}
	f.mu.Unlock()
	return f.record(fmt.Sprintf("CreateRoom:%s", room))
}

// timeoutsFor returns the (emptyTimeout, departureTimeout) pair the most
// recent CreateRoom/CreateRoomWithTimeouts call recorded for room, and
// whether any such call was recorded at all.
func (f *fakeRooms) timeoutsFor(room string) ([2]uint32, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.createTimeouts[room]
	return t, ok
}

func (f *fakeRooms) RemoveParticipant(_ context.Context, room, identity string) error {
	return f.record(fmt.Sprintf("RemoveParticipant:%s/%s", room, identity))
}

func (f *fakeRooms) DeleteRoom(_ context.Context, room string) error {
	return f.record(fmt.Sprintf("DeleteRoom:%s", room))
}

func (f *fakeRooms) ListParticipants(_ context.Context, room string) ([]string, error) {
	if err := f.record(fmt.Sprintf("ListParticipants:%s", room)); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.participants[room], nil
}

// setParticipants configures what ListParticipants reports as currently
// present in a room — the Task 5 breakout assignment↔presence worker arm's
// test seam (the setRooms genre, one level down: presence per room rather
// than existence per room).
func (f *fakeRooms) setParticipants(room string, identities []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.participants[room] = identities
}

func (f *fakeRooms) ListRooms(_ context.Context) ([]string, error) {
	if err := f.record("ListRooms"); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rooms, nil
}

// setRooms configures what ListRooms reports as currently live on the SFU —
// the Task 12 worker test seam.
func (f *fakeRooms) setRooms(rooms []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rooms = rooms
}

// sawCall reports whether the exact call string was recorded — the
// eviction-invariant assertion shape (`TestEveryRevokePathEvicts`, Task 10)
// uses this rather than comparing the whole slice, so a test isn't coupled
// to incidental ordering of unrelated calls (e.g. a CreateRoom pre-join
// alongside a later DeleteRoom).
func (f *fakeRooms) sawCall(call string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if c == call {
			return true
		}
	}
	return false
}

var _ RoomController = (*fakeRooms)(nil)
