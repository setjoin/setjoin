package meet

import (
	"context"
	"fmt"
	"sync"
)

// fakeEgress is the EgressController test double, the fakeRooms genre
// (fake_rooms_test.go) extended for the recording seam: calls/sawCall
// mirror it exactly so a test can interleave the two fakes' recorders when
// asserting cross-controller ordering (TestEndMeetingStopsEgressBeforeDeleteRoom).
// startErrs is keyed by ROOM name (not the full call string fakeRooms uses)
// because StartRoomComposite's staging key embeds a recording id a test
// cannot know before the reducer call runs mid-route — room name is the one
// piece of the call a test DOES know ahead of time (roomNameFor). stopErrs
// mirrors fakeRooms' shape (keyed by the exact "StopEgress:<id>" call,
// since a test always knows the egress id before calling StopEgress).
// startHook lets a test probe DB state from INSIDE the StartRoomComposite
// call — the banner-fact-precedes-frames proof at the route level: the
// reducer row must already exist in 'requested' before Go ever calls out to
// Egress.
type fakeEgress struct {
	mu        sync.Mutex
	calls     []string
	startErrs map[string]error // room -> error
	stopErrs  map[string]error // "StopEgress:<id>" -> error
	egresses  []EgressStatus
	startHook func()
	// startSeq is a bug fix (found B2 Task 11): a deterministic "EG_"+room
	// id collides on meeting_recordings.egress_id's UNIQUE constraint the
	// moment a test starts a SECOND real recording on the SAME room (stop,
	// then start again — a wholly legitimate sequence; real LiveKit egress
	// mints a fresh session id every call and never collides on it). The
	// counter suffix keeps every call's return value unique; no existing
	// caller is affected — every consumer of a REAL StartRoomComposite call
	// reads the bound egress_id back from the DB, never recomputes
	// "EG_"+room itself (only seedRecording fixtures, which never call this
	// method, do that).
	startSeq int
}

func newFakeEgress() *fakeEgress {
	return &fakeEgress{startErrs: map[string]error{}, stopErrs: map[string]error{}}
}

func (f *fakeEgress) record(call string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
}

func (f *fakeEgress) StartRoomComposite(_ context.Context, room string, req RecordingRequest) (string, error) {
	if f.startHook != nil {
		f.startHook()
	}
	f.record(fmt.Sprintf("StartRoomComposite:%s:%s", room, req.StagingKey))
	f.mu.Lock()
	err := f.startErrs[room]
	f.startSeq++
	seq := f.startSeq
	f.mu.Unlock()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("EG_%s_%d", room, seq), nil
}

func (f *fakeEgress) StopEgress(_ context.Context, egressID string) error {
	call := fmt.Sprintf("StopEgress:%s", egressID)
	f.record(call)
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stopErrs[call]
}

func (f *fakeEgress) ListEgress(_ context.Context) ([]EgressStatus, error) {
	f.record("ListEgress")
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.egresses, nil
}

// setEgresses configures what ListEgress reports — the Task 7 reconcile
// worker's seam for simulating the SFU/bus's own egress view.
func (f *fakeEgress) setEgresses(es []EgressStatus) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.egresses = es
}

// sawCall reports whether the exact call string was recorded — the
// fakeRooms.sawCall precedent.
func (f *fakeEgress) sawCall(call string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if c == call {
			return true
		}
	}
	return false
}

var _ EgressController = (*fakeEgress)(nil)
