package meet

import (
	"context"
	"fmt"
	"sync"
)

// fakeCaptions is the CaptionsController test double — the fakeEgress genre
// (fake_egress_test.go) applied to the third seam: calls/sawCall mirror it
// exactly. startErrs is keyed by ROOM (a test knows the room ahead of the
// route call, same as fakeEgress.startErrs); stopErrs mirrors fakeRooms'
// exact-call-string shape (keyed by "Stop:<room>", since a test always
// knows the room before calling Stop). startHook lets a test probe DB state
// from INSIDE the Start call — the fact-precedes-sidecar-call proof at the
// route level (the fakeEgress startHook genre): the reducer row must
// already read captionsOn=true before Go ever calls out to the ASR
// sidecar. sessions is Status()'s return value — the Task 14 reconcile
// worker's seam for simulating "the ASR sidecar still has this room live"
// (the fakeRooms.rooms / fakeEgress.egresses genre).
type fakeCaptions struct {
	mu        sync.Mutex
	calls     []string
	startErrs map[string]error // room -> error (e.g. errCaptionsBusy)
	stopErrs  map[string]error // "Stop:<room>" -> error
	sessions  []string
	startHook func()
}

func newFakeCaptions() *fakeCaptions {
	return &fakeCaptions{startErrs: map[string]error{}, stopErrs: map[string]error{}}
}

func (f *fakeCaptions) record(call string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
}

func (f *fakeCaptions) Start(_ context.Context, room, _ string) error {
	if f.startHook != nil {
		f.startHook()
	}
	f.record(fmt.Sprintf("Start:%s", room))
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.startErrs[room]
}

func (f *fakeCaptions) Stop(_ context.Context, room string) error {
	call := fmt.Sprintf("Stop:%s", room)
	f.record(call)
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stopErrs[call]
}

func (f *fakeCaptions) Status(_ context.Context) ([]string, error) {
	f.record("Status")
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sessions, nil
}

// setSessions configures what Status reports as currently live on the ASR
// sidecar — the Task 14 reconcile worker's test seam (the
// fakeRooms.setRooms / fakeEgress.setEgresses genre).
func (f *fakeCaptions) setSessions(rooms []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sessions = rooms
}

// sawCall reports whether the exact call string was recorded — the
// fakeRooms.sawCall precedent.
func (f *fakeCaptions) sawCall(call string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if c == call {
			return true
		}
	}
	return false
}

var _ CaptionsController = (*fakeCaptions)(nil)
