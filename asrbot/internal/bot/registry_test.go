package bot

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type registryRunner struct {
	started atomic.Int64
	active  atomic.Int64
	block   chan struct{}
}

type drainingRunner struct {
	started  chan struct{}
	canceled chan struct{}
	drain    chan struct{}
}

func (f *drainingRunner) Run(ctx context.Context, _, _ string) {
	close(f.started)
	<-ctx.Done()
	close(f.canceled)
	<-f.drain
}

func (f *registryRunner) Run(ctx context.Context, _, _ string) {
	f.started.Add(1)
	f.active.Add(1)
	defer f.active.Add(-1)
	if f.block == nil {
		return
	}
	select {
	case <-ctx.Done():
	case <-f.block:
	}
}

func TestStopBetweenAdmissionAndRunnerStartDoesNotStrandSession(t *testing.T) {
	runner := &registryRunner{}
	rooms := NewRoomRegistry(1, runner)

	session, admitted, ok := rooms.admit("room-a")
	if !ok || !admitted || session == nil {
		t.Fatal("initial admission failed")
	}
	rooms.Stop("room-a")

	// Deterministically resume the already-admitted start after Stop. execute
	// must observe the cancelled identity and never hand it to LiveKit.
	rooms.execute(session, "tok")
	if got := runner.started.Load(); got != 0 {
		t.Fatalf("runner starts = %d, want 0 after stop won before runner start", got)
	}
	if got := rooms.Rooms(); len(got) != 0 {
		t.Fatalf("status after stop = %v, want empty", got)
	}
	if !rooms.Start("room-b", "tok") {
		t.Fatal("cancelled admission did not free capacity")
	}
}

func TestRoomRegistryConcurrentStartHonorsCapacityAndIdentity(t *testing.T) {
	const capacity = 8
	runner := &registryRunner{block: make(chan struct{})}
	rooms := NewRoomRegistry(capacity, runner)
	t.Cleanup(func() { close(runner.block) })

	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			room := fmt.Sprintf("room-%03d", i%50)
			rooms.Start(room, "tok")
		}(i)
	}
	wg.Wait()

	got := rooms.Rooms()
	if len(got) != capacity {
		t.Fatalf("admitted rooms = %d, want capacity %d: %v", len(got), capacity, got)
	}
	if !sort.StringsAreSorted(got) {
		t.Fatalf("Rooms not sorted: %v", got)
	}
	waitForAtomic(t, &runner.started, capacity)
	if started := runner.started.Load(); started != capacity {
		t.Fatalf("runner starts = %d, want exactly one per admitted identity (%d)", started, capacity)
	}
	waitForAtomic(t, &runner.active, capacity)
	if active := runner.active.Load(); active != capacity {
		t.Fatalf("active runners = %d, want capacity %d", active, capacity)
	}
}

func TestRoomRegistryConnectFailureAndNaturalDisconnectReleaseCapacity(t *testing.T) {
	t.Run("connect failure", func(t *testing.T) {
		runner := &registryRunner{} // returning before live models connect failure
		rooms := NewRoomRegistry(1, runner)
		if !rooms.Start("room-a", "tok") {
			t.Fatal("start rejected")
		}
		waitForAtomic(t, &runner.started, 1)
		waitForRooms(t, rooms, 0)
		if !rooms.Start("room-b", "tok") {
			t.Fatal("connect failure did not free capacity")
		}
	})

	t.Run("natural disconnect", func(t *testing.T) {
		disconnect := make(chan struct{})
		runner := &registryRunner{block: disconnect}
		rooms := NewRoomRegistry(1, runner)
		if !rooms.Start("room-a", "tok") {
			t.Fatal("start rejected")
		}
		waitForAtomic(t, &runner.active, 1)
		if got := rooms.Rooms(); len(got) != 1 || got[0] != "room-a" {
			t.Fatalf("live status = %v, want [room-a]", got)
		}
		close(disconnect)
		waitForRooms(t, rooms, 0)
		if !rooms.Start("room-b", "tok") {
			t.Fatal("natural disconnect did not free capacity")
		}
	})
}

func TestRoomRegistryStopCancelsActiveRunner(t *testing.T) {
	runner := &registryRunner{block: make(chan struct{})}
	rooms := NewRoomRegistry(1, runner)
	if !rooms.Start("room-a", "tok") {
		t.Fatal("start rejected")
	}
	waitForAtomic(t, &runner.active, 1)
	rooms.Stop("room-a")
	waitForAtomicEqual(t, &runner.active, 0)
	waitForRooms(t, rooms, 0)
}

func TestRoomRegistryStoppingSessionRetainsCapacityUntilRunnerDrains(t *testing.T) {
	runner := &drainingRunner{
		started:  make(chan struct{}),
		canceled: make(chan struct{}),
		drain:    make(chan struct{}),
	}
	rooms := NewRoomRegistry(1, runner)
	if !rooms.Start("room-a", "tok") {
		t.Fatal("start rejected")
	}
	<-runner.started
	rooms.Stop("room-a")
	<-runner.canceled
	if rooms.Start("room-b", "tok") {
		t.Fatal("replacement exceeded capacity while old runner was still draining")
	}
	if rooms.Start("room-a", "tok") {
		t.Fatal("start racing a stopping identity reported false success")
	}
	if got := rooms.Rooms(); len(got) != 1 || got[0] != "room-a" {
		t.Fatalf("stopping identity status = %v, want [room-a] until runner drains", got)
	}
	close(runner.drain)
	waitForRooms(t, rooms, 0)
}

func TestRoomRegistryStaleReleaseCannotDeleteReplacement(t *testing.T) {
	rooms := NewRoomRegistry(1, &registryRunner{})
	old, admitted, ok := rooms.admit("room-a")
	if !ok || !admitted {
		t.Fatal("old admission failed")
	}
	rooms.Stop("room-a")
	if !rooms.release(old) {
		t.Fatal("matching old release failed")
	}
	newer, admitted, ok := rooms.admit("room-a")
	if !ok || !admitted || newer == old {
		t.Fatal("replacement admission failed")
	}
	if rooms.release(old) {
		t.Fatal("stale release reported success")
	}
	if got := rooms.Rooms(); len(got) != 1 || got[0] != "room-a" {
		t.Fatalf("stale release changed replacement status: %v", got)
	}
	if !rooms.release(newer) {
		t.Fatal("matching replacement release failed")
	}
}

func waitForAtomic(t *testing.T, value *atomic.Int64, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for value.Load() < int64(want) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d; got %d", want, value.Load())
		}
		time.Sleep(time.Millisecond)
	}
}

func waitForAtomicEqual(t *testing.T, value *atomic.Int64, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for value.Load() != int64(want) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d; got %d", want, value.Load())
		}
		time.Sleep(time.Millisecond)
	}
}

func waitForRooms(t *testing.T, rooms *RoomRegistry, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for len(rooms.Rooms()) != want {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d rooms; got %v", want, rooms.Rooms())
		}
		time.Sleep(time.Millisecond)
	}
}
