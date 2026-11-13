package identitysource

import (
	"context"
	"errors"
	"sync"
	"testing"
)

type blockingWorker struct {
	started chan<- int64
	stopped chan<- int64
	id      int64
}

func TestSupervisorBuildFailureStopsOnlyInvalidGenerationAndStartsPeers(t *testing.T) {
	t.Parallel()
	started := make(chan int64, 4)
	stopped := make(chan int64, 4)
	supervisor := NewSupervisor()
	t.Cleanup(supervisor.Stop)
	ctx := context.Background()

	if err := supervisor.Reconcile(ctx, []Spec{{SourceID: 1, Generation: 1}},
		func(spec Spec) (Runnable, error) {
			return blockingWorker{started: started, stopped: stopped, id: spec.SourceID}, nil
		}); err != nil {
		t.Fatal(err)
	}
	if got := <-started; got != 1 {
		t.Fatalf("started %d", got)
	}

	err := supervisor.Reconcile(ctx, []Spec{
		{SourceID: 1, Generation: 2},
		{SourceID: 2, Generation: 1},
	}, func(spec Spec) (Runnable, error) {
		if spec.SourceID == 1 {
			return nil, errors.New("invalid replacement")
		}
		return blockingWorker{started: started, stopped: stopped, id: spec.SourceID}, nil
	})
	if err == nil {
		t.Fatal("replacement build failure was hidden")
	}
	if got := <-stopped; got != 1 {
		t.Fatalf("stopped %d", got)
	}
	if got := <-started; got != 2 {
		t.Fatalf("peer started %d", got)
	}
	if supervisor.Count() != 1 {
		t.Fatalf("running workers = %d, want only the valid peer", supervisor.Count())
	}
}

func (w blockingWorker) Run(ctx context.Context) {
	w.started <- w.id
	<-ctx.Done()
	w.stopped <- w.id
}

func TestSupervisorReconcileCancelJoinReplace(t *testing.T) {
	t.Parallel()
	started := make(chan int64, 4)
	stopped := make(chan int64, 4)
	supervisor := NewSupervisor()
	t.Cleanup(supervisor.Stop)

	var mu sync.Mutex
	built := map[int64]int{}
	factory := func(spec Spec) (Runnable, error) {
		mu.Lock()
		built[spec.SourceID]++
		mu.Unlock()
		return blockingWorker{started: started, stopped: stopped, id: spec.SourceID}, nil
	}

	ctx := context.Background()
	if err := supervisor.Reconcile(ctx, []Spec{{SourceID: 1, Generation: 1}}, factory); err != nil {
		t.Fatal(err)
	}
	if got := <-started; got != 1 {
		t.Fatalf("started %d", got)
	}
	if err := supervisor.Reconcile(ctx, []Spec{{SourceID: 1, Generation: 1}}, factory); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if built[1] != 1 {
		t.Fatalf("unchanged generation rebuilt %d times", built[1])
	}
	mu.Unlock()

	if err := supervisor.Reconcile(ctx, []Spec{{SourceID: 1, Generation: 2}}, factory); err != nil {
		t.Fatal(err)
	}
	if got := <-stopped; got != 1 {
		t.Fatalf("stopped %d", got)
	}
	if got := <-started; got != 1 {
		t.Fatalf("restarted %d", got)
	}
	if err := supervisor.Reconcile(ctx, nil, factory); err != nil {
		t.Fatal(err)
	}
	if got := <-stopped; got != 1 {
		t.Fatalf("removed %d", got)
	}
	if supervisor.Count() != 0 {
		t.Fatal("removed worker remains registered")
	}
}

type nilRunnableHolder struct{ pointer *struct{} }

func (nilRunnableHolder) Run(context.Context) {}

func TestSupervisorNilRunnableRecordedAsBuildErrorNotStarted(t *testing.T) {
	t.Parallel()
	supervisor := NewSupervisor()
	t.Cleanup(supervisor.Stop)
	ctx := context.Background()

	// A typed-nil Runnable (Go's typed-nil interface trap) must be recorded as
	// a build error and never started: starting it would panic the process.
	var typedNil *nilRunnableHolder
	err := supervisor.Reconcile(ctx, []Spec{{SourceID: 1, Generation: 1}},
		func(Spec) (Runnable, error) { return typedNil, nil })
	if err == nil {
		t.Fatal("expected build error for factory returning typed-nil runnable")
	}
	if got := supervisor.Count(); got != 0 {
		t.Fatalf("supervisor started %d workers from a nil runnable, want 0", got)
	}

	// An untyped nil return is equally a build error.
	err = supervisor.Reconcile(ctx, []Spec{{SourceID: 2, Generation: 1}},
		func(Spec) (Runnable, error) { return nil, nil })
	if err == nil {
		t.Fatal("expected build error for factory returning untyped nil runnable")
	}
	if got := supervisor.Count(); got != 0 {
		t.Fatalf("supervisor started %d workers from an untyped nil, want 0", got)
	}

	// A non-nil worker from the same factory surface still starts.
	started := make(chan int64, 1)
	stopped := make(chan int64, 1)
	if err := supervisor.Reconcile(ctx, []Spec{{SourceID: 3, Generation: 1}},
		func(spec Spec) (Runnable, error) {
			return blockingWorker{started: started, stopped: stopped, id: spec.SourceID}, nil
		}); err != nil {
		t.Fatal(err)
	}
	if got := <-started; got != 3 {
		t.Fatalf("started %d, want 3", got)
	}
}
