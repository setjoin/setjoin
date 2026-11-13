package identitysource

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
)

// Runnable is one configured source discovery loop.
type Runnable interface {
	Run(context.Context)
}

type Spec struct {
	SourceID   int64
	Generation int64
}

// Factory builds one source worker. A Factory must not return (nil, nil): a
// nil Runnable (including Go's typed-nil interface trap) is recorded as a
// build error and never started, mirroring an explicit build failure.
type Factory func(Spec) (Runnable, error)

type running struct {
	generation int64
	cancel     context.CancelFunc
	done       chan struct{}
}

// Supervisor replaces source workers without a process restart. Replacement
// always cancels and joins the old generation before starting the new one.
type Supervisor struct {
	mu      sync.Mutex
	workers map[int64]running
}

func NewSupervisor() *Supervisor {
	return &Supervisor{workers: make(map[int64]running)}
}

func (s *Supervisor) Reconcile(ctx context.Context, specs []Spec, factory Factory) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	wanted := make(map[int64]Spec, len(specs))
	for _, spec := range specs {
		if spec.SourceID <= 0 || spec.Generation <= 0 {
			return fmt.Errorf("invalid source worker spec: %+v", spec)
		}
		if _, duplicate := wanted[spec.SourceID]; duplicate {
			return fmt.Errorf("duplicate source worker spec %d", spec.SourceID)
		}
		wanted[spec.SourceID] = spec
	}

	ordered := append([]Spec(nil), specs...)
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].SourceID < ordered[j].SourceID
	})
	built := make(map[int64]Runnable, len(ordered))
	var buildErrors []error
	for _, spec := range ordered {
		if current, ok := s.workers[spec.SourceID]; ok &&
			current.generation == spec.Generation {
			continue
		}
		worker, err := factory(spec)
		if err != nil {
			buildErrors = append(buildErrors,
				fmt.Errorf("build source worker %d: %w", spec.SourceID, err))
			continue
		}
		if isNilRunnable(worker) {
			// A factory returning (nil, nil) must not reach goroutine start:
			// worker.Run would panic on the first method dereference and take
			// the process down. Record it like any other build failure.
			buildErrors = append(buildErrors,
				fmt.Errorf("build source worker %d: factory returned nil runnable", spec.SourceID))
			continue
		}
		built[spec.SourceID] = worker
	}

	for sourceID, current := range s.workers {
		spec, keep := wanted[sourceID]
		if keep && spec.Generation == current.generation {
			delete(wanted, sourceID)
			continue
		}
		current.cancel()
		<-current.done
		delete(s.workers, sourceID)
	}

	for _, spec := range ordered {
		sourceID := spec.SourceID
		if _, needsStart := wanted[sourceID]; !needsStart {
			continue
		}
		worker, ok := built[sourceID]
		if !ok {
			continue
		}
		workerCtx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		s.workers[sourceID] = running{
			generation: spec.Generation, cancel: cancel, done: done,
		}
		go func() {
			defer close(done)
			worker.Run(workerCtx)
		}()
	}
	return errors.Join(buildErrors...)
}

func (s *Supervisor) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, worker := range s.workers {
		worker.cancel()
		<-worker.done
		delete(s.workers, id)
	}
}

func (s *Supervisor) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.workers)
}
