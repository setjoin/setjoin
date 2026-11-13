package identitysource

import (
	"context"
	"sync/atomic"
	"testing"
)

type controllerTestWorker struct {
	runs atomic.Int32
}

func (w *controllerTestWorker) Run(ctx context.Context) {
	w.runs.Add(1)
	<-ctx.Done()
}

func TestControllerIgnoresTypedNilRunnable(t *testing.T) {
	var worker *controllerTestWorker
	var controller Controller
	controller.Start(context.Background(), worker)
	controller.Replace(worker)
	controller.Stop()
}

func TestControllerStartsReplacesAndStopsWorker(t *testing.T) {
	first := &controllerTestWorker{}
	second := &controllerTestWorker{}
	var controller Controller
	controller.Start(context.Background(), first)
	controller.Replace(second)
	controller.Stop()
	if first.runs.Load() != 1 {
		t.Fatalf("first worker runs=%d want 1", first.runs.Load())
	}
	if second.runs.Load() != 1 {
		t.Fatalf("second worker runs=%d want 1", second.runs.Load())
	}
}
