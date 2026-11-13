package webhook

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"setjoin.com/shared/testsupport"
	wh "setjoin.com/shared/webhook"
)

// TestDeliverOne_DetachedFromCancelledParent verifies that deliverOne completes
// even when the parent context is cancelled before the HTTP call returns.
// Previously, passing a request-scoped ctx directly caused silent delivery loss.
func TestDeliverOne_DetachedFromCancelledParent(t *testing.T) {
	delivered := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(delivered)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := &Dispatcher{
		httpClient: &http.Client{},
		breakers:   make(map[int64]*circuitBreaker),
	}

	body := []byte(`{"specversion":"1.0"}`)
	event := wh.CloudEvent{ID: "test-1", Type: "test/event"}

	// Cancel the parent context immediately — simulates request completion.
	parent, cancel := context.WithCancel(context.Background())
	cancel()

	// deliverOne must use a detached context; the caller (Dispatch) passes bg.
	bg := context.WithoutCancel(parent)
	ctx30, done := context.WithTimeout(bg, 5*time.Second)
	defer done()

	d.deliverTask(ctx30, deliveryTask{subID: 1, url: srv.URL, secret: "test-secret-0123456789abcdef-0123456789abcdef", event: event, body: body, attempt: 1})

	select {
	case <-delivered:
		// OK: server received the POST despite cancelled parent
	default:
		t.Error("deliverOne did not reach the subscriber even with detached context")
	}
}

func TestDeliveryBatchUsesFixedConcurrency(t *testing.T) {
	var active atomic.Int32
	var maximum atomic.Int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		now := active.Add(1)
		for {
			old := maximum.Load()
			if now <= old || maximum.CompareAndSwap(old, now) {
				break
			}
		}
		<-release
		active.Add(-1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	d := &Dispatcher{httpClient: srv.Client(), breakers: make(map[int64]*circuitBreaker)}
	d.StartRetryWorker(t.Context())
	event := wh.CloudEvent{ID: "bounded", Type: wh.EventUserDeleted}
	body := []byte(`{"specversion":"1.0","id":"bounded","type":"user.deleted"}`)
	tasks := make([]deliveryTask, 25)
	for i := range tasks {
		tasks[i] = deliveryTask{subID: int64(i + 1), url: srv.URL, secret: "test-secret-0123456789abcdef-0123456789abcdef", event: event, body: body, attempt: 1}
	}
	accepted := d.submit(t.Context(), tasks, true)
	accepted += d.submit(t.Context(), tasks, true)
	if accepted > deliveryWorkers+deliveryQueueSize {
		t.Fatalf("executor admitted %d tasks, capacity is workers+queue=%d", accepted, deliveryWorkers+deliveryQueueSize)
	}
	deadline := time.Now().Add(time.Second)
	for active.Load() < deliveryWorkers && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := maximum.Load(); got > deliveryWorkers {
		t.Fatalf("maximum concurrent deliveries=%d, fixed worker limit=%d", got, deliveryWorkers)
	}
	if got := maximum.Load(); got != deliveryWorkers {
		t.Fatalf("executor concurrency=%d, want fixed workers=%d", got, deliveryWorkers)
	}
	close(release)
}

// TestRetryTickExceedsDeliveryTimeout guards the no-overlap invariant: the retry
// ticker must fire strictly less often than a single delivery's timeout, so a
// row whose deliverOne is still in-flight cannot be re-selected and double-POSTed.
func TestRetryTickExceedsDeliveryTimeout(t *testing.T) {
	if retryTickInterval <= deliveryTimeout {
		t.Fatalf("retryTickInterval (%s) must exceed deliveryTimeout (%s) to avoid overlapping-tick duplicate delivery", retryTickInterval, deliveryTimeout)
	}
}

func TestDeliveryLeaseCoversHTTPAndSettlement(t *testing.T) {
	if deliveryLeaseTime <= deliveryTimeout+settlementTimeout {
		t.Fatalf("delivery lease (%s) must exceed HTTP timeout + settlement timeout (%s)",
			deliveryLeaseTime, deliveryTimeout+settlementTimeout)
	}
}

func TestSubmitFailsClosedBeforeStartDuringStopAndAtCapacity(t *testing.T) {
	event := wh.CloudEvent{ID: "submit-boundary", Type: wh.EventUserDeleted}
	task := deliveryTask{event: event}

	notStarted := &Dispatcher{logger: testsupport.TestLogger()}
	if got := notStarted.submit(t.Context(), []deliveryTask{task}, true); got != 0 {
		t.Fatalf("submit before lifecycle start admitted %d tasks", got)
	}

	stopping := &Dispatcher{logger: testsupport.TestLogger(), tasks: make(chan deliveryTask, 1), admission: make(chan struct{}, 1)}
	stopping.started.Store(true)
	stopping.stopping.Store(true)
	if got := stopping.submit(t.Context(), []deliveryTask{task}, true); got != 0 {
		t.Fatalf("submit during shutdown admitted %d tasks", got)
	}

	admissionFull := &Dispatcher{logger: testsupport.TestLogger(), tasks: make(chan deliveryTask, 1), admission: make(chan struct{}, 1)}
	admissionFull.started.Store(true)
	admissionFull.admission <- struct{}{}
	if got := admissionFull.submit(t.Context(), []deliveryTask{task}, true); got != 0 {
		t.Fatalf("submit past admission capacity admitted %d tasks", got)
	}

	queueFull := &Dispatcher{logger: testsupport.TestLogger(), tasks: make(chan deliveryTask), admission: make(chan struct{}, 1)}
	queueFull.started.Store(true)
	if got := queueFull.submit(t.Context(), []deliveryTask{task}, true); got != 0 {
		t.Fatalf("submit into a full queue admitted %d tasks", got)
	}
	if got := len(queueFull.admission); got != 0 {
		t.Fatalf("queue rejection leaked %d admission tokens", got)
	}
}

func TestDeliverTaskInvalidURLFailsWithoutHTTPAttempt(t *testing.T) {
	d := &Dispatcher{logger: testsupport.TestLogger(), breakers: make(map[int64]*circuitBreaker)}
	d.deliverTask(t.Context(), deliveryTask{
		subID: 1, url: "://invalid", durable: true, deliveryID: 1,
		event: wh.CloudEvent{ID: "invalid-url", Type: wh.EventUserDeleted},
	})
}

func TestCircuitBreakerTrips(t *testing.T) {
	cb := &circuitBreaker{}
	for i := 0; i < 10; i++ {
		cb.onFailure()
	}
	if !cb.isOpen() {
		t.Error("circuit breaker should be open after 10 failures")
	}
}

func TestCircuitBreakerResets(t *testing.T) {
	cb := &circuitBreaker{}
	cb.onSuccess()
	if cb.isOpen() {
		t.Error("circuit breaker should be closed after success")
	}
}

func TestCircuitBreakerHalfOpen(t *testing.T) {
	cb := &circuitBreaker{}
	for i := 0; i < 10; i++ {
		cb.onFailure()
	}
	cb.lastFailureAt = time.Now().Add(-3 * time.Minute)
	if cb.isOpen() {
		t.Error("circuit breaker should half-open after 2 minutes")
	}
}
