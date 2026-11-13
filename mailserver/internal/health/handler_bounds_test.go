package health

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"setjoin.com/shared/httputil"
)

// countingHandler returns a Handler whose evaluation is a counted seam —
// no live DB pool is touched, exactly like probeRows' pool-free test
// posture — with the throttle disabled unless the caller supplies one.
func countingHandler(t *testing.T) (*Handler, *atomic.Int64) {
	t.Helper()
	h := NewHandler(nil, slog.Default(), nil)
	var evals atomic.Int64
	h.evaluate = func(ctx context.Context, w http.ResponseWriter) {
		n := evals.Add(1)
		httputil.WriteJSON(w, http.StatusOK, map[string]string{
			"status": "ok",
			"eval":   strconv.FormatInt(n, 10),
		})
	}
	return h, &evals
}

func getHealth(h *Handler, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.PublicCheck(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

// TestHealthVerdictCachedWithinTTL pins the cache half of the package row's
// proposedTests: repeated /health requests are served from cache (the
// evaluation count stays at 1) and a fresh full evaluation still occurs
// within the cache TTL — the first request after expiry re-evaluates.
func TestHealthVerdictCachedWithinTTL(t *testing.T) {
	h, evals := countingHandler(t)
	h.evalTTL = 50 * time.Millisecond
	h.throttle = nil // cache contract only; the throttle has its own test

	first := getHealth(h, "/health")
	if first.Code != http.StatusOK {
		t.Fatalf("first /health status=%d body=%q", first.Code, first.Body.String())
	}
	wantBody := first.Body.String()
	if got := evals.Load(); got != 1 {
		t.Fatalf("evaluations after first request = %d, want 1", got)
	}

	// Repeated polls inside the TTL: served from cache, zero re-evaluation.
	for i := 0; i < 9; i++ {
		rec := getHealth(h, "/health")
		if rec.Code != http.StatusOK {
			t.Fatalf("cached /health status=%d body=%q", rec.Code, rec.Body.String())
		}
		if rec.Body.String() != wantBody {
			t.Fatalf("cached body %q differs from fresh body %q", rec.Body.String(), wantBody)
		}
	}
	if got := evals.Load(); got != 1 {
		t.Fatalf("evaluations after 10 in-TTL requests = %d, want 1 (cache must absorb repeats)", got)
	}

	// After the TTL a fresh full evaluation occurs.
	time.Sleep(80 * time.Millisecond)
	after := getHealth(h, "/health")
	if after.Code != http.StatusOK {
		t.Fatalf("post-TTL /health status=%d body=%q", after.Code, after.Body.String())
	}
	if got := evals.Load(); got != 2 {
		t.Fatalf("evaluations after TTL expiry = %d, want 2 (a fresh full evaluation must occur within the cache TTL)", got)
	}
}

// TestHealthVerdictConcurrentRequestsBoundedEvaluations pins the stated
// bound half of the proposedTests: a thundering herd on a cold cache cannot
// drive pool contention or peripheral dial churn beyond the stated bound —
// single-flight collapses the herd onto at most 2 evaluations (exactly 1 in
// practice; 2 allows for one straggler re-evaluating after the TTL on a
// heavily preempted CI box), with every request served the same verdict.
func TestHealthVerdictConcurrentRequestsBoundedEvaluations(t *testing.T) {
	h := NewHandler(nil, slog.Default(), nil)
	var evals atomic.Int64
	h.evaluate = func(ctx context.Context, w http.ResponseWriter) {
		evals.Add(1)
		time.Sleep(25 * time.Millisecond) // widen the herd's cache-miss window
		httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
	h.evalTTL = 2 * time.Second
	h.throttle = nil

	const herd = 40
	recs := make([]*httptest.ResponseRecorder, herd)
	for i := range recs {
		recs[i] = httptest.NewRecorder()
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range recs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			h.Check(recs[i], httptest.NewRequest(http.MethodGet, "/health", nil))
		}(i)
	}
	close(start)
	wg.Wait()

	if got := evals.Load(); got < 1 || got > 2 {
		t.Fatalf("evaluations for %d concurrent requests = %d, want within the stated bound [1,2]", herd, got)
	}
	for i, rec := range recs {
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d status=%d body=%q, want 200", i, rec.Code, rec.Body.String())
		}
		if rec.Body.String() != recs[0].Body.String() {
			t.Fatalf("request %d body %q differs from request 0 body %q", i, rec.Body.String(), recs[0].Body.String())
		}
	}
}

// TestHealthThrottleServesCachedVerdictWhenExhausted pins the throttle
// contract: beyond the global bucket, requests are served the last cached
// verdict (stale serve — a flood neither errors the endpoint nor adds
// evaluation work), and a throttled request with no verdict yet at all
// fails closed with 503 rather than admitting an unbounded burst.
func TestHealthThrottleServesCachedVerdictWhenExhausted(t *testing.T) {
	h, evals := countingHandler(t)
	h.evalTTL = time.Hour // the cache never expires in this test
	h.throttle = newTokenBucket(0.001, 2)

	var firstBody string
	for i := 0; i < 10; i++ {
		rec := getHealth(h, "/health")
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d status=%d body=%q, want 200 (throttled requests must be served the cached verdict)", i, rec.Code, rec.Body.String())
		}
		if i == 0 {
			firstBody = rec.Body.String()
		} else if rec.Body.String() != firstBody {
			t.Fatalf("request %d body %q differs from first body %q", i, rec.Body.String(), firstBody)
		}
	}
	if got := evals.Load(); got != 1 {
		t.Fatalf("evaluations after burst-exhausted flood = %d, want 1 (throttled requests add zero evaluation work)", got)
	}

	// Cold corner: exhausted bucket and no verdict yet → fail closed 503.
	cold := NewHandler(nil, slog.Default(), nil)
	var coldEvals atomic.Int64
	cold.evaluate = func(ctx context.Context, w http.ResponseWriter) {
		coldEvals.Add(1)
		httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
	cold.evalTTL = time.Hour
	cold.throttle = newTokenBucket(0.001, 0)
	rec := getHealth(cold, "/health")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("cold throttled status=%d body=%q, want 503 fail-closed", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != "{\"status\":\"error\"}\n" {
		t.Fatalf("cold throttled public body=%q, want the redacted aggregate verdict only", got)
	}
	if got := coldEvals.Load(); got != 0 {
		t.Fatalf("cold throttled evaluations = %d, want 0 (a 503 must not evaluate)", got)
	}
}

// TestHealthFailedEvaluationIsCached pins the outage bound: a failed
// evaluation (e.g. unreachable DB) is cached for the TTL like any verdict,
// so a persistent outage drives at most one failed pool query per TTL
// instead of one per request.
func TestHealthFailedEvaluationIsCached(t *testing.T) {
	h := NewHandler(nil, slog.Default(), nil)
	var evals atomic.Int64
	h.evaluate = func(ctx context.Context, w http.ResponseWriter) {
		evals.Add(1)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
	h.evalTTL = time.Hour
	h.throttle = nil

	for i := 0; i < 3; i++ {
		rec := getHealth(h, "/health")
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("request %d status=%d body=%q, want cached 500 failure verdict", i, rec.Code, rec.Body.String())
		}
	}
	if got := evals.Load(); got != 1 {
		t.Fatalf("evaluations during outage = %d, want 1 (failure verdicts must be cached for the TTL)", got)
	}
}
