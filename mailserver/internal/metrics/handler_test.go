package metrics

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"setjoin.com/shared/testsupport"
)

// TestHistogram_SingleBucketPerObservation verifies that a single observation
// lands in exactly one bucket, so the cumulative output loop produces the
// correct Prometheus histogram (each bucket ≥ the previous by exactly
// the number of observations that fall in it, not double-counted).
//
// Before the fix: a 3 ms request incremented ALL buckets where 0.003 ≤ b,
// making the cumulative output 1,2,3,4,5,6,7 instead of 1,1,1,1,1,1,1.
func TestHistogram_SingleBucketPerObservation(t *testing.T) {
	h := NewHandler()

	// 3 ms — falls in bucket 0 (≤ 5 ms) only.
	h.RecordMethod("jmap", "Email/get", 3*time.Millisecond)

	h.histMu.Lock()
	mh := h.histogram["jmap/Email/get"]
	h.histMu.Unlock()
	if mh == nil {
		t.Fatal("histogram entry not created")
	}

	// With the fix: only bucket[0] (≤ 5 ms) gets +1; all others stay 0.
	var totalBucketIncs uint64
	for i := range mh.buckets {
		totalBucketIncs += mh.buckets[i].Load()
	}
	if totalBucketIncs != 1 {
		t.Errorf("expected 1 total bucket increment for one observation, got %d (double-count bug)", totalBucketIncs)
	}
	if mh.buckets[0].Load() != 1 {
		t.Errorf("expected bucket[0] (≤5ms) = 1, got %d", mh.buckets[0].Load())
	}
}

// TestHistogram_PrometheusOutput verifies the /metrics output is non-decreasing
// (Prometheus histogram contract: cumulative bucket counts must be monotone).
func TestHistogram_PrometheusOutput(t *testing.T) {
	h := NewHandler()
	h.RecordMethod("proto", "method", 3*time.Millisecond)   // bucket[0] ≤5ms
	h.RecordMethod("proto", "method", 60*time.Millisecond)  // bucket[4] ≤100ms
	h.RecordMethod("proto", "method", 500*time.Millisecond) // bucket[6] ≤1000ms

	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "gateway_method_duration_seconds_bucket") {
		t.Fatal("expected histogram bucket lines in /metrics output")
	}
	if !strings.Contains(body, `method="proto/method"`) {
		t.Error("expected proto/method label in output")
	}
	// The +Inf bucket must equal the total count (3).
	if !strings.Contains(body, `le="+Inf"} 3`) {
		t.Errorf("expected +Inf bucket = 3 in output:\n%s", body)
	}
}

func TestIdentityMetricsAreAggregateGauges(t *testing.T) {
	h := NewHandler()
	h.identityCriticalDivergences.Store(2)
	h.identityCanaryMembers.Store(7)
	h.identityInboxQuarantined.Store(3)
	h.identityCollectorSuccess.Store(1)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{
		"gateway_identity_shadow_critical 2",
		"gateway_identity_canary_members 7",
		"gateway_identity_inbox_quarantined 3",
		"gateway_identity_collector_success 1",
		"# TYPE setjoin_identity_sync_runs_total counter",
		"setjoin_identity_shadow_divergences 2",
		"setjoin_identity_auth_resolution_total 0",
		"setjoin_identity_effect_oldest_age_seconds 0",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing aggregate identity metric %q", want)
		}
	}
	for _, forbidden := range []string{"user_id=", "subject=", "source_key="} {
		if strings.Contains(body, forbidden) {
			t.Errorf("identity metrics exposed high-cardinality identifier %q", forbidden)
		}
	}
}

func TestRunIdentityCollectorPublishesDatabaseAggregates(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewHandler()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.RunIdentityCollector(ctx, pool, testsupport.TestLogger())
	}()

	deadline := time.Now().Add(2 * time.Second)
	for h.identityCollectorSuccess.Load() != 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("identity collector did not stop on context cancellation")
	}
	if h.identityCollectorSuccess.Load() != 1 {
		t.Fatal("identity collector did not publish a successful database sample")
	}
	if h.identityCriticalDivergences.Load() < 0 ||
		h.identitySourcesAttention.Load() < 0 ||
		h.identityInboxPending.Load() < 0 ||
		h.identityInboxQuarantined.Load() < 0 ||
		h.identityConflictsPending.Load() < 0 ||
		h.identityTransitionsPending.Load() < 0 ||
		h.identityEffectsPending.Load() < 0 ||
		h.identityCanaryMembers.Load() < 0 ||
		h.identitySyncRuns.Load() < 0 ||
		h.identityCursorAgeSeconds.Load() < 0 ||
		h.identityTransitionAge.Load() < 0 ||
		h.identityApprovalsPending.Load() < 0 ||
		h.identityApprovalExpiry.Load() < 0 ||
		h.identityEffectOldestAge.Load() < 0 {
		t.Fatal("identity aggregate gauges must never be negative")
	}
}

func TestRunIdentityCollectorNilPoolReturns(t *testing.T) {
	NewHandler().RunIdentityCollector(context.Background(), nil, nil)
}

func TestRunIdentityCollectorUsesDefaultLogger(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx, cancel := context.WithCancel(context.Background())
	h := NewHandler()
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.RunIdentityCollector(ctx, pool, nil)
	}()
	deadline := time.Now().Add(time.Second)
	for h.identityCollectorSuccess.Load() != 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if h.identityCollectorSuccess.Load() != 1 {
		t.Fatal("identity collector with default logger did not publish its initial sample")
	}
}

func TestRunIdentityCollectorPublishesFailureAndStops(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	pool.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		NewHandler().RunIdentityCollector(ctx, pool, testsupport.TestLogger())
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("failed identity collector did not stop")
	}
}
