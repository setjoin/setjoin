package threat

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"

	"setjoin.com/shared/toggle"
)

// testLogger returns a discard-sink slog logger for use in decision cache tests.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// countingGeoStore counts ResolveGeoTier calls — a full eval calls it once, a
// decision-cache hit does not. The policy needs geo so every full eval resolves.
type countingGeoStore struct {
	rows []PolicyRow
	mu   sync.Mutex
	geoN int
}

func (s *countingGeoStore) LoadAllPolicies(ctx context.Context) ([]PolicyRow, error) {
	return s.rows, nil
}
func (s *countingGeoStore) LoadPolicies(ctx context.Context, p PolicyEvalContext) ([]PolicyRow, error) {
	return s.rows, nil
}
func (s *countingGeoStore) ResolveGeoTier(ctx context.Context, c string) (string, error) {
	s.mu.Lock()
	s.geoN++
	s.mu.Unlock()
	return "low", nil
}
func (s *countingGeoStore) LoadBreakGlass(_ context.Context) ([]int64, error) { return nil, nil }
func (s *countingGeoStore) LoadNamedLocations(_ context.Context) ([]NamedLocation, error) {
	return nil, nil
}
func (s *countingGeoStore) LoadAuthStrengths(_ context.Context) ([]AuthStrength, error) {
	return nil, nil
}
func (s *countingGeoStore) calls() int { s.mu.Lock(); defer s.mu.Unlock(); return s.geoN }

func geoPolicy(action string, extra map[string]interface{}) []PolicyRow {
	cond := map[string]interface{}{"geo_risk_tier": "high"}
	for k, v := range extra {
		cond[k] = v
	}
	return []PolicyRow{{ID: 1, Name: "p", Enabled: true, ScopeType: "global",
		Conditions: cond, Actions: map[string]interface{}{"action": action}}}
}

func newCacheEngine(store PolicyStore) *PolicyEngine {
	tg := toggle.NewStatic(map[string]bool{toggle.FeatureConditionalAccess: true})
	return NewPolicyEngine(store, tg, nil, nil, testLogger(), false)
}

func TestDecisionCacheHitSkipsWork(t *testing.T) {
	store := &countingGeoStore{rows: geoPolicy("notify", nil)}
	pe := newCacheEngine(store)
	ctx := context.Background()
	pectx := PolicyEvalContext{UserID: 7, Country: "US", Protocol: "imap"}
	pe.Evaluate(ctx, pectx)
	pe.Evaluate(ctx, pectx) // identical -> cache hit, no second ResolveGeoTier
	if got := store.calls(); got != 1 {
		t.Fatalf("identical evals must resolve geo ONCE (cache hit), got %d", got)
	}
}

func TestDecisionCacheMissOnDifferentBucket(t *testing.T) {
	store := &countingGeoStore{rows: geoPolicy("notify", nil)}
	pe := newCacheEngine(store)
	ctx := context.Background()
	pe.Evaluate(ctx, PolicyEvalContext{UserID: 7, Country: "US", Protocol: "imap", CurrentACR: "aal1"})
	pe.Evaluate(ctx, PolicyEvalContext{UserID: 7, Country: "US", Protocol: "imap", CurrentACR: "aal2"})
	if got := store.calls(); got != 2 {
		t.Fatalf("different acr bucket must MISS, got %d calls", got)
	}
}

func TestDecisionCacheBypassesTimeOfDay(t *testing.T) {
	store := &countingGeoStore{rows: geoPolicy("notify",
		map[string]interface{}{"time_of_day": map[string]interface{}{"from": "09:00", "to": "17:00"}})}
	pe := newCacheEngine(store)
	ctx := context.Background()
	pectx := PolicyEvalContext{UserID: 7, Country: "US", Protocol: "imap"}
	pe.Evaluate(ctx, pectx)
	pe.Evaluate(ctx, pectx)
	if got := store.calls(); got != 2 {
		t.Fatalf("time_of_day policy must BYPASS the decision cache (re-eval), got %d calls", got)
	}
}

func TestDecisionCacheSkipsRevocationSensitive(t *testing.T) {
	store := &countingGeoStore{rows: geoPolicy("notify", nil)}
	pe := newCacheEngine(store)
	ctx := context.Background()
	pectx := PolicyEvalContext{UserID: 7, Country: "US", Protocol: "imap", RevocationSensitive: true}
	pe.Evaluate(ctx, pectx)
	pe.Evaluate(ctx, pectx)
	if got := store.calls(); got != 2 {
		t.Fatalf("revocation-sensitive eval must NOT be cached, got %d calls", got)
	}
}

func TestInvalidateCacheFlushesDecisions(t *testing.T) {
	store := &countingGeoStore{rows: geoPolicy("notify", nil)}
	pe := newCacheEngine(store)
	ctx := context.Background()
	pectx := PolicyEvalContext{UserID: 7, Country: "US", Protocol: "imap"}
	pe.Evaluate(ctx, pectx)
	pe.InvalidateCache() // must drop cached decisions too
	pe.Evaluate(ctx, pectx)
	if got := store.calls(); got != 2 {
		t.Fatalf("InvalidateCache must flush decisions (next eval reloads), got %d calls", got)
	}
}

// TestDecisionCacheMissOnDifferentGroups verifies that two evals identical in all
// fields except GroupIDs produce a cache MISS — i.e. different group membership
// yields a different cache key and the full eval (including ResolveGeoTier) runs
// both times.
func TestDecisionCacheMissOnDifferentGroups(t *testing.T) {
	store := &countingGeoStore{rows: geoPolicy("notify", nil)}
	pe := newCacheEngine(store)
	ctx := context.Background()
	base := PolicyEvalContext{UserID: 7, Country: "US", Protocol: "imap"}

	pectx1 := base
	pectx1.GroupIDs = []int64{1, 2}
	pectx2 := base
	pectx2.GroupIDs = []int64{1, 3} // different membership

	pe.Evaluate(ctx, pectx1)
	pe.Evaluate(ctx, pectx2)
	if got := store.calls(); got != 2 {
		t.Fatalf("different GroupIDs must cache MISS (full eval both times), got %d ResolveGeoTier calls", got)
	}
}

// TestDecisionCacheHitSameGroupsDifferentOrder verifies that the same membership
// set supplied in a different slice order produces a cache HIT — the sort in
// decisionCacheKey makes the key order-independent.
func TestDecisionCacheHitSameGroupsDifferentOrder(t *testing.T) {
	store := &countingGeoStore{rows: geoPolicy("notify", nil)}
	pe := newCacheEngine(store)
	ctx := context.Background()
	base := PolicyEvalContext{UserID: 7, Country: "US", Protocol: "imap"}

	pectx1 := base
	pectx1.GroupIDs = []int64{1, 2}
	pectx2 := base
	pectx2.GroupIDs = []int64{2, 1} // same members, reversed order

	pe.Evaluate(ctx, pectx1)
	pe.Evaluate(ctx, pectx2) // must hit the cache from the first eval
	if got := store.calls(); got != 1 {
		t.Fatalf("same GroupIDs in different order must cache HIT (geo resolved once), got %d ResolveGeoTier calls", got)
	}
}

// TestDecisionCacheMissOnDifferentCompletedFactors verifies that two evals identical
// in all fields except CompletedFactors produce a cache MISS. require_strength
// dispatch (CA-F) branches on completed factors — different factor sets must never
// share a decision cache entry.
func TestDecisionCacheMissOnDifferentCompletedFactors(t *testing.T) {
	store := &countingGeoStore{rows: geoPolicy("notify", nil)}
	pe := newCacheEngine(store)
	ctx := context.Background()
	base := PolicyEvalContext{UserID: 7, Country: "US", Protocol: "http"}

	pectx1 := base
	pectx1.CompletedFactors = []string{"password"}
	pectx2 := base
	pectx2.CompletedFactors = []string{"password", "webauthn"} // stronger session

	pe.Evaluate(ctx, pectx1)
	pe.Evaluate(ctx, pectx2)
	if got := store.calls(); got != 2 {
		t.Fatalf("different CompletedFactors must cache MISS (full eval both times), got %d ResolveGeoTier calls", got)
	}
}

// TestDecisionCacheHitSameCompletedFactorsDifferentOrder verifies that the same
// factor set in different order still hits the cache (sort makes key order-independent).
func TestDecisionCacheHitSameCompletedFactorsDifferentOrder(t *testing.T) {
	store := &countingGeoStore{rows: geoPolicy("notify", nil)}
	pe := newCacheEngine(store)
	ctx := context.Background()
	base := PolicyEvalContext{UserID: 7, Country: "US", Protocol: "http"}

	pectx1 := base
	pectx1.CompletedFactors = []string{"password", "webauthn"}
	pectx2 := base
	pectx2.CompletedFactors = []string{"webauthn", "password"} // same set, reversed

	pe.Evaluate(ctx, pectx1)
	pe.Evaluate(ctx, pectx2) // must hit the cache
	if got := store.calls(); got != 1 {
		t.Fatalf("same CompletedFactors in different order must cache HIT, got %d ResolveGeoTier calls", got)
	}
}

// TestDecisionCacheMissOnDifferentUserAgent verifies that two evals with different
// UserAgents (mapping to different platform buckets) produce a cache MISS when a
// device_platform condition is present. Without UserAgent in the key, an iOS-cached
// decision would be served to an Android request — silently bypassing the condition.
func TestDecisionCacheMissOnDifferentUserAgent(t *testing.T) {
	rows := []PolicyRow{{ID: 1, Name: "platform-block", Enabled: true, ScopeType: "global",
		Conditions: map[string]interface{}{"device_platform": "ios"},
		Actions:    map[string]interface{}{"action": "block"}}}
	store := &countingGeoStore{rows: rows}
	pe := newCacheEngine(store)
	ctx := context.Background()

	iosCtx := PolicyEvalContext{UserID: 7, Country: "US", Protocol: "https",
		UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"}
	androidCtx := PolicyEvalContext{UserID: 7, Country: "US", Protocol: "https",
		UserAgent: "Mozilla/5.0 (Linux; Android 14; Pixel 8)"}

	pe.Evaluate(ctx, iosCtx)
	pe.Evaluate(ctx, androidCtx) // different UA → different platform → must MISS
	if got := store.calls(); got != 2 {
		t.Fatalf("different UserAgent must cache MISS (device_platform collision), got %d ResolveGeoTier calls", got)
	}
}

// TestDecisionCacheMissOnDifferentIsGuestAndRiskLevel pins the narrow-race
// hardening (D-SHARED-THREAT-007): scope selection branches on IsGuest
// ('guests'-scope policies) and require_risk_remediation dispatch branches on
// RiskLevel, so two evals differing in either field must produce a cache MISS
// instead of serving the other side's verdict within the TTL.
func TestDecisionCacheMissOnDifferentIsGuestAndRiskLevel(t *testing.T) {
	store := &countingGeoStore{rows: geoPolicy("notify", nil)}
	pe := newCacheEngine(store)
	ctx := context.Background()
	base := PolicyEvalContext{UserID: 7, Country: "US", Protocol: "imap"}

	pectx1 := base
	pectx1.IsGuest = true
	pectx2 := base
	pectx2.IsGuest = false // guest→member transition: must not share the verdict

	pe.Evaluate(ctx, pectx1)
	pe.Evaluate(ctx, pectx2)
	if got := store.calls(); got != 2 {
		t.Fatalf("different IsGuest must cache MISS (full eval both times), got %d ResolveGeoTier calls", got)
	}

	pe2 := newCacheEngine(store)
	pectx3 := base
	pectx3.RiskLevel = "low"
	pectx4 := base
	pectx4.RiskLevel = "high" // risk-band transition: must not share the verdict

	pe2.Evaluate(ctx, pectx3)
	pe2.Evaluate(ctx, pectx4)
	if got := store.calls(); got != 4 {
		t.Fatalf("different RiskLevel must cache MISS, got %d cumulative ResolveGeoTier calls", got)
	}
}
