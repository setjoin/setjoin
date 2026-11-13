package middleware

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/threat"
	"setjoin.com/shared/toggle"
)

func benchDeps(featureOn bool) RuntimeAccessDeps {
	toggles := toggle.NewTestFlags(map[string]bool{toggle.FeatureCAERuntime: featureOn})
	sif := int64(86400)
	claims := &jwtutil.Claims{UserID: 1, SignInFreq: &sif}
	claims.IssuedAt = jwtutil.NewNumericDate(time.Now())
	return RuntimeAccessDeps{
		Claims:   func(*http.Request) *jwtutil.Claims { return claims },
		Denylist: threat.NewSessionDenylist(nil, slog.Default()),
		Engine:   nil, // no enabled policy references device/IP ⇒ resolution skipped
		Toggles:  toggles,
		Replay:   threat.NewDPoPReplayCache(time.Minute),
		Logger:   slog.Default(),
	}
}

// stubPolicyStore is an in-memory PolicyStore returning M global policies each
// carrying a device_trust condition. No DB or network call is ever made.
// ponytail: satisfies threat.PolicyStore; only LoadAllPolicies is called by the engine hot path.
type stubPolicyStore struct{ rows []threat.PolicyRow }

func (s *stubPolicyStore) LoadAllPolicies(_ context.Context) ([]threat.PolicyRow, error) {
	return s.rows, nil
}
func (s *stubPolicyStore) LoadPolicies(_ context.Context, _ threat.PolicyEvalContext) ([]threat.PolicyRow, error) {
	return s.rows, nil
}
func (s *stubPolicyStore) ResolveGeoTier(_ context.Context, _ string) (string, error) {
	return "low", nil
}
func (s *stubPolicyStore) LoadBreakGlass(_ context.Context) ([]int64, error) { return nil, nil }
func (s *stubPolicyStore) LoadNamedLocations(_ context.Context) ([]threat.NamedLocation, error) {
	return nil, nil
}
func (s *stubPolicyStore) LoadAuthStrengths(_ context.Context) ([]threat.AuthStrength, error) {
	return nil, nil
}

// makePoliciesWithDeviceCond returns m global policies each carrying a
// device_trust condition (the condition that triggers trust-tier resolution).
// All policies allow on match; with trustTier="unknown" (nil deviceTrust resolver)
// none match, so the scanner walks all m entries — the worst-case hot path.
func makePoliciesWithDeviceCond(m int) []threat.PolicyRow {
	rows := make([]threat.PolicyRow, m)
	for i := range rows {
		rows[i] = threat.PolicyRow{
			ID:         int64(i + 1),
			Priority:   i + 1,
			Name:       fmt.Sprintf("device-policy-%d", i+1),
			State:      "on",
			ScopeType:  "global",
			Conditions: map[string]interface{}{"device_trust": "managed"},
			Actions:    map[string]interface{}{"action": "allow"},
		}
	}
	return rows
}

// benchDepsWithConds returns RuntimeAccessDeps with a non-nil Engine backed by
// a stub store returning m policies that all carry a device_trust condition.
// Engine.deviceTrust=nil → trustTier resolves to "unknown" in-process (no DB).
// Country left empty → ResolveGeoTier is never called (no DB).
// Cache is warmed before returning so benchmarks measure the hot path only.
func benchDepsWithConds(m int) RuntimeAccessDeps {
	toggles := toggle.NewTestFlags(map[string]bool{
		toggle.FeatureCAERuntime:        true,
		toggle.FeatureConditionalAccess: true,
	})
	sif := int64(86400)
	claims := &jwtutil.Claims{UserID: 1, SignInFreq: &sif}
	claims.IssuedAt = jwtutil.NewNumericDate(time.Now())

	store := &stubPolicyStore{rows: makePoliciesWithDeviceCond(m)}
	// nil deviceTrust + nil ipRisk: resolveTrustTier returns "unknown" immediately;
	// resolveIPRiskChecked returns "low" without calling the store (Country is empty).
	engine := threat.NewPolicyEngine(store, toggles, nil, nil, slog.Default(), false)
	// Warm the policy cache so the benchmark loop measures only the hot-path eval.
	engine.Evaluate(context.Background(), threat.PolicyEvalContext{UserID: 0})

	return RuntimeAccessDeps{
		Claims:   func(*http.Request) *jwtutil.Claims { return claims },
		Denylist: threat.NewSessionDenylist(nil, slog.Default()),
		Engine:   engine,
		Toggles:  toggles,
		Replay:   threat.NewDPoPReplayCache(time.Minute),
		Logger:   slog.Default(),
	}
}

func BenchmarkRuntimeAccessFeatureOff(b *testing.B) {
	mw := RequireRuntimeAccess(benchDeps(false))(okHandler())
	req := httptest.NewRequest("GET", "/jmap", nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mw.ServeHTTP(httptest.NewRecorder(), req)
	}
}

func BenchmarkRuntimeAccessFeatureOnNoConditions(b *testing.B) {
	mw := RequireRuntimeAccess(benchDeps(true))(okHandler())
	req := httptest.NewRequest("GET", "/jmap", nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mw.ServeHTTP(httptest.NewRecorder(), req)
	}
}

// BenchmarkRuntimeAccessWithDeviceConditions benchmarks the feature-on path with
// a non-nil Engine carrying M global policies each referencing device_trust.
// This is the code path that could accidentally add a DB or GeoIP call on Engine
// evaluation — the budget guard below catches any such regression.
func BenchmarkRuntimeAccessWithDeviceConditions(b *testing.B) {
	for _, m := range []int{1, 10, 50} {
		m := m
		b.Run(fmt.Sprintf("M%d", m), func(b *testing.B) {
			deps := benchDepsWithConds(m)
			mw := RequireRuntimeAccess(deps)(okHandler())
			req := httptest.NewRequest("GET", "/jmap", nil)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				mw.ServeHTTP(httptest.NewRecorder(), req)
			}
		})
	}
}

// TestRuntimeCostBudget asserts the feature-on no-conditions path is not
// pathologically slower than feature-off (the condition-gating keeps it a map
// lookup, not a DB/GeoIP call). Budget: ≤ 50x the feature-off per-op time on
// the same machine (generous; catches an accidental DB call on the hot path).
func TestRuntimeCostBudget(t *testing.T) {
	off := testing.Benchmark(BenchmarkRuntimeAccessFeatureOff)
	on := testing.Benchmark(BenchmarkRuntimeAccessFeatureOnNoConditions)
	if on.NsPerOp() > 50*off.NsPerOp()+5000 {
		t.Fatalf("feature-on hot path too slow: on=%dns off=%dns", on.NsPerOp(), off.NsPerOp())
	}
}

// TestRuntimeCostBudgetWithDeviceConditions asserts the with-device-conditions
// path (non-nil Engine, M policies carrying device_trust) stays within budget
// at each policy-count step. An accidental DB or GeoIP call on this path would
// push ns/op orders of magnitude above the feature-off baseline.
// Budget: ≤ 200x off + 10 000 ns (generous — real ceiling is ≈5x at M=50 on CI).
func TestRuntimeCostBudgetWithDeviceConditions(t *testing.T) {
	off := testing.Benchmark(BenchmarkRuntimeAccessFeatureOff)
	for _, m := range []int{1, 10, 50} {
		m := m
		t.Run(fmt.Sprintf("M%d", m), func(t *testing.T) {
			result := testing.Benchmark(func(b *testing.B) {
				deps := benchDepsWithConds(m)
				mw := RequireRuntimeAccess(deps)(okHandler())
				req := httptest.NewRequest("GET", "/jmap", nil)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					mw.ServeHTTP(httptest.NewRecorder(), req)
				}
			})
			if result.NsPerOp() > 200*off.NsPerOp()+10000 {
				t.Fatalf("with-device-conditions M=%d too slow: on=%dns off=%dns (budget=200x+10000ns)",
					m, result.NsPerOp(), off.NsPerOp())
			}
		})
	}
}
