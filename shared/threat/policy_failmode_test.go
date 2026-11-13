package threat

import (
	"context"
	"errors"
	"testing"
)

// errPolicyStore is a PolicyStore whose LoadAllPolicies always fails — the seam for
// pinning the fail-closed / fail-open fork in PolicyEngine.Evaluate. It mirrors
// the staticPolicyStore pattern in policy_acr_test.go.
type errPolicyStore struct{}

func (errPolicyStore) LoadAllPolicies(_ context.Context) ([]PolicyRow, error) {
	return nil, errors.New("simulated policy-store failure (DB blip)")
}

func (errPolicyStore) LoadPolicies(_ context.Context, _ PolicyEvalContext) ([]PolicyRow, error) {
	return nil, errors.New("simulated policy-store failure (DB blip)")
}

func (errPolicyStore) ResolveGeoTier(_ context.Context, _ string) (string, error) {
	return "low", nil
}
func (errPolicyStore) LoadBreakGlass(_ context.Context) ([]int64, error)             { return nil, nil }
func (errPolicyStore) LoadNamedLocations(_ context.Context) ([]NamedLocation, error) { return nil, nil }
func (errPolicyStore) LoadAuthStrengths(_ context.Context) ([]AuthStrength, error)   { return nil, nil }

// errAfterLoadStore loads policies successfully once (populating the cache), then
// has ResolveGeoTier always fail — simulates a mid-eval error after a successful
// cache warm. Used to exercise the cacheLoaded=true branch of failModeDecision.
type errAfterLoadStore struct{ rows []PolicyRow }

func (s *errAfterLoadStore) LoadAllPolicies(_ context.Context) ([]PolicyRow, error) {
	return s.rows, nil
}
func (s *errAfterLoadStore) LoadPolicies(_ context.Context, _ PolicyEvalContext) ([]PolicyRow, error) {
	return s.rows, nil
}
func (s *errAfterLoadStore) ResolveGeoTier(_ context.Context, _ string) (string, error) {
	return "", errors.New("geo backend down (simulated)")
}
func (s *errAfterLoadStore) LoadBreakGlass(_ context.Context) ([]int64, error) { return nil, nil }
func (s *errAfterLoadStore) LoadNamedLocations(_ context.Context) ([]NamedLocation, error) {
	return nil, nil
}
func (s *errAfterLoadStore) LoadAuthStrengths(_ context.Context) ([]AuthStrength, error) {
	return nil, nil
}

// TestPolicyEngine_FailClosed_Legacy_BlocksOnLoadError pins the legacy failClosed=true
// constructor param. It is now a back-compat shim that maps to failMode="closed"; the
// engine has never successfully loaded policies (errPolicyStore always fails), so
// cacheLoaded stays false → BLOCK (cold-boot safe default).
//
// nil toggles ⇒ the conditional-access gate is treated as enabled (per the
// policy_acr_test.go pattern), so Evaluate reaches the load-error branch.
func TestPolicyEngine_FailClosed_Legacy_BlocksOnLoadError(t *testing.T) {
	pe := NewPolicyEngine(errPolicyStore{}, nil, nil, nil, acrTestLogger(), true /* failClosed */)

	res := pe.Evaluate(context.Background(), PolicyEvalContext{UserID: 7})

	if res.Decision != DecisionBlock {
		t.Fatalf("SECURITY: failClosed=true (legacy, cache never loaded) did NOT fail closed: decision=%s reason=%q",
			res.Decision, res.Reason)
	}
}

// TestPolicyEngine_FailClosed_NeverLoaded_BlocksOnLoadError pins the cold-boot safety
// gate: failMode="closed" + eval error + cache NEVER SUCCESSFULLY LOADED → BLOCK.
// We cannot prove it is safe to allow when we have never seen the policy set.
func TestPolicyEngine_FailClosed_NeverLoaded_BlocksOnLoadError(t *testing.T) {
	pe := NewPolicyEngine(errPolicyStore{}, nil, nil, nil, acrTestLogger(), false)
	// failMode="closed" is the default; cacheLoaded stays false because errPolicyStore fails.

	res := pe.Evaluate(context.Background(), PolicyEvalContext{UserID: 7})

	if res.Decision != DecisionBlock {
		t.Fatalf("SECURITY: failMode=closed + never-loaded cache did NOT fail closed: decision=%s reason=%q",
			res.Decision, res.Reason)
	}
}

// TestPolicyEngine_FailClosed_LoadedEnforcing_BlocksOnEvalError pins the case where
// the cache was successfully loaded and contains an enforcing block policy, then a
// mid-eval error (e.g. geo backend) fires → BLOCK.
func TestPolicyEngine_FailClosed_LoadedEnforcing_BlocksOnEvalError(t *testing.T) {
	enforcingRows := []PolicyRow{{
		ID: 1, Name: "block-high-geo", Enabled: true, ScopeType: "global",
		Conditions: map[string]interface{}{"geo_risk_tier": "high"},
		Actions:    map[string]interface{}{"action": "block"},
	}}
	pe := NewPolicyEngine(&errAfterLoadStore{rows: enforcingRows}, nil, nil, nil, acrTestLogger(), false)
	// failMode="closed" default; cache will be loaded by first Evaluate call, then geo fails.

	res := pe.Evaluate(context.Background(), PolicyEvalContext{UserID: 7, Country: "RU"})

	if res.Decision != DecisionBlock {
		t.Fatalf("SECURITY: failMode=closed + enforcing policy + eval error did NOT fail closed: decision=%s reason=%q",
			res.Decision, res.Reason)
	}
}

// TestPolicyEngine_FailClosed_LoadedZeroEnforcing_AllowsOnEvalError pins the spec's
// "zero enforcing → allow" case: cache successfully loaded WITH zero enforcing policies
// (only notify-action policies), then a mid-eval error fires. Since we KNOW no
// enforcing policy exists, allow is correct per spec.
func TestPolicyEngine_FailClosed_LoadedZeroEnforcing_AllowsOnEvalError(t *testing.T) {
	notifyOnlyRows := []PolicyRow{{
		ID: 2, Name: "notify-only", Enabled: true, ScopeType: "global",
		Conditions: map[string]interface{}{"geo_risk_tier": "high"},
		Actions:    map[string]interface{}{"action": "notify"},
	}}
	pe := NewPolicyEngine(&errAfterLoadStore{rows: notifyOnlyRows}, nil, nil, nil, acrTestLogger(), false)
	// failMode="closed" default; cache loads successfully with zero enforcing policies.

	res := pe.Evaluate(context.Background(), PolicyEvalContext{UserID: 7, Country: "RU"})

	if res.Decision != DecisionAllow {
		t.Fatalf("failMode=closed + zero enforcing + eval error: want DecisionAllow (we KNOW none enforce), got %v reason=%q",
			res.Decision, res.Reason)
	}
}

// TestPolicyEngine_BreakGlass_AllowsOnEvalError pins the break-glass short-circuit:
// excluded principal + eval error → ALLOW regardless of fail mode. The excluded admin
// must never be stranded by an eval error.
func TestPolicyEngine_BreakGlass_AllowsOnEvalError(t *testing.T) {
	pe := NewPolicyEngine(errPolicyStore{}, nil, nil, nil, acrTestLogger(), true /* failClosed */)
	pe.ExcludeChecker = func(_ context.Context, p PolicyEvalContext) bool { return p.UserID == 7 }

	res := pe.Evaluate(context.Background(), PolicyEvalContext{UserID: 7})

	if res.Decision != DecisionAllow {
		t.Fatalf("break-glass excluded principal under eval error: want DecisionAllow, got %v reason=%q",
			res.Decision, res.Reason)
	}
}

// TestPolicyEngine_FailOpen_AllowsOnLoadError pins that failMode="open" always allows
// on eval error, regardless of cache state (availability over strictness).
func TestPolicyEngine_FailOpen_AllowsOnLoadError(t *testing.T) {
	pe := NewPolicyEngine(errPolicyStore{}, nil, nil, nil, acrTestLogger(), false)
	pe.failMode = "open" // explicitly open posture

	res := pe.Evaluate(context.Background(), PolicyEvalContext{UserID: 7})

	if res.Decision != DecisionAllow {
		t.Fatalf("failMode=open engine did NOT allow on policy-load error: decision=%s reason=%q",
			res.Decision, res.Reason)
	}
}

// TestPolicyEngine_FailClosed_ReportOnlyBlockOnly_AllowsOnEvalError pins the core
// report_only contract for fail-mode: a deployment whose ONLY block policy is
// State="report_only" must NEVER enforce under an eval error, even in fail_mode=closed.
// report_only policies are "evaluated but never enforced"; they must not silently
// become blocking via the fail-closed safety net.
func TestPolicyEngine_FailClosed_ReportOnlyBlockOnly_AllowsOnEvalError(t *testing.T) {
	reportOnlyRows := []PolicyRow{{
		ID: 9, Name: "dry-run-block", Enabled: true, ScopeType: "global",
		State:      "report_only",
		Conditions: map[string]interface{}{"geo_risk_tier": "high"},
		Actions:    map[string]interface{}{"action": "block"},
	}}
	// errAfterLoadStore: cache loads successfully (cacheLoaded=true), then geo fails.
	pe := NewPolicyEngine(&errAfterLoadStore{rows: reportOnlyRows}, nil, nil, nil, acrTestLogger(), false)
	// failMode="closed" is the default.

	res := pe.Evaluate(context.Background(), PolicyEvalContext{UserID: 7, Country: "RU"})

	if res.Decision != DecisionAllow {
		t.Fatalf("SECURITY: report_only-only deployment + failMode=closed + eval error must NOT block: decision=%s reason=%q",
			res.Decision, res.Reason)
	}
}

// ── I1 tests: internal break-glass snapshot survives fail-closed branch ──────

// TestBreakGlass_SurvivesFailClosed_LoadError pins the I1 fix: a break-glass admin
// must get DecisionAllow even when loadPolicies fails (DB blip) under fail_mode=closed.
// The internal snapshot check runs BEFORE loadPolicies; no per-server wiring needed.
//
//	(a-load) break-glass + fail_mode=closed + load error → DecisionAllow
func TestBreakGlass_SurvivesFailClosed_LoadError(t *testing.T) {
	// errPolicyStore.LoadAllPolicies always fails — simulates DB blip.
	pe := NewPolicyEngine(errPolicyStore{}, nil, nil, nil, acrTestLogger(), true /* failClosed=closed */)
	pe.SetBreakGlass([]int64{42})

	res := pe.Evaluate(context.Background(), PolicyEvalContext{UserID: 42})

	if res.Decision != DecisionAllow {
		t.Fatalf("SECURITY (I1): break-glass admin stranded by load error under fail_mode=closed: decision=%s reason=%q",
			res.Decision, res.Reason)
	}
	if res.Reason != "break-glass exempt" {
		t.Fatalf("I1: expected 'break-glass exempt' reason, got %q", res.Reason)
	}
}

// TestBreakGlass_SurvivesFailClosed_GeoError pins the I1 fix for the mid-eval error
// path: geo-resolver error after a successful cache load.
//
//	(a-geo) break-glass + fail_mode=closed + geo-resolver error → DecisionAllow
func TestBreakGlass_SurvivesFailClosed_GeoError(t *testing.T) {
	// errAfterLoadStore: LoadAllPolicies succeeds (cache loaded), ResolveGeoTier fails.
	enforcingRows := []PolicyRow{{
		ID: 1, Name: "block-all", State: "on", ScopeType: "global",
		Conditions: map[string]interface{}{"geo_risk_tier": "high"},
		Actions:    map[string]interface{}{"action": "block"},
	}}
	pe := NewPolicyEngine(&errAfterLoadStore{rows: enforcingRows}, nil, nil, nil, acrTestLogger(), true)
	pe.SetBreakGlass([]int64{42})

	res := pe.Evaluate(context.Background(), PolicyEvalContext{UserID: 42, Country: "RU"})

	if res.Decision != DecisionAllow {
		t.Fatalf("SECURITY (I1): break-glass admin stranded by geo error under fail_mode=closed: decision=%s reason=%q",
			res.Decision, res.Reason)
	}
}

// TestNonBreakGlass_BlockedUnderFailClosed pins that a non-break-glass admin is
// still blocked by the fail-closed branch (the fix must not widen the exclusion).
//
//	(b) non-break-glass + fail_mode=closed + load error → DecisionBlock
func TestNonBreakGlass_BlockedUnderFailClosed(t *testing.T) {
	pe := NewPolicyEngine(errPolicyStore{}, nil, nil, nil, acrTestLogger(), true /* failClosed=closed */)
	pe.SetBreakGlass([]int64{42}) // user 99 is NOT in the set

	res := pe.Evaluate(context.Background(), PolicyEvalContext{UserID: 99})

	if res.Decision != DecisionBlock {
		t.Fatalf("SECURITY (I1 non-regression): non-break-glass user should be blocked under fail_mode=closed + load error: decision=%s reason=%q",
			res.Decision, res.Reason)
	}
}

// TestBreakGlass_AllowsUnderNormalBlock pins that the internal snapshot short-circuit
// fires even when there is NO error — a break-glass admin under an enforcing global-block
// policy must still be allowed (exclude-before-include, now via internal snapshot).
//
//	(c) break-glass + normal enforcing block (no error) → DecisionAllow
func TestBreakGlass_AllowsUnderNormalBlock(t *testing.T) {
	rows := []PolicyRow{{
		ID: 1, State: "on", ScopeType: "global",
		Actions: map[string]interface{}{"action": "block"},
	}}
	pe := newEngineWith(rows, []int64{42})

	res := pe.Evaluate(context.Background(), PolicyEvalContext{UserID: 42})

	if res.Decision != DecisionAllow {
		t.Fatalf("I1: break-glass admin under enforcing global-block must be Allow, got %v reason=%q",
			res.Decision, res.Reason)
	}
}
