package threat

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"setjoin.com/shared/jwtutil"
)

func acrTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// staticPolicyStore is a closed (no-DB) PolicyStore returning a fixed policy set,
// following the AST-seam pattern used elsewhere in the repo: the engine talks to
// the PolicyStore interface, so a test substitutes an in-memory implementation.
type staticPolicyStore struct {
	policies []PolicyRow
}

func (s *staticPolicyStore) LoadAllPolicies(_ context.Context) ([]PolicyRow, error) {
	return s.policies, nil
}

func (s *staticPolicyStore) LoadPolicies(_ context.Context, _ PolicyEvalContext) ([]PolicyRow, error) {
	return s.policies, nil
}

func (s *staticPolicyStore) ResolveGeoTier(_ context.Context, _ string) (string, error) {
	return "low", nil
}
func (s *staticPolicyStore) LoadBreakGlass(_ context.Context) ([]int64, error) { return nil, nil }
func (s *staticPolicyStore) LoadNamedLocations(_ context.Context) ([]NamedLocation, error) {
	return nil, nil
}
func (s *staticPolicyStore) LoadAuthStrengths(_ context.Context) ([]AuthStrength, error) {
	return nil, nil
}

// newACRPolicyEngine builds a PolicyEngine with conditional access enabled and a
// single global require_acr=aal2 policy. No DeviceTrustResolver / IPRiskScorer
// are wired (nil), so resolution defaults to unknown/low — the policy matches
// every context, isolating the acr requirement under test.
func newACRPolicyEngine(t *testing.T) *PolicyEngine {
	t.Helper()
	// nil toggles: Evaluate's toggle gate is skipped (treated as enabled), which
	// isolates the acr requirement under test without needing a DB-backed
	// FeatureFlags instance.
	store := &staticPolicyStore{policies: []PolicyRow{
		{
			ID:         1,
			Priority:   10,
			Name:       "require-aal2-everywhere",
			Enabled:    true,
			ScopeType:  "global",
			Conditions: map[string]interface{}{}, // matches all contexts
			Actions: map[string]interface{}{
				"action": "require_acr",
				"acr":    jwtutil.ACRAAL2,
			},
		},
	}}
	return NewPolicyEngine(store, nil, nil, nil, acrTestLogger(), false)
}

// TestRequireACR_RejectsAAL1Token proves a require_acr=aal2 policy is NOT
// satisfied by an aal1 token: the downstream EvaluateTokenACR check returns a
// step-up decision (the gateway must reject / force re-auth).
func TestRequireACR_RejectsAAL1Token(t *testing.T) {
	pe := newACRPolicyEngine(t)

	res, ok := pe.EvaluateTokenACR(context.Background(), PolicyEvalContext{
		UserID:     42,
		CurrentACR: jwtutil.ACRAAL1, // aal1 token presented
	})
	if ok {
		t.Fatalf("aal1 token unexpectedly satisfied an aal2 requirement: %+v", res)
	}
	if res.Decision != DecisionStepUp {
		t.Errorf("decision = %s, want step_up", res.Decision)
	}
	if res.RequiredACR != jwtutil.ACRAAL2 {
		t.Errorf("RequiredACR = %q, want aal2", res.RequiredACR)
	}
}

// TestRequireACR_AllowsAAL2Token proves the same policy is satisfied by an aal2
// token (no step-up).
func TestRequireACR_AllowsAAL2Token(t *testing.T) {
	pe := newACRPolicyEngine(t)

	res, ok := pe.EvaluateTokenACR(context.Background(), PolicyEvalContext{
		UserID:     42,
		CurrentACR: jwtutil.ACRAAL2,
	})
	if !ok {
		t.Fatalf("aal2 token failed an aal2 requirement: %+v", res)
	}
	if res.Decision != DecisionAllow {
		t.Errorf("decision = %s, want allow", res.Decision)
	}
}

// TestRequireACR_LoginStepUp proves that at login time (no acr yet), a
// require_acr=aal2 policy forces a step-up so the user completes a second factor.
func TestRequireACR_LoginStepUp(t *testing.T) {
	pe := newACRPolicyEngine(t)

	res := pe.Evaluate(context.Background(), PolicyEvalContext{
		UserID:     42,
		CurrentACR: "", // first factor only
	})
	if res.Decision != DecisionStepUp {
		t.Errorf("decision = %s, want step_up", res.Decision)
	}
	if len(res.StepUpMethods) == 0 {
		t.Error("expected default step-up methods to be populated")
	}
}

// TestRequireACR_DefaultsToAAL2 proves a require_acr action with no explicit acr
// defaults to demanding aal2.
func TestRequireACR_DefaultsToAAL2(t *testing.T) {
	row := PolicyRow{ID: 1, Name: "p", Actions: map[string]interface{}{"action": "require_acr"}}
	res := dispatchAction(row.Actions, row, PolicyEvalContext{CurrentACR: jwtutil.ACRAAL1}, nil)
	if res.RequiredACR != jwtutil.ACRAAL2 {
		t.Errorf("RequiredACR = %q, want aal2 default", res.RequiredACR)
	}
	if res.Decision != DecisionStepUp {
		t.Errorf("decision = %s, want step_up for unsatisfied default", res.Decision)
	}
}
