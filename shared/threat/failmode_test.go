package threat

import (
	"context"
	"errors"
	"testing"

	"setjoin.com/shared/toggle"
)

// geoErrStore loads policies fine but ResolveGeoTier fails — a mid-eval resolver
// error on a policy that needs geo. The block policy is enforcing.
type geoErrStore struct{ rows []PolicyRow }

func (s *geoErrStore) LoadAllPolicies(ctx context.Context) ([]PolicyRow, error) { return s.rows, nil }
func (s *geoErrStore) LoadPolicies(ctx context.Context, p PolicyEvalContext) ([]PolicyRow, error) {
	return s.rows, nil
}
func (s *geoErrStore) ResolveGeoTier(ctx context.Context, c string) (string, error) {
	return "", errors.New("geo backend down")
}
func (s *geoErrStore) LoadBreakGlass(_ context.Context) ([]int64, error)             { return nil, nil }
func (s *geoErrStore) LoadNamedLocations(_ context.Context) ([]NamedLocation, error) { return nil, nil }
func (s *geoErrStore) LoadAuthStrengths(_ context.Context) ([]AuthStrength, error)   { return nil, nil }

func enforcingBlockRows() []PolicyRow {
	return []PolicyRow{{
		ID: 1, Name: "block-high-geo", Enabled: true, ScopeType: "global",
		Conditions: map[string]interface{}{"geo_risk_tier": "high"},
		Actions:    map[string]interface{}{"action": "block"},
	}}
}

func newFailClosedEngine(store PolicyStore) *PolicyEngine {
	tg := toggle.NewStatic(map[string]bool{toggle.FeatureConditionalAccess: true})
	pe := NewPolicyEngine(store, tg, nil, nil, acrTestLogger(), false)
	pe.failMode = "closed"
	return pe
}

func TestFailClosedBlocksOnEvalError(t *testing.T) {
	pe := newFailClosedEngine(&geoErrStore{rows: enforcingBlockRows()})
	r := pe.Evaluate(context.Background(), PolicyEvalContext{UserID: 7, Country: "RU"})
	if r.Decision != DecisionBlock {
		t.Fatalf("closed + enforcing block + eval error: want DecisionBlock, got %v", r.Decision)
	}
}

func TestFailClosedBreakGlassShortCircuits(t *testing.T) {
	pe := newFailClosedEngine(&geoErrStore{rows: enforcingBlockRows()})
	pe.ExcludeChecker = func(ctx context.Context, p PolicyEvalContext) bool { return p.UserID == 7 }
	r := pe.Evaluate(context.Background(), PolicyEvalContext{UserID: 7, Country: "RU"})
	if r.Decision != DecisionAllow {
		t.Fatalf("excluded principal under eval error: want DecisionAllow (short-circuit), got %v", r.Decision)
	}
}

func TestFailClosedNoEnforcingPolicyAllows(t *testing.T) {
	allowRows := []PolicyRow{{
		ID: 2, Name: "notify-only", Enabled: true, ScopeType: "global",
		Conditions: map[string]interface{}{"geo_risk_tier": "high"},
		Actions:    map[string]interface{}{"action": "notify"},
	}}
	pe := newFailClosedEngine(&geoErrStore{rows: allowRows})
	r := pe.Evaluate(context.Background(), PolicyEvalContext{UserID: 7, Country: "RU"})
	if r.Decision != DecisionAllow {
		t.Fatalf("no enforcing block + eval error: want DecisionAllow (no behavior change), got %v", r.Decision)
	}
}

func TestCheckFailModePostureWarnsOnOpen(t *testing.T) {
	pe := newFailClosedEngine(&geoErrStore{rows: enforcingBlockRows()})
	pe.failMode = "open"
	// Prime the cache so the posture check sees the enforcing block policy.
	_, _ = pe.loadPolicies(context.Background())
	// CheckFailModePosture must not panic and should detect the open+enforcing combo.
	if !pe.hasEnforcingBlockPolicy() {
		t.Fatal("posture check must see the enforcing block policy in the cached set")
	}
	pe.CheckFailModePosture() // logs slog.Warn — asserting no panic; log captured by acrTestLogger
}
