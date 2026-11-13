package threat

import (
	"context"
	"log/slog"
	"testing"

	"setjoin.com/shared/toggle"
)

// fakeStore returns a fixed policy set and a break-glass list.
type fakeStore struct {
	rows       []PolicyRow
	breakGlass []int64
}

func (f *fakeStore) LoadAllPolicies(_ context.Context) ([]PolicyRow, error) { return f.rows, nil }
func (f *fakeStore) LoadPolicies(_ context.Context, _ PolicyEvalContext) ([]PolicyRow, error) {
	return f.rows, nil
}
func (f *fakeStore) ResolveGeoTier(_ context.Context, _ string) (string, error) { return "low", nil }
func (f *fakeStore) LoadBreakGlass(_ context.Context) ([]int64, error) {
	return f.breakGlass, nil
}
func (f *fakeStore) LoadNamedLocations(_ context.Context) ([]NamedLocation, error) { return nil, nil }
func (f *fakeStore) LoadAuthStrengths(_ context.Context) ([]AuthStrength, error)   { return nil, nil }

func newEngineWith(rows []PolicyRow, bg []int64) *PolicyEngine {
	tg := toggle.NewStatic(map[string]bool{toggle.FeatureConditionalAccess: true})
	pe := NewPolicyEngine(&fakeStore{rows: rows, breakGlass: bg}, tg, nil, nil, slog.Default(), false)
	pe.SetBreakGlass(bg)
	return pe
}

func TestEvaluate_ExcludeBeforeInclude(t *testing.T) {
	rows := []PolicyRow{{ID: 1, State: "on", ScopeType: "global", Actions: map[string]interface{}{"action": "block"}, ExcludeUsers: []int64{7}}}
	pe := newEngineWith(rows, nil)
	res := pe.Evaluate(context.Background(), PolicyEvalContext{UserID: 7})
	if res.Decision != DecisionAllow {
		t.Fatalf("excluded admin under global-block should be Allow, got %v", res.Decision)
	}
}

func TestEvaluate_ExcludeByGroup(t *testing.T) {
	rows := []PolicyRow{{ID: 1, State: "on", ScopeType: "global", Actions: map[string]interface{}{"action": "block"}, ExcludeGroups: []int64{42}}}
	pe := newEngineWith(rows, nil)
	res := pe.Evaluate(context.Background(), PolicyEvalContext{UserID: 7, GroupIDs: []int64{42}})
	if res.Decision != DecisionAllow {
		t.Fatalf("group-excluded principal under global-block should be Allow, got %v", res.Decision)
	}
}

func TestEvaluate_ExcludeByBreakGlass(t *testing.T) {
	rows := []PolicyRow{{ID: 1, State: "on", ScopeType: "global", Actions: map[string]interface{}{"action": "block"}}}
	pe := newEngineWith(rows, []int64{7})
	res := pe.Evaluate(context.Background(), PolicyEvalContext{UserID: 7})
	if res.Decision != DecisionAllow {
		t.Fatalf("break-glass admin under global-block should be Allow, got %v", res.Decision)
	}
}

func TestEvaluate_ReportOnlyNeverEnforces(t *testing.T) {
	rows := []PolicyRow{{ID: 1, State: "report_only", ScopeType: "global", Actions: map[string]interface{}{"action": "block"}}}
	pe := newEngineWith(rows, nil)
	res := pe.Evaluate(context.Background(), PolicyEvalContext{UserID: 7})
	if res.Decision != DecisionAllow {
		t.Fatalf("report_only block must never enforce, got %v", res.Decision)
	}
}

func TestEvaluate_ReportOnlyDoesNotShadowOn(t *testing.T) {
	rows := []PolicyRow{
		{ID: 1, Priority: 10, State: "report_only", ScopeType: "global", Actions: map[string]interface{}{"action": "block"}},
		{ID: 2, Priority: 20, State: "on", ScopeType: "global", Actions: map[string]interface{}{"action": "block"}},
	}
	pe := newEngineWith(rows, nil)
	res := pe.Evaluate(context.Background(), PolicyEvalContext{UserID: 7})
	if res.Decision != DecisionBlock || res.PolicyID != 2 {
		t.Fatalf("on policy must still enforce despite an earlier report_only match, got %v id=%d", res.Decision, res.PolicyID)
	}
}

func TestEvaluate_OnBlockStillBlocks(t *testing.T) {
	rows := []PolicyRow{{ID: 3, State: "on", ScopeType: "global", Actions: map[string]interface{}{"action": "block"}}}
	pe := newEngineWith(rows, nil)
	res := pe.Evaluate(context.Background(), PolicyEvalContext{UserID: 99})
	if res.Decision != DecisionBlock || res.PolicyID != 3 {
		t.Fatalf("on block policy with no exclude must block, got %v id=%d", res.Decision, res.PolicyID)
	}
}
