package threat

import (
	"context"
	"testing"

	"setjoin.com/shared/toggle"
)

// fakeRawStore returns a fixed raw set and counts LoadAllPolicies calls so the
// test proves the cache loads ONCE and is filtered per-request afterwards.
type fakeRawStore struct {
	rows  []PolicyRow
	loads int
}

func (f *fakeRawStore) LoadAllPolicies(ctx context.Context) ([]PolicyRow, error) {
	f.loads++
	return f.rows, nil
}
func (f *fakeRawStore) LoadPolicies(ctx context.Context, p PolicyEvalContext) ([]PolicyRow, error) {
	return f.rows, nil
}
func (f *fakeRawStore) ResolveGeoTier(ctx context.Context, c string) (string, error) {
	return "low", nil
}
func (f *fakeRawStore) LoadBreakGlass(_ context.Context) ([]int64, error) { return nil, nil }
func (f *fakeRawStore) LoadNamedLocations(_ context.Context) ([]NamedLocation, error) {
	return nil, nil
}
func (f *fakeRawStore) LoadAuthStrengths(_ context.Context) ([]AuthStrength, error) { return nil, nil }

func TestRawCacheFiltersPerUser(t *testing.T) {
	store := &fakeRawStore{rows: []PolicyRow{
		{ID: 1, Name: "block-user-7", ScopeType: "user", ScopeTarget: "7",
			Actions: map[string]interface{}{"action": "block"}},
		{ID: 2, Name: "block-user-9", ScopeType: "user", ScopeTarget: "9",
			Actions: map[string]interface{}{"action": "block"}},
	}}
	tg := toggle.NewStatic(map[string]bool{toggle.FeatureConditionalAccess: true})
	pe := NewPolicyEngine(store, tg, nil, nil, acrTestLogger(), false)

	// User 7 is blocked by policy 1.
	r7 := pe.Evaluate(context.Background(), PolicyEvalContext{UserID: 7})
	if r7.Decision != DecisionBlock {
		t.Fatalf("user 7: want block, got %v", r7.Decision)
	}
	// User 9 is blocked by policy 2 — served from the SAME cached raw load.
	r9 := pe.Evaluate(context.Background(), PolicyEvalContext{UserID: 9})
	if r9.Decision != DecisionBlock {
		t.Fatalf("user 9: want block (no cross-user leak), got %v", r9.Decision)
	}
	// User 5 matches neither -> allow.
	r5 := pe.Evaluate(context.Background(), PolicyEvalContext{UserID: 5})
	if r5.Decision != DecisionAllow {
		t.Fatalf("user 5: want allow, got %v", r5.Decision)
	}
	if store.loads != 1 {
		t.Fatalf("want exactly 1 raw load (cache), got %d", store.loads)
	}
}
