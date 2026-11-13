package threat

import (
	"context"
	"testing"

	"setjoin.com/shared/toggle"
)

// TestInvalidateForcesReload proves the seam the NOTIFY listeners call:
// after InvalidateCache(), the next Evaluate() must reload from the store
// (not serve the prior cached set). This is the only job of the
// NOTIFY->InvalidateCache handler wired in both servers on "conditional_access".
func TestInvalidateForcesReload(t *testing.T) {
	store := &fakeRawStore{rows: []PolicyRow{
		{ID: 1, Name: "p", ScopeType: "global", Actions: map[string]interface{}{"action": "allow"}},
	}}
	tg := toggle.NewStatic(map[string]bool{toggle.FeatureConditionalAccess: true})
	pe := NewPolicyEngine(store, tg, nil, nil, acrTestLogger(), false)

	// First Evaluate: loads from store (load #1).
	pe.Evaluate(context.Background(), PolicyEvalContext{UserID: 1})

	// InvalidateCache: must clear cachedPolicies so next Evaluate reloads.
	pe.InvalidateCache()

	// Second Evaluate: cache is gone, must reload (load #2).
	pe.Evaluate(context.Background(), PolicyEvalContext{UserID: 1})

	if store.loads != 2 {
		t.Fatalf("InvalidateCache must force reload: want 2 loads, got %d", store.loads)
	}
}
