package threat

import "testing"

func dispatch(actions map[string]interface{}, pectx PolicyEvalContext, strengths map[int64]AuthStrength) PolicyResult {
	return dispatchAction(actions, PolicyRow{ID: 1, Name: "t"}, pectx, strengths)
}

func TestDispatchLegacySingleAction(t *testing.T) {
	// Read-only legacy tolerance: bare {"action":"block"} parses as one block grant.
	got := dispatch(map[string]interface{}{"action": "block"}, PolicyEvalContext{}, nil)
	if got.Decision != DecisionBlock {
		t.Fatalf("legacy single-action block = %v, want block", got.Decision)
	}
}

func TestDispatchGrantArrayAllBlockShortCircuits(t *testing.T) {
	actions := map[string]interface{}{"operator": "all", "grants": []interface{}{
		map[string]interface{}{"type": "block"},
		map[string]interface{}{"type": "allow"},
	}}
	if got := dispatch(actions, PolicyEvalContext{}, nil); got.Decision != DecisionBlock {
		t.Fatalf("ALL with a block grant must block, got %v", got.Decision)
	}
}

func TestDispatchGrantArrayOneAllowSufficient(t *testing.T) {
	actions := map[string]interface{}{"operator": "one", "grants": []interface{}{
		map[string]interface{}{"type": "require_acr", "acr": "aal2"}, // unsatisfied (no CurrentACR)
		map[string]interface{}{"type": "allow"},
	}}
	if got := dispatch(actions, PolicyEvalContext{}, nil); got.Decision != DecisionAllow {
		t.Fatalf("ONE with a satisfied allow grant must allow, got %v", got.Decision)
	}
}

func TestDispatchRequireStrengthHTTPStepUp(t *testing.T) {
	strengths := map[int64]AuthStrength{1: {ID: 1, Slug: "phishing-resistant", Combinations: [][]string{{"webauthn"}}, MinACR: "aal2"}}
	actions := map[string]interface{}{"operator": "all", "grants": []interface{}{
		map[string]interface{}{"type": "require_strength", "strength_id": float64(1)},
	}}
	// HTTP context: factors known but webauthn not completed → step up, missing factor surfaced.
	pectx := PolicyEvalContext{CompletedFactors: []string{"password"}, CurrentACR: "aal1"}
	got := dispatch(actions, pectx, strengths)
	if got.Decision != DecisionStepUp {
		t.Fatalf("unsatisfied strength on HTTP = %v, want step_up", got.Decision)
	}
	if len(got.StepUpMethods) == 0 {
		t.Fatal("expected missing factors in StepUpMethods")
	}
	// Satisfied → allow.
	pectx2 := PolicyEvalContext{CompletedFactors: []string{"webauthn"}, CurrentACR: "aal2"}
	if got2 := dispatch(actions, pectx2, strengths); got2.Decision != DecisionAllow {
		t.Fatalf("satisfied strength = %v, want allow", got2.Decision)
	}
}

func TestDispatchRequireStrengthLegacyBlocks(t *testing.T) {
	strengths := map[int64]AuthStrength{1: {ID: 1, Combinations: [][]string{{"webauthn"}}, MinACR: "aal2"}}
	actions := map[string]interface{}{"operator": "all", "grants": []interface{}{
		map[string]interface{}{"type": "require_strength", "strength_id": float64(1)},
	}}
	// Legacy/no-CurrentACR + no completed factors known → block (T3).
	pectx := PolicyEvalContext{ClientType: "imap"}
	if got := dispatch(actions, pectx, strengths); got.Decision != DecisionBlock {
		t.Fatalf("require_strength on legacy = %v, want block", got.Decision)
	}
}

// Finding 1 guard: empty grants array must fail-closed (block), not allow.
func TestDispatchEmptyGrantsFailClosed(t *testing.T) {
	// Canonical empty grants array — must block, not allow.
	got := dispatch(map[string]interface{}{"operator": "all", "grants": []interface{}{}}, PolicyEvalContext{}, nil)
	if got.Decision != DecisionBlock {
		t.Fatalf("empty grants array = %v, want block (fail-closed)", got.Decision)
	}
	// operator=one, empty grants → also block.
	got2 := dispatch(map[string]interface{}{"operator": "one", "grants": []interface{}{}}, PolicyEvalContext{}, nil)
	if got2.Decision != DecisionBlock {
		t.Fatalf("operator=one empty grants = %v, want block (fail-closed)", got2.Decision)
	}
	if !isEnforcingActions(map[string]interface{}{"operator": "all", "grants": []interface{}{}}) {
		t.Fatal("empty grants must be classified as enforcing because runtime dispatch blocks")
	}
}

func TestDispatchInvalidGrantDiscriminatorsFailClosed(t *testing.T) {
	tests := []struct {
		name  string
		grant interface{}
	}{
		{name: "missing", grant: map[string]interface{}{}},
		{name: "unknown", grant: map[string]interface{}{"type": "unknown"}},
		{name: "malformed", grant: map[string]interface{}{"type": true}},
		{name: "malformed canonical with legacy allow fallback", grant: map[string]interface{}{"type": true, "action": "allow"}},
		{name: "empty canonical with legacy allow fallback", grant: map[string]interface{}{"type": "", "action": "allow"}},
		{name: "conflicting", grant: map[string]interface{}{"type": "allow", "action": "block"}},
		{name: "non-object", grant: "block"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actions := map[string]interface{}{
				"operator": "all",
				"grants":   []interface{}{tt.grant},
			}
			if got := dispatch(actions, PolicyEvalContext{}, nil); got.Decision != DecisionBlock {
				t.Fatalf("invalid grant dispatch = %v, want block", got.Decision)
			}
			if !isEnforcingActions(actions) {
				t.Fatal("invalid grant must be classified as enforcing because runtime dispatch blocks")
			}
		})
	}
}

// Finding 3 guard: operator=one must allow if ANY grant resolves to allow,
// regardless of whether a block grant appears before or after the allow.
func TestDispatchOneOperatorBlockBeforeAllow(t *testing.T) {
	// block first, then allow — must allow (OR semantics).
	actions := map[string]interface{}{"operator": "one", "grants": []interface{}{
		map[string]interface{}{"type": "block"},
		map[string]interface{}{"type": "allow"},
	}}
	if got := dispatch(actions, PolicyEvalContext{}, nil); got.Decision != DecisionAllow {
		t.Fatalf("operator=one [block,allow] = %v, want allow (any-allow wins)", got.Decision)
	}
	// allow first, then block — must also allow.
	actions2 := map[string]interface{}{"operator": "one", "grants": []interface{}{
		map[string]interface{}{"type": "allow"},
		map[string]interface{}{"type": "block"},
	}}
	if got := dispatch(actions2, PolicyEvalContext{}, nil); got.Decision != DecisionAllow {
		t.Fatalf("operator=one [allow,block] = %v, want allow", got.Decision)
	}
	// all blocks, no allow → block.
	actions3 := map[string]interface{}{"operator": "one", "grants": []interface{}{
		map[string]interface{}{"type": "block"},
		map[string]interface{}{"type": "block"},
	}}
	if got := dispatch(actions3, PolicyEvalContext{}, nil); got.Decision != DecisionBlock {
		t.Fatalf("operator=one [block,block] = %v, want block", got.Decision)
	}
}
