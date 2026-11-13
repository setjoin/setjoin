package threat

import "testing"

func TestDispatchLimitedWeb(t *testing.T) {
	row := PolicyRow{ID: 5, Name: "lw"}
	res := dispatchAction(map[string]interface{}{"action": "limited_web"}, row, PolicyEvalContext{}, nil)
	if res.Decision != DecisionAllow {
		t.Fatalf("limited_web should allow, got %v", res.Decision)
	}
	if !res.LimitedWeb {
		t.Fatalf("limited_web should set LimitedWeb=true")
	}
}

// TestDispatchLimitedWebOneOperator guards the op="one" early-return path.
// A {"operator":"one","grants":[{"type":"limited_web"}]} must not silently upgrade
// to full-allow — the early-return in the "one" loop must set LimitedWeb before returning.
func TestDispatchLimitedWebOneOperator(t *testing.T) {
	row := PolicyRow{ID: 6, Name: "lw-one"}
	actions := map[string]interface{}{
		"operator": "one",
		"grants":   []interface{}{map[string]interface{}{"type": "limited_web"}},
	}
	res := dispatchAction(actions, row, PolicyEvalContext{}, nil)
	if res.Decision != DecisionAllow {
		t.Fatalf("limited_web (one) should allow, got %v", res.Decision)
	}
	if !res.LimitedWeb {
		t.Fatalf("limited_web (op=one) early-return must set LimitedWeb=true")
	}
}

func TestReferencedConditions(t *testing.T) {
	// State is the DB column; Enabled is never scanned from DB. Use State here.
	policies := []PolicyRow{
		{ID: 1, State: "on", Conditions: map[string]interface{}{"device_trust": "managed"}},
		{ID: 2, State: "report_only", Conditions: map[string]interface{}{"auth_method": "password"}},
		{ID: 3, State: "off", Conditions: map[string]interface{}{"geo_risk_tier": "high"}},
	}
	pe := &PolicyEngine{}
	ref := pe.ReferencedConditions(policies)
	if !ref["device_trust"] {
		t.Fatalf("device_trust should be referenced (State=on)")
	}
	if !ref["auth_method"] {
		t.Fatalf("auth_method should be referenced (State=report_only)")
	}
	if ref["geo_risk_tier"] {
		t.Fatalf("disabled policy's geo_risk_tier must NOT be referenced (State=off)")
	}
}
