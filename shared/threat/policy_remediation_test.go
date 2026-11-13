package threat

import "testing"

func TestDispatchRequireTerms(t *testing.T) {
	row := PolicyRow{ID: 7, Name: "aup", Actions: map[string]interface{}{
		"action": "require_terms", "tou_id": float64(70001)}}
	res := dispatchAction(row.Actions, row, PolicyEvalContext{}, nil)
	if res.Decision != DecisionBlock {
		t.Fatalf("require_terms must deny (block) so the gateway stops the request, got %v", res.Decision)
	}
	if res.Remediation != "terms" {
		t.Fatalf("require_terms must set Remediation=terms, got %q", res.Remediation)
	}
	if res.RemediationTermsID != 70001 {
		t.Fatalf("require_terms must carry the tou_id, got %d", res.RemediationTermsID)
	}
}

// TestDispatchRequireRiskRemediationElevated: a user with elevated risk (high/medium)
// must get a Block+remediation so the runtime gate denies and points them to re-auth.
func TestDispatchRequireRiskRemediationElevated(t *testing.T) {
	row := PolicyRow{ID: 8, Name: "risk", Actions: map[string]interface{}{
		"action": "require_risk_remediation"}}
	for _, level := range []string{"high", "medium"} {
		res := dispatchAction(row.Actions, row, PolicyEvalContext{RiskLevel: level}, nil)
		if res.Decision != DecisionBlock {
			t.Fatalf("require_risk_remediation with level=%q must deny, got %v", level, res.Decision)
		}
		if res.Remediation != "risk" {
			t.Fatalf("require_risk_remediation with level=%q must set Remediation=risk, got %q", level, res.Remediation)
		}
	}
}

// TestDispatchRequireRiskRemediationLow: a user with low/none/empty risk must be
// ALLOWED — a global-scope require_risk_remediation policy must not mass-lockout
// users who have no elevated risk signal.
func TestDispatchRequireRiskRemediationLow(t *testing.T) {
	row := PolicyRow{ID: 8, Name: "risk", Actions: map[string]interface{}{
		"action": "require_risk_remediation"}}
	for _, level := range []string{"", "low", "none"} {
		res := dispatchAction(row.Actions, row, PolicyEvalContext{RiskLevel: level}, nil)
		if res.Decision != DecisionAllow {
			t.Fatalf("require_risk_remediation with level=%q must allow (not elevated), got %v", level, res.Decision)
		}
	}
}

// TestValidateGrantsRejectsRequireTermsInGrantsArray: require_terms and
// require_risk_remediation are top-level verbs only — they must be rejected
// when nested in a grants array so a policy author gets an authoring-time error.
func TestValidateGrantsRejectsRemediationVerbsInGrantsArray(t *testing.T) {
	cond := map[string]interface{}{}
	for _, verb := range []string{"require_terms", "require_risk_remediation"} {
		for shape, grant := range map[string]map[string]interface{}{
			"canonical":     {"type": verb},
			"schema-v1":     {"action": verb},
			"matching-dual": {"type": verb, "action": verb},
		} {
			bad := map[string]interface{}{"grants": []interface{}{grant}}
			if err := ValidatePolicyDocument(cond, bad); err == nil {
				t.Errorf("%s grants array with remediation verb %q must be rejected, got nil error", shape, verb)
			}
		}
	}
}
