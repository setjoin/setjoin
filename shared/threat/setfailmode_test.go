package threat

import (
	"context"
	"testing"
)

// TestSetFailMode_OpenWhenCAFailModeOpen proves the wiring seam: after
// SetFailMode("open") the engine is in open posture, and after SetFailMode with
// any other value (or "closed") it stays / returns to closed.
func TestSetFailMode_OpenWhenCAFailModeOpen(t *testing.T) {
	pe := NewPolicyEngine(errPolicyStore{}, nil, nil, nil, acrTestLogger(), false)
	// default must be closed
	if pe.failMode != "closed" {
		t.Fatalf("default failMode: want closed, got %q", pe.failMode)
	}

	// simulate startup reading ca_fail_mode = "open" from system_config
	pe.SetFailMode("open")
	if pe.failMode != "open" {
		t.Fatalf("SetFailMode(\"open\"): want open, got %q", pe.failMode)
	}
}

func TestSetFailMode_ClosedWhenCAFailModeClosedOrAbsent(t *testing.T) {
	pe := NewPolicyEngine(errPolicyStore{}, nil, nil, nil, acrTestLogger(), false)

	// explicit "closed"
	pe.SetFailMode("closed")
	if pe.failMode != "closed" {
		t.Fatalf("SetFailMode(\"closed\"): want closed, got %q", pe.failMode)
	}

	// unrecognised value must default to closed for safety
	pe.SetFailMode("unknown-value")
	if pe.failMode != "closed" {
		t.Fatalf("SetFailMode(unrecognised): want closed (safe default), got %q", pe.failMode)
	}
}

// TestSetFailMode_OpenEngineAllowsOnLoadError ties the posture to the decision:
// an engine set to "open" via SetFailMode must allow on a policy-store failure
// (matches TestPolicyEngine_FailOpen_AllowsOnLoadError but via the setter path).
func TestSetFailMode_OpenEngineAllowsOnLoadError(t *testing.T) {
	pe := NewPolicyEngine(errPolicyStore{}, nil, nil, nil, acrTestLogger(), false)
	pe.SetFailMode("open") // simulates ca_fail_mode='open' startup read

	res := pe.Evaluate(context.Background(), PolicyEvalContext{UserID: 42})
	if res.Decision != DecisionAllow {
		t.Fatalf("open posture via SetFailMode: want DecisionAllow on load error, got %v reason=%q",
			res.Decision, res.Reason)
	}
}

// TestSetFailMode_ClosedEngineBlocksOnLoadError mirrors the inverse: SetFailMode
// to "closed" (the same as the default) still blocks on a load error.
func TestSetFailMode_ClosedEngineBlocksOnLoadError(t *testing.T) {
	pe := NewPolicyEngine(errPolicyStore{}, nil, nil, nil, acrTestLogger(), false)
	pe.SetFailMode("closed")

	res := pe.Evaluate(context.Background(), PolicyEvalContext{UserID: 42})
	if res.Decision != DecisionBlock {
		t.Fatalf("closed posture via SetFailMode: want DecisionBlock on load error, got %v reason=%q",
			res.Decision, res.Reason)
	}
}
