package threat

import (
	"context"
	"log/slog"
	"testing"

	"setjoin.com/shared/toggle"
)

// c9-bug regression: FeatureConditionalAccess is a DEFAULT-OFF security toggle.
// With NO row seeded (drifted DB), Evaluate must treat the engine as DISABLED —
// the old IsEnabled read silently ENGAGED it (unknown key → true) while the
// sibling device gates read the same flag as OFF (split-brain).
func TestEvaluate_UnseededConditionalAccessToggleDisengages(t *testing.T) {
	flags := toggle.NewTestFlags(map[string]bool{}) // row absent
	pe := NewPolicyEngine(nil, flags, nil, nil, slog.Default(), false)

	res := pe.Evaluate(context.Background(), PolicyEvalContext{})
	if res.Decision != DecisionAllow {
		t.Fatalf("unseeded toggle must disengage the engine, got %v", res.Decision)
	}
	if res.Reason != "conditional access disabled" {
		t.Fatalf("expected disabled reason, got %q", res.Reason)
	}
}

// A seeded false row reads as disabled through the same path (row wins).
func TestEvaluate_SeededFalseDisengages(t *testing.T) {
	flags := toggle.NewTestFlags(map[string]bool{toggle.FeatureConditionalAccess: false})
	pe := NewPolicyEngine(nil, flags, nil, nil, slog.Default(), false)

	res := pe.Evaluate(context.Background(), PolicyEvalContext{})
	if res.Decision != DecisionAllow || res.Reason != "conditional access disabled" {
		t.Fatalf("seeded false row must disengage, got %v %q", res.Decision, res.Reason)
	}
}
