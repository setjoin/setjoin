package threat

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"setjoin.com/shared/toggle"
)

func slogDiscard() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func recTestEngine(rows []PolicyRow) *PolicyEngine {
	pe := NewPolicyEngine(nil, toggle.NewStatic(map[string]bool{toggle.FeatureConditionalAccess: true}), nil, nil, slogDiscard(), false)
	pe.cachedPolicies = rows
	pe.cachedAt = time.Now()
	return pe
}

func TestEvaluate_RecordsEvaluatedOutcomes(t *testing.T) {
	rows := []PolicyRow{
		{ID: 7, Name: "geo step-up", State: "on", ScopeType: "global",
			Conditions: map[string]interface{}{"client_type": "imap"}, // won't match web ctx
			Actions:    map[string]interface{}{"action": "step_up"}},
		{ID: 12, Name: "block RO", State: "report_only", ScopeType: "global",
			Conditions: map[string]interface{}{},
			Actions:    map[string]interface{}{"action": "block"}},
	}
	pe := recTestEngine(rows)
	res := pe.Evaluate(context.Background(), PolicyEvalContext{UserID: 4711, ClientType: "web", RequestTime: time.Now()})

	if res.Decision != DecisionAllow {
		t.Fatalf("report_only must never enforce: got %v", res.Decision)
	}
	if len(res.Evaluated) != 2 {
		t.Fatalf("want 2 evaluated outcomes, got %d", len(res.Evaluated))
	}
	if res.Evaluated[0].Outcome != "skipped" {
		t.Errorf("policy 7 should be skipped (condition miss), got %q", res.Evaluated[0].Outcome)
	}
	if res.Evaluated[1].Outcome != "would_block" {
		t.Errorf("policy 12 (report_only block) should be would_block, got %q", res.Evaluated[1].Outcome)
	}
	if res.CorrelationID != "" {
		t.Errorf("allow/report_only flow must mint no correlation id, got %q", res.CorrelationID)
	}
}

func TestEvaluate_EnforcingBlockMintsCorrelationID(t *testing.T) {
	rows := []PolicyRow{{ID: 5, Name: "hard block", State: "on", ScopeType: "global",
		Conditions: map[string]interface{}{}, Actions: map[string]interface{}{"action": "block"}}}
	pe := recTestEngine(rows)
	res := pe.Evaluate(context.Background(), PolicyEvalContext{UserID: 4711, RequestTime: time.Now()})
	if res.Decision != DecisionBlock {
		t.Fatalf("want block, got %v", res.Decision)
	}
	if !strings.HasPrefix(res.CorrelationID, "CA-") {
		t.Errorf("enforcing block must mint a CA- correlation id, got %q", res.CorrelationID)
	}
	if res.Evaluated[0].Outcome != "applied" {
		t.Errorf("enforcing match outcome should be applied, got %q", res.Evaluated[0].Outcome)
	}
}

func TestEvaluate_CacheHitMintsFreshCorrelationID(t *testing.T) {
	rows := []PolicyRow{{ID: 5, Name: "hard block", State: "on", ScopeType: "global",
		Conditions: map[string]interface{}{}, Actions: map[string]interface{}{"action": "block"}}}
	pe := recTestEngine(rows)
	pctx := PolicyEvalContext{UserID: 4711, RequestTime: time.Now()}
	r1 := pe.Evaluate(context.Background(), pctx)
	// First eval must have cached the decision, so the second eval is a genuine hit.
	if len(pe.decisionCache) != 1 {
		t.Fatalf("decision should be cached after first eval, got %d entries", len(pe.decisionCache))
	}
	r2 := pe.Evaluate(context.Background(), pctx) // decision-cache HIT
	if r1.Decision != DecisionBlock || r2.Decision != DecisionBlock {
		t.Fatalf("want block both, got %v %v", r1.Decision, r2.Decision)
	}
	if r1.CorrelationID == "" || r2.CorrelationID == "" {
		t.Fatalf("both events must mint a correlation id, got %q / %q", r1.CorrelationID, r2.CorrelationID)
	}
	if r1.CorrelationID == r2.CorrelationID {
		t.Errorf("correlation id must be per-event; the cache hit replayed it: %q", r1.CorrelationID)
	}
}

func TestBuildSignInRow_CarriesOutcomeAndCorrelation(t *testing.T) {
	res := PolicyResult{
		Decision:      DecisionAllow,
		CorrelationID: "",
		Evaluated:     []policyOutcome{{PolicyID: 12, Name: "block RO", Outcome: "would_block"}},
	}
	// report-only would_block rides into would_decision via the matched policy trace.
	row := buildSignInRow(PolicyEvalContext{UserID: 4711, SourceIP: "203.0.113.9", Protocol: "http", ClientType: "web", Country: "CN"}, res)
	if row["user_id"] != int64(4711) {
		t.Errorf("user_id not carried: %v", row["user_id"])
	}
	if row["decision"] != "allow" {
		t.Errorf("decision not carried: %v", row["decision"])
	}
	ev, ok := row["evaluated"].([]policyOutcome)
	if !ok || len(ev) != 1 || ev[0].Outcome != "would_block" {
		t.Errorf("evaluated trace not carried: %v", row["evaluated"])
	}
}

func TestBuildSignInRow_BlockCarriesCorrelationAndWouldDecision(t *testing.T) {
	res := PolicyResult{Decision: DecisionBlock, CorrelationID: "CA-abc123"}
	row := buildSignInRow(PolicyEvalContext{UserID: 1, Protocol: "http"}, res)
	if row["decision"] != "block" || row["correlation_id"] != "CA-abc123" {
		t.Errorf("block row must carry decision+correlation_id: %v", row)
	}
}

// TestBuildSignInRow_EnforcedBlockNotReportOnly — I1 regression: an enforced
// block (PolicyID != 0) whose trace also contains a would_ entry must NOT be
// stamped report_only=true. Before the fix, the would_ loop ran unconditionally
// and overwrote report_only on enforced rows whose earlier evaluated entry had
// a would_ prefix.
func TestBuildSignInRow_EnforcedBlockNotReportOnly(t *testing.T) {
	res := PolicyResult{
		Decision:      DecisionBlock,
		PolicyID:      5,
		CorrelationID: "CA-enforce",
		Evaluated: []policyOutcome{
			{PolicyID: 3, Name: "geo RO", Outcome: "would_block"}, // earlier report-only hit
			{PolicyID: 5, Name: "hard block", Outcome: "applied"}, // enforcing match
		},
	}
	row := buildSignInRow(PolicyEvalContext{UserID: 1, Protocol: "http"}, res)
	if row["report_only"] != false {
		t.Errorf("I1: enforced block with a would_ trace entry must have report_only=false, got %v", row["report_only"])
	}
	if _, ok := row["would_decision"]; ok {
		t.Errorf("I1: enforced block must not set would_decision, got %v", row["would_decision"])
	}
}
