package threat

import (
	"context"
	"testing"

	"setjoin.com/shared/toggle"
)

// med-shard3-022 wave89 HOLD item 1 — DB-free lanes pinning the pipeline
// contract that makes feed-informed policy evaluation reachable: the feed
// enforcement step runs AFTER the conditional-access policy step, and the
// enforcement step alone reproduces the former step-1 terminal exactly.

func feedPathToggles() *toggle.FeatureFlags {
	// Explicit for every pipeline toggle: NewStatic leaves unlisted keys on
	// their registry defaults (spray/threat-feed are default-on), and these
	// lanes isolate the feed steps.
	return toggle.NewStatic(map[string]bool{
		toggle.FeatureThreatFeed:  true,
		toggle.FeatureGeoBlock:    false,
		toggle.FeatureSprayDetect: false,
		toggle.FeatureCaptcha:     false,
		toggle.FeatureTarpit:      false,
		toggle.FeatureRateLimit:   false,
	})
}

// TestThreatFeedEnforceStepContract pins the enforcement step's behavior: the
// terminal is byte-identical to the former inline stepThreatFeed reject, and
// the step self-gates on FeatureThreatFeed.
func TestThreatFeedEnforceStepContract(t *testing.T) {
	on := &ThreatInterceptor{toggles: feedPathToggles(), logger: acrTestLogger()}
	hit := &ConnectionMeta{FeedHits: 2}
	if res, reason, delay := on.stepThreatFeedEnforce(context.Background(), hit); res != ActionReject || reason != "threat_blocked" || delay != 0 {
		t.Fatalf("positive hit count must terminate with the preserved feed terminal; got %v %q %v", res, reason, delay)
	}
	clean := &ConnectionMeta{FeedHits: 0}
	if res, reason, _ := on.stepThreatFeedEnforce(context.Background(), clean); res != ActionProceed || reason != "" {
		t.Fatalf("zero hits must fall through; got %v %q", res, reason)
	}

	off := &ThreatInterceptor{toggles: toggle.NewStatic(map[string]bool{toggle.FeatureThreatFeed: false}), logger: acrTestLogger()}
	if res, _, _ := off.stepThreatFeedEnforce(context.Background(), hit); res != ActionProceed {
		t.Fatalf("enforcement must self-gate on FeatureThreatFeed; got %v", res)
	}
}

// TestPipelinePlacesFeedEnforcementAfterPolicy pins the ORDER contract the
// reachability fix rests on: threat_feed < policy < threat_feed_enforce, and
// threat_feed_enforce is the final step — so policy evaluation sees the
// acquired hits, and a positive hit count can never fall through the pipeline
// even when no policy matches.
func TestPipelinePlacesFeedEnforcementAfterPolicy(t *testing.T) {
	steps := (&ThreatInterceptor{}).buildPipeline()
	names := make([]string, 0, len(steps))
	idx := map[string]int{}
	for i, s := range steps {
		names = append(names, s.name)
		idx[s.name] = i
	}
	for _, want := range []string{"threat_feed", "policy", "threat_feed_enforce"} {
		if _, ok := idx[want]; !ok {
			t.Fatalf("pipeline step %q missing; steps = %v", want, names)
		}
	}
	if idx["threat_feed"] >= idx["policy"] {
		t.Fatalf("feed acquisition must run before policy evaluation; steps = %v", names)
	}
	if idx["policy"] >= idx["threat_feed_enforce"] {
		t.Fatalf("feed enforcement must run AFTER policy evaluation (reachability contract); steps = %v", names)
	}
	if idx["threat_feed_enforce"] != len(steps)-1 {
		t.Fatalf("feed enforcement must be the final step so a positive count can never fall through; steps = %v", names)
	}
}

// TestRunPipelinePolicySeesHitsBeforeFeedEnforcement drives the real step
// methods through runPipeline: a request carrying acquired hits reaches the
// policy step (validated high condition fires) BEFORE the enforcement step can
// terminate it; when no condition matches, the enforcement step emits the
// preserved threat_blocked terminal.
func TestRunPipelinePolicySeesHitsBeforeFeedEnforcement(t *testing.T) {
	mkSteps := func(ti *ThreatInterceptor) []step {
		return []step{
			{name: "policy", run: ti.stepPolicy},
			{name: "threat_feed_enforce", run: ti.stepThreatFeedEnforce},
		}
	}

	// Engine whose only policy blocks the "high" band: hits acquired in-pipeline
	// (meta.FeedHits = 2) + critical geo tier ⇒ 40 + 40 = 80 → "high" → fires.
	highBlock := &tieredPolicyStore{
		tier: "critical",
		policies: []PolicyRow{{
			ID: 1, Name: "block-high-ip", Enabled: true, State: "on", ScopeType: "global",
			Conditions: map[string]interface{}{"ip_reputation": "high"},
			Actions:    map[string]interface{}{"action": "block"},
		}},
	}
	tiHigh := &ThreatInterceptor{
		toggles:      feedPathToggles(),
		logger:       acrTestLogger(),
		policyEngine: NewPolicyEngine(highBlock, nil, nil, NewIPRiskScorer(nil, acrTestLogger()), acrTestLogger(), false),
	}
	meta := &ConnectionMeta{SourceIP: "198.51.100.10", Country: "ZZ", Protocol: ProtocolHTTP, FeedHits: 2}
	if res, reason, _ := runPipeline(mkSteps(tiHigh), context.Background(), meta); res != ActionReject || reason != "conditional_access_blocked" {
		t.Fatalf("policy step must evaluate with the acquired hits before enforcement; got %v %q", res, reason)
	}

	// Engine whose only policy demands "critical": the band stops at "high", the
	// policy is skipped, and the pipeline terminates on the preserved feed
	// reject instead of proceeding.
	criticalOnly := &tieredPolicyStore{
		tier: "critical",
		policies: []PolicyRow{{
			ID: 2, Name: "block-critical-ip", Enabled: true, State: "on", ScopeType: "global",
			Conditions: map[string]interface{}{"ip_reputation": "critical"},
			Actions:    map[string]interface{}{"action": "block"},
		}},
	}
	tiCrit := &ThreatInterceptor{
		toggles:      feedPathToggles(),
		logger:       acrTestLogger(),
		policyEngine: NewPolicyEngine(criticalOnly, nil, nil, NewIPRiskScorer(nil, acrTestLogger()), acrTestLogger(), false),
	}
	meta2 := &ConnectionMeta{SourceIP: "198.51.100.11", Country: "ZZ", Protocol: ProtocolHTTP, FeedHits: 2}
	if res, reason, _ := runPipeline(mkSteps(tiCrit), context.Background(), meta2); res != ActionReject || reason != "threat_blocked" {
		t.Fatalf("feed enforcement must terminate the pipeline when no policy fires; got %v %q", res, reason)
	}
}
