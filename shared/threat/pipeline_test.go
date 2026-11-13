package threat

import (
	"context"
	"testing"
	"time"

	"setjoin.com/shared/toggle"
)

// TestRunPipeline_ShortCircuitsAndPreservesOrder drives the runner over a []step
// of FAKE steps (no DB, no middleware) and asserts the two sequencing
// invariants the declarative pipeline depends on: (1) steps run in list order,
// and (2) the first step that returns a non-ActionProceed result short-circuits
// the loop — no later step runs.
func TestRunPipeline_ShortCircuitsAndPreservesOrder(t *testing.T) {
	var order []string
	mkProceed := func(name string) step {
		return step{name: name, run: func(_ context.Context, _ *ConnectionMeta) (InterceptorResult, string, time.Duration) {
			order = append(order, name)
			return ActionProceed, "", 0
		}}
	}
	mkTerminal := func(name string, res InterceptorResult, reason string, delay time.Duration) step {
		return step{name: name, run: func(_ context.Context, _ *ConnectionMeta) (InterceptorResult, string, time.Duration) {
			order = append(order, name)
			return res, reason, delay
		}}
	}

	t.Run("all proceed -> ActionProceed, every step ran in order", func(t *testing.T) {
		order = nil
		steps := []step{mkProceed("a"), mkProceed("b"), mkProceed("c")}
		res, reason, delay := runPipeline(steps, context.Background(), &ConnectionMeta{})
		if res != ActionProceed || reason != "" || delay != 0 {
			t.Fatalf("all-proceed must return (ActionProceed, \"\", 0); got %v %q %v", res, reason, delay)
		}
		if got := order; len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
			t.Fatalf("steps must run in list order; got %v", got)
		}
	})

	t.Run("first terminal short-circuits, later steps do not run", func(t *testing.T) {
		order = nil
		steps := []step{
			mkProceed("a"),
			mkTerminal("b", ActionReject, "blocked_at_b", 7*time.Second),
			mkProceed("c"), // must NOT run
		}
		res, reason, delay := runPipeline(steps, context.Background(), &ConnectionMeta{})
		if res != ActionReject || reason != "blocked_at_b" || delay != 7*time.Second {
			t.Fatalf("must return the first terminal's decision; got %v %q %v", res, reason, delay)
		}
		if got := order; len(got) != 2 || got[0] != "a" || got[1] != "b" {
			t.Fatalf("runner must stop after the first terminal; ran %v", got)
		}
	})

	t.Run("terminal at index 0 stops the whole pipeline", func(t *testing.T) {
		order = nil
		steps := []step{
			mkTerminal("first", ActionRateLimited, "rate_limited", 0),
			mkProceed("never"),
		}
		res, reason, _ := runPipeline(steps, context.Background(), &ConnectionMeta{})
		if res != ActionRateLimited || reason != "rate_limited" {
			t.Fatalf("index-0 terminal must win; got %v %q", res, reason)
		}
		if len(order) != 1 || order[0] != "first" {
			t.Fatalf("only the first step may run; ran %v", order)
		}
	})

	t.Run("empty pipeline proceeds", func(t *testing.T) {
		res, reason, delay := runPipeline(nil, context.Background(), &ConnectionMeta{})
		if res != ActionProceed || reason != "" || delay != 0 {
			t.Fatalf("empty pipeline must proceed; got %v %q %v", res, reason, delay)
		}
	})
}

// TestStepGeoBlock_InIsolation exercises one real step against a fake/empty
// ConnectionMeta with no DB: a blocked country rejects with "geo_blocked", a
// non-blocked country (or an empty country, or the feature off) proceeds.
func TestStepGeoBlock_InIsolation(t *testing.T) {
	mk := func(geoEnabled bool, blocked ...string) *ThreatInterceptor {
		bc := make(map[string]bool, len(blocked))
		for _, cc := range blocked {
			bc[cc] = true
		}
		return &ThreatInterceptor{
			toggles:        toggle.NewStatic(map[string]bool{toggle.FeatureGeoBlock: geoEnabled}),
			blockCountries: bc,
		}
	}

	t.Run("blocked country -> reject geo_blocked", func(t *testing.T) {
		ti := mk(true, "KP", "RU")
		res, reason, delay := ti.stepGeoBlock(context.Background(), &ConnectionMeta{Country: "KP"})
		if res != ActionReject || reason != "geo_blocked" || delay != 0 {
			t.Fatalf("blocked country must reject geo_blocked; got %v %q %v", res, reason, delay)
		}
	})

	t.Run("non-blocked country -> proceed", func(t *testing.T) {
		ti := mk(true, "KP")
		res, reason, _ := ti.stepGeoBlock(context.Background(), &ConnectionMeta{Country: "US"})
		if res != ActionProceed || reason != "" {
			t.Fatalf("non-blocked country must proceed; got %v %q", res, reason)
		}
	})

	t.Run("empty country -> proceed", func(t *testing.T) {
		ti := mk(true, "KP")
		res, _, _ := ti.stepGeoBlock(context.Background(), &ConnectionMeta{Country: ""})
		if res != ActionProceed {
			t.Fatalf("empty country must proceed; got %v", res)
		}
	})

	t.Run("feature disabled -> proceed even for a blocked country (self-gate)", func(t *testing.T) {
		ti := mk(false, "KP")
		res, _, _ := ti.stepGeoBlock(context.Background(), &ConnectionMeta{Country: "KP"})
		if res != ActionProceed {
			t.Fatalf("geo-block off must proceed; got %v", res)
		}
	})
}
