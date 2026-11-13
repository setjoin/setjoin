package threat

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/toggle"
)

// med-shard3-022 / D-SHARED-THREAT-005 (THREAT-IPRISK-UNWIRED-SCORING-INPUT).
// Feed/VPN signals are REQUEST-SCOPED decision inputs carried on the evaluation
// context. The former SetFeedHits mutator wrote to a scorer instance shared
// across requests — a data race whose misattribution leaked one request's
// signals into another identity's decision — and had zero production callers,
// so the score was structurally capped at medium and validated high/critical
// ip_reputation conditions could never fire.

// tieredPolicyStore is an in-memory PolicyStore whose geo tier is
// caller-controlled so tests can compose a specific score band without a DB.
type tieredPolicyStore struct {
	policies []PolicyRow
	tier     string
}

func (s *tieredPolicyStore) LoadAllPolicies(_ context.Context) ([]PolicyRow, error) {
	return s.policies, nil
}
func (s *tieredPolicyStore) LoadPolicies(_ context.Context, _ PolicyEvalContext) ([]PolicyRow, error) {
	return s.policies, nil
}
func (s *tieredPolicyStore) ResolveGeoTier(_ context.Context, _ string) (string, error) {
	return s.tier, nil
}
func (s *tieredPolicyStore) LoadBreakGlass(_ context.Context) ([]int64, error) { return nil, nil }
func (s *tieredPolicyStore) LoadNamedLocations(_ context.Context) ([]NamedLocation, error) {
	return nil, nil
}
func (s *tieredPolicyStore) LoadAuthStrengths(_ context.Context) ([]AuthStrength, error) {
	return nil, nil
}

// TestIPRiskInputsConcurrentIsolation is the concurrency/isolation lane (run
// under -race): simultaneous scorings with DIFFERENT feed/VPN inputs must each
// produce exactly their own expected composite. Any shared-state mutation (the
// old SetFeedHits pattern) trips the race detector; any misattribution breaks
// the per-request expectation.
func TestIPRiskInputsConcurrentIsolation(t *testing.T) {
	irs := NewIPRiskScorer(nil, acrTestLogger())

	const goroutines = 64
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			in := IPRiskInputs{FeedHits: i % 3, VPNScore: i % 21}
			want := feedScore(in.FeedHits) + geoTierToScore("low") + applyVPNScore(in.VPNScore)
			gotScore, gotBand := irs.ScoreWithTier(WithIPRiskInputs(context.Background(), in), "203.0.113.7", "low")
			if gotScore != want || gotBand != scoreToBand(want) {
				errs <- fmt.Errorf("request %d inputs %+v: got (%d,%q), want (%d,%q) — cross-request attribution leak",
					i, in, gotScore, gotBand, want, scoreToBand(want))
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestStepPolicyFeedHitIsolationConcurrent drives the real stepPolicy step (the
// production pre-auth entry into the engine) concurrently with hit-carrying and
// clean metas through ONE shared engine+scorer: every hit-carrying request must
// block, every clean request must proceed — no leakage in either direction.
func TestStepPolicyFeedHitIsolationConcurrent(t *testing.T) {
	store := &tieredPolicyStore{
		tier: "critical", // feed 40 + critical tier 40 = 80 → "high" with hits; 40 → "medium" without
		policies: []PolicyRow{{
			ID: 1, Name: "block-high-ip", Enabled: true, State: "on", ScopeType: "global",
			Conditions: map[string]interface{}{"ip_reputation": "high"},
			Actions:    map[string]interface{}{"action": "block"},
		}},
	}
	pe := NewPolicyEngine(store, nil, nil, NewIPRiskScorer(nil, acrTestLogger()), acrTestLogger(), false)
	ti := &ThreatInterceptor{policyEngine: pe, logger: acrTestLogger()}

	const goroutines = 32
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			meta := &ConnectionMeta{
				SourceIP: "198.51.100.10",
				Country:  "ZZ",
				Protocol: ProtocolHTTP,
				FeedHits: i % 2 * 2, // half the requests carry 2 hits, half carry 0
			}
			res, reason, _ := ti.stepPolicy(context.Background(), meta)
			if meta.FeedHits > 0 {
				if res != ActionReject || reason != "conditional_access_blocked" {
					errs <- fmt.Errorf("feed-hit request must block via the high ip_reputation condition; got %v %q", res, reason)
				}
			} else if res != ActionProceed {
				errs <- fmt.Errorf("clean request must proceed; got %v %q (hit-informed verdict leaked into the clean eval)", res, reason)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestIPRiskInputsFireCriticalBandThroughEvaluate pins the reachability fix at
// the engine boundary: request-scoped feed+VPN inputs raise the composite above
// the historical medium cap so a VALIDATED critical ip_reputation condition
// actually fires through PolicyEngine.Evaluate — and, without carried inputs,
// the same condition stays unreachable (the historical, silently-dead posture).
func TestIPRiskInputsFireCriticalBandThroughEvaluate(t *testing.T) {
	store := &tieredPolicyStore{
		tier: "critical",
		policies: []PolicyRow{{
			ID: 3, Name: "block-critical-ip", Enabled: true, State: "on", ScopeType: "global",
			Conditions: map[string]interface{}{"ip_reputation": "critical"},
			Actions:    map[string]interface{}{"action": "block"},
		}},
	}
	pe := NewPolicyEngine(store, nil, nil, NewIPRiskScorer(nil, acrTestLogger()), acrTestLogger(), false)
	ctx := context.Background()

	// 40 feed + 40 critical tier + 20 vpn = 100 → "critical" → validated condition fires.
	pectx := PolicyEvalContext{UserID: 11, SourceIP: "203.0.113.50", Country: "ZZ", Protocol: ProtocolHTTP}
	res := pe.Evaluate(WithIPRiskInputs(ctx, IPRiskInputs{FeedHits: 2, VPNScore: 20}), pectx)
	if res.Decision != DecisionBlock {
		t.Fatalf("feed+VPN inputs must raise ip_reputation to critical so the validated block condition fires; got %s (%s)", res.Decision, res.Reason)
	}

	// Control, distinct principal/IP (own decision-cache key): absent inputs give
	// 40 + 40 = 80 → "high" ≠ critical — the condition cannot fire without the
	// carried inputs. This is the historical silent-no-op made explicit.
	pectxClean := PolicyEvalContext{UserID: 12, SourceIP: "203.0.113.51", Country: "ZZ", Protocol: ProtocolHTTP}
	resClean := pe.Evaluate(WithIPRiskInputs(ctx, IPRiskInputs{}), pectxClean)
	if resClean.Decision != DecisionAllow {
		t.Fatalf("without carried inputs the critical condition must not fire; got %s (%s)", resClean.Decision, resClean.Reason)
	}
}

// TestEvaluatePostAuthFeedHitsEndToEnd is the end-to-end lane through a
// production request path: ThreatInterceptor.EvaluatePostAuth (the user-scoped
// post-auth pass on real logins) carries meta.FeedHits into scoring, the
// validated high-band condition fires, and the decision cache can neither serve
// a stale clean verdict to the hit-carrying request nor be poisoned by it.
func TestEvaluatePostAuthFeedHitsEndToEnd(t *testing.T) {
	store := &tieredPolicyStore{
		tier: "critical", // 40 + 40 = 80 → "high" with 2 feed hits; 40 → "medium" without
		policies: []PolicyRow{{
			ID: 9, Name: "step-up-block-high-ip", Enabled: true, State: "on", ScopeType: "global",
			Conditions: map[string]interface{}{"ip_reputation": "high"},
			Actions:    map[string]interface{}{"action": "block"},
		}},
	}
	pe := NewPolicyEngine(store, nil, nil, NewIPRiskScorer(nil, acrTestLogger()), acrTestLogger(), false)
	ti := &ThreatInterceptor{policyEngine: pe, logger: acrTestLogger()}
	ctx := context.Background()

	cleanMeta := &ConnectionMeta{
		UserID: 7, SourceIP: "198.51.100.77", Country: "ZZ", Protocol: ProtocolHTTP,
	}
	// 1. Clean eval → allow, and cached (normal fast path preserved).
	if res, reason := ti.EvaluatePostAuth(ctx, cleanMeta); res != ActionProceed {
		t.Fatalf("clean request must proceed; got %v %q", res, reason)
	}

	// 2. Feed hits arrive for the SAME principal/IP (own meta, as the caller
	// carries it): the uncacheable, hit-informed eval must BLOCK — the cached
	// clean allow must not be replayed.
	hitMeta := &ConnectionMeta{
		UserID: 7, SourceIP: "198.51.100.77", Country: "ZZ", Protocol: ProtocolHTTP,
		FeedHits: 2,
	}
	res, reason := ti.EvaluatePostAuth(ctx, hitMeta)
	if res != ActionReject || reason != "conditional_access_blocked" {
		t.Fatalf("feed hits must raise ip_reputation above medium so the validated high condition fires end-to-end; got %v %q", res, reason)
	}

	// 3. The hit-informed block verdict must not poison the cache: the next clean
	// eval for the same principal/IP proceeds again.
	if res, _ := ti.EvaluatePostAuth(ctx, cleanMeta); res != ActionProceed {
		t.Fatalf("hit-informed verdict leaked into later clean evals; got %v", res)
	}
}

// TestStepThreatFeedAcquiresHitsWithoutTerminating (DB-gated) drives the
// production feed step against the test database: the hit COUNT lands on
// meta.FeedHits as the request-scoped scoring input and the step ACQUIRES AND
// CONTINUES — the terminal reject lives in stepThreatFeedEnforce, AFTER the
// policy step, so hit-informed ip_reputation evaluation is reachable through
// the pipeline (wave89 item 1). Feed-hit counts stay capped at 2 (feedScore
// distinguishes only 0/1/2+), and the enforcement step preserves the hard
// reject one-for-one.
func TestStepThreatFeedAcquiresHitsWithoutTerminating(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set — skipping integration test (set to postgres://mail@127.0.0.1:5432/mailserver_test?sslmode=disable)")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	defer pool.Close()
	ctx := context.Background()

	const srcTag = "med-shard3-022-iprisk-test"
	cleanFixtures := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM threat_feed_blocks WHERE source = $1`, srcTag)
	}
	cleanFixtures()
	t.Cleanup(cleanFixtures)

	// Two overlapping rows cover 198.51.100.123; a third wide row keeps the cap
	// observable (all three cover the IP; the count must saturate at 2).
	for _, cidr := range []string{"198.51.100.123/32", "198.51.100.0/24", "198.51.0.0/16"} {
		if _, err := pool.Exec(ctx,
			`INSERT INTO threat_feed_blocks (cidr, source) VALUES ($1, $2)
			 ON CONFLICT (cidr) DO NOTHING`, cidr, srcTag); err != nil {
			t.Fatalf("seed threat_feed_blocks %s: %v", cidr, err)
		}
	}

	ti := &ThreatInterceptor{
		pool:    pool,
		toggles: toggle.NewStatic(map[string]bool{toggle.FeatureThreatFeed: true}),
		logger:  acrTestLogger(),
	}

	hitMeta := &ConnectionMeta{SourceIP: "198.51.100.123"}
	if res, reason, _ := ti.stepThreatFeed(ctx, hitMeta); res != ActionProceed || reason != "" {
		t.Fatalf("feed step must acquire-and-continue (reject moved after policy evaluation); got %v %q", res, reason)
	} else if hitMeta.FeedHits != 2 {
		t.Fatalf("feed hits must be counted onto meta.FeedHits capped at 2; got %d", hitMeta.FeedHits)
	}
	if res, reason, _ := ti.stepThreatFeedEnforce(ctx, hitMeta); res != ActionReject || reason != "threat_blocked" {
		t.Fatalf("feed-listed IP must still be hard-rejected by the enforcement step; got %v %q", res, reason)
	}

	cleanMeta := &ConnectionMeta{SourceIP: "192.0.2.177"}
	if res, _, _ := ti.stepThreatFeed(ctx, cleanMeta); res != ActionProceed {
		t.Fatalf("non-listed IP must proceed; got %v", res)
	}
	if cleanMeta.FeedHits != 0 {
		t.Fatalf("non-listed IP must carry zero feed hits; got %d", cleanMeta.FeedHits)
	}
	if res, reason, _ := ti.stepThreatFeedEnforce(ctx, cleanMeta); res != ActionProceed || reason != "" {
		t.Fatalf("clean IP must fall through the enforcement step; got %v %q", res, reason)
	}
}
