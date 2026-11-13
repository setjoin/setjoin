package threat

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/toggle"
)

// med-shard3-022 wave89 HOLD item 1 (P2): acquisition-through-request-path
// coverage. The feed hit count must be ACQUIRED by the production pipeline
// (stepThreatFeed's threat_feed_blocks query) and CARRIED into
// conditional-access evaluation (stepPolicy → WithIPRiskInputs → ip_reputation
// scoring) so a validated high-band condition is genuinely reachable through a
// production request path — Intercept, the same entry IMAP/SMTP callers use —
// while the hard feed reject is preserved for every feed-listed request.
//
// These lanes run the REAL assembly: pgxPolicyStore + PolicyEngine +
// IPRiskScorer + the full built pipeline, against the test database.

const feedPathSrcTag = "med-shard3-022-feedpath-test"

// newFeedPathInterceptor builds the production ThreatInterceptor assembly on a
// real pool with only FeatureThreatFeed enabled (other steps self-gate off) and
// a real policy engine; the test seeds its own threat_feed_blocks rows, geo
// tier, and CA policy, and cleans all of them up.
func newFeedPathInterceptor(t *testing.T) (*pgxpool.Pool, *ThreatInterceptor) {
	t.Helper()
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set — skipping integration test (set to postgres://mail@127.0.0.1:5432/mailserver_test?sslmode=disable)")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	// Threat-feed rows (source-tagged cleanup, re-run safe).
	cleanFeed := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM threat_feed_blocks WHERE source = $1`, feedPathSrcTag)
	}
	cleanFeed()
	t.Cleanup(cleanFeed)
	for _, cidr := range []string{"198.51.100.123/32", "198.51.100.0/24"} {
		if _, err := pool.Exec(ctx,
			`INSERT INTO threat_feed_blocks (cidr, source) VALUES ($1, $2)
			 ON CONFLICT (cidr) DO NOTHING`, cidr, feedPathSrcTag); err != nil {
			t.Fatalf("seed threat_feed_blocks %s: %v", cidr, err)
		}
	}

	// Geo tier for the evaluation country: 'high' (30). Feed 2 hits (40) +
	// high tier (30) = 70 → "high" band WITH hits; 30 → "low" without.
	// Preserve any pre-existing row for 'ZZ'.
	var priorTier string
	hadPrior := false
	if err := pool.QueryRow(ctx,
		`SELECT tier FROM geo_country_tiers WHERE country_code = 'ZZ'`).Scan(&priorTier); err == nil {
		hadPrior = true
	}
	t.Cleanup(func() {
		if hadPrior {
			_, _ = pool.Exec(ctx, `UPDATE geo_country_tiers SET tier = $1 WHERE country_code = 'ZZ'`, priorTier)
		} else {
			_, _ = pool.Exec(ctx, `DELETE FROM geo_country_tiers WHERE country_code = 'ZZ'`)
		}
	})
	if _, err := pool.Exec(ctx,
		`INSERT INTO geo_country_tiers (country_code, tier, reason) VALUES ('ZZ', 'high', 'med-shard3-022 feed-path test')
		 ON CONFLICT (country_code) DO UPDATE SET tier = EXCLUDED.tier`); err != nil {
		t.Fatalf("seed geo_country_tiers ZZ: %v", err)
	}

	logger := acrTestLogger()
	engine := NewPolicyEngine(NewPolicyStore(pool, logger), nil, nil, NewIPRiskScorer(pool, logger), logger, false)
	// Explicit for every toggle: unlisted keys take registry defaults (spray is
	// default-on) and these lanes isolate acquisition → policy → enforcement.
	toggles := toggle.NewStatic(map[string]bool{
		toggle.FeatureThreatFeed:  true,
		toggle.FeatureGeoBlock:    false,
		toggle.FeatureSprayDetect: false,
		toggle.FeatureCaptcha:     false,
		toggle.FeatureTarpit:      false,
		toggle.FeatureRateLimit:   false,
	})
	ti := New(pool, nil, toggles, nil /* geoip: tests preset meta.Country */, ThreatConfig{}, logger, engine)
	return pool, ti
}

// seedFeedPathPolicy inserts (re-run safe) one enforcing policy and registers
// its cleanup; conditions/actions come from the subtest.
func seedFeedPathPolicy(t *testing.T, pool *pgxpool.Pool, name string, priority int, conditions string) {
	t.Helper()
	ctx := context.Background()
	cleanPolicy := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM conditional_access_policies WHERE name = $1`, name)
	}
	cleanPolicy()
	t.Cleanup(cleanPolicy)
	if _, err := pool.Exec(ctx,
		`INSERT INTO conditional_access_policies
		     (priority, name, scope_type, scope_target, state, enabled, conditions, actions)
		 VALUES ($1, $2, 'global', '', 'on', true, $3::jsonb, '{"action":"block"}'::jsonb)`,
		priority, name, conditions); err != nil {
		t.Fatalf("seed policy %s: %v", name, err)
	}
}

// TestFeedHitsReachPolicyThroughRequestPath is the reachability lane the wave89
// review demanded: a feed-listed request acquires its hit count through the
// production pipeline and the validated high ip_reputation condition FIRES —
// with the decision cache neither serving a stale clean verdict nor being
// poisoned by the hit-informed one.
func TestFeedHitsReachPolicyThroughRequestPath(t *testing.T) {
	pool, ti := newFeedPathInterceptor(t)
	seedFeedPathPolicy(t, pool, "med-shard3-022-feedpath-high", 987041, `{"ip_reputation":"high"}`)
	ctx := context.Background()

	// 1. Feed-listed request: hits acquired in-pipeline raise the band to
	// "high" (40 feed + 30 high tier), so the enforcing block policy fires —
	// the policy step runs BEFORE the preserved feed enforcement, so the reason
	// is the policy's, not the feed's.
	listed := &ConnectionMeta{SourceIP: "198.51.100.123", Country: "ZZ", Protocol: ProtocolHTTP, Username: "feedpath@example.com"}
	if res, reason, _ := ti.Intercept(ctx, listed); res != ActionReject || reason != "conditional_access_blocked" {
		t.Fatalf("feed-informed request must reach policy evaluation and fire the validated high ip_reputation block; got %v %q", res, reason)
	}

	// 2. Clean request, same policy: no hits → "low" band → condition cannot
	// fire → request proceeds (the historical medium-cap failure mode is gone,
	// and the clean path is untouched).
	clean := &ConnectionMeta{SourceIP: "192.0.2.188", Country: "ZZ", Protocol: ProtocolHTTP, Username: "feedpath@example.com"}
	if res, reason, _ := ti.Intercept(ctx, clean); res != ActionProceed || reason != "" {
		t.Fatalf("clean request must proceed; got %v %q", res, reason)
	}

	// 3. Repeat of (1) after the clean eval: the cached clean verdict must not
	// be replayed for the hit-carrying request (distinct band ⇒ distinct
	// decision-cache entry) and the hit-informed verdict must not poison (2).
	listed2 := &ConnectionMeta{SourceIP: "198.51.100.123", Country: "ZZ", Protocol: ProtocolHTTP, Username: "feedpath@example.com"}
	if res, reason, _ := ti.Intercept(ctx, listed2); res != ActionReject || reason != "conditional_access_blocked" {
		t.Fatalf("repeat feed-informed request must block again (no stale clean replay); got %v %q", res, reason)
	}
	clean2 := &ConnectionMeta{SourceIP: "192.0.2.188", Country: "ZZ", Protocol: ProtocolHTTP, Username: "feedpath@example.com"}
	if res, _, _ := ti.Intercept(ctx, clean2); res != ActionProceed {
		t.Fatalf("clean request after hit-informed block must still proceed (no cache poisoning); got %v", res)
	}
}

// TestFeedRejectionPreservedWhenPolicyDoesNotFire pins the second half of the
// wave89 requirement: the threat-feed hard reject survives the reorder. A
// feed-listed request whose conditions do NOT match (critical-only policy
// against a "high" band) must still be terminated with the SAME terminal the
// old step-1 reject produced — (ActionReject, "threat_blocked") — now emitted
// by the final enforcement step.
func TestFeedRejectionPreservedWhenPolicyDoesNotFire(t *testing.T) {
	pool, ti := newFeedPathInterceptor(t)
	seedFeedPathPolicy(t, pool, "med-shard3-022-feedpath-critical", 987042, `{"ip_reputation":"critical"}`)
	ctx := context.Background()

	// Feed-listed: policy evaluated (band "high" ≠ "critical") then skipped, so
	// the request falls through to the feed enforcement step — rejected.
	listed := &ConnectionMeta{SourceIP: "198.51.100.123", Country: "ZZ", Protocol: ProtocolHTTP, Username: "feedpath@example.com"}
	if res, reason, _ := ti.Intercept(ctx, listed); res != ActionReject || reason != "threat_blocked" {
		t.Fatalf("feed-listed request must be hard-rejected with threat_blocked when no policy fires; got %v %q", res, reason)
	}

	// Clean IP: no hits, policy does not match → proceeds.
	clean := &ConnectionMeta{SourceIP: "192.0.2.189", Country: "ZZ", Protocol: ProtocolHTTP, Username: "feedpath@example.com"}
	if res, _, _ := ti.Intercept(ctx, clean); res != ActionProceed {
		t.Fatalf("clean request must proceed; got %v", res)
	}
}
