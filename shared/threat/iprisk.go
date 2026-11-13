// IP risk scoring for conditional access policy engine.
//
// Additive composite score (0–100) from three sub-scores:
//   - Feed hits: 0 → 0, 1 → 20, 2+ → 40
//   - Geo tier:  low → 0, medium → 15, high → 30, critical → 40, unknown → 10
//   - VPN/proxy: Anonymous +10, AnonymousVPN +10, HostingProvider +5,
//     PublicProxy +10, TorExitNode +20 (capped 20)
//
// Bands: 0-20 low, 21-50 medium, 51-80 high, 81-100 critical.
//
// Feed-hit and VPN signals are REQUEST-SCOPED decision inputs carried on the
// evaluation context (WithIPRiskInputs). A single IPRiskScorer is shared across
// concurrent requests, so per-request signals must never be stored on the
// scorer: the former SetFeedHits mutator raced and attributed one request's
// feed signals to another identity's decision (THREAT-IPRISK-UNWIRED-SCORING-
// INPUT), and with zero production callers the score was structurally capped at
// medium so validated high/critical ip_reputation conditions could never fire.
//
// Spec: docs/design/security/ (conditional access policies)
package threat

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
)

// IPRiskInputs carries the request-scoped threat signals that feed IP risk
// scoring for ONE authentication attempt.
type IPRiskInputs struct {
	// FeedHits is the number of threat_feed_blocks CIDRs covering the source IP
	// for this request (stepThreatFeed populates ConnectionMeta.FeedHits; capped
	// at 2 — feedScore distinguishes only 0/1/2+).
	FeedHits int
	// VPNScore is the VPN/anonymous-proxy contribution (0–20) for this request,
	// produced by external VPN detection when wired to real request paths
	// (production source tracked as an open question; absent input contributes 0,
	// exactly the historical behavior).
	VPNScore int
}

// ipRiskInputsKey is the unexported context key for IPRiskInputs.
type ipRiskInputsKey struct{}

// WithIPRiskInputs returns a context carrying the request-scoped IP-risk inputs
// for this evaluation. Interceptor call sites (stepPolicy / EvaluatePostAuth)
// attach the signals collected for the current request; the scorer reads them
// from the same context, so concurrent requests with different inputs produce
// isolated decisions.
func WithIPRiskInputs(ctx context.Context, in IPRiskInputs) context.Context {
	return context.WithValue(ctx, ipRiskInputsKey{}, in)
}

// ipRiskInputsFromContext extracts the carried inputs. Absent/nil context
// yields the zero value: no feed hits, no VPN detection.
func ipRiskInputsFromContext(ctx context.Context) IPRiskInputs {
	if ctx == nil {
		return IPRiskInputs{}
	}
	in, _ := ctx.Value(ipRiskInputsKey{}).(IPRiskInputs)
	return in
}

// IPRiskScorer computes an IP risk score and band. It is immutable per-request
// state-wise and safe for concurrent use: all request-scoped signals arrive via
// the evaluation context, never via scorer fields.
type IPRiskScorer struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewIPRiskScorer creates an IP risk scorer.
func NewIPRiskScorer(pool *pgxpool.Pool, logger *slog.Logger) *IPRiskScorer {
	return &IPRiskScorer{pool: pool, logger: logger}
}

// Score returns the composite IP risk score (0–100) and band.
// It queries geo_country_tiers internally to derive the geo component.
// Prefer ScoreWithTier when the caller has already resolved the country tier.
func (irs *IPRiskScorer) Score(ctx context.Context, sourceIP, country string) (score int, band string) {
	inputs := ipRiskInputsFromContext(ctx)
	score = feedScore(inputs.FeedHits)
	score += irs.geoTierScore(ctx, country)
	score += applyVPNScore(inputs.VPNScore)

	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}

	band = scoreToBand(score)
	return score, band
}

// ScoreWithTier returns the composite IP risk score (0–100) and band,
// using a pre-resolved country tier string instead of querying the database.
// This avoids a duplicate geo_country_tiers query when the caller has already
// resolved the tier via another path (e.g., PolicyEngine via its store).
func (irs *IPRiskScorer) ScoreWithTier(ctx context.Context, sourceIP, tier string) (score int, band string) {
	inputs := ipRiskInputsFromContext(ctx)
	score = feedScore(inputs.FeedHits)
	score += geoTierToScore(tier)
	score += applyVPNScore(inputs.VPNScore)

	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}

	band = scoreToBand(score)
	return score, band
}

// feedScore maps a threat-feed hit count to its 0–40 score contribution
// (0 → 0, 1 → 20, 2+ → 40).
func feedScore(hits int) int {
	switch {
	case hits >= 2:
		return 40
	case hits == 1:
		return 20
	default:
		return 0
	}
}

// geoTierScore maps a country risk tier to a 0–40 score.
func (irs *IPRiskScorer) geoTierScore(ctx context.Context, country string) int {
	if country == "" || irs.pool == nil {
		return 10 // unknown = 10
	}

	var tier string
	err := irs.pool.QueryRow(ctx,
		`SELECT tier FROM geo_country_tiers WHERE country_code = $1`, country,
	).Scan(&tier)
	if err != nil {
		return 10 // unknown = 10
	}

	return geoTierToScore(tier)
}

// geoTierToScore maps a country risk tier string to its score contribution (0–40).
func geoTierToScore(tier string) int {
	switch tier {
	case "critical":
		return 40
	case "high":
		return 30
	case "medium":
		return 15
	case "low":
		return 0
	default:
		return 10
	}
}

// applyVPNScore clamps the request's VPN/anonymous-proxy contribution to the
// documented 0–20 band (Anonymous +10, AnonymousVPN +10, HostingProvider +5,
// PublicProxy +10, TorExitNode +20). The GeoIP Anonymous-IP detection that
// produces it is not wired into request paths yet (production source tracked as
// an open question); an absent input contributes 0.
func applyVPNScore(score int) int {
	if score < 0 {
		return 0
	}
	if score > 20 {
		return 20
	}
	return score
}

// scoreToBand maps a numeric score (0–100) to a risk band.
func scoreToBand(score int) string {
	switch {
	case score <= 20:
		return "low"
	case score <= 50:
		return "medium"
	case score <= 80:
		return "high"
	default:
		return "critical"
	}
}
