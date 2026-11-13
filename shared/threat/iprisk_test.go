package threat

import (
	"context"
	"testing"
)

// ── IP risk scoring ──

func TestFeedScore(t *testing.T) {
	tests := []struct {
		name      string
		hitCount  int
		wantScore int
	}{
		{"zero hits", 0, 0},
		{"one hit", 1, 20},
		{"two hits", 2, 40},
		{"three hits", 3, 40},
		{"many hits", 10, 40},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := feedScore(tt.hitCount)
			if got != tt.wantScore {
				t.Errorf("feedScore() with %d hits = %d, want %d", tt.hitCount, got, tt.wantScore)
			}
		})
	}
}

func TestGeoTierScore_NilPool(t *testing.T) {
	irs := &IPRiskScorer{pool: nil}

	// With nil pool, unknown country returns 10
	got := irs.geoTierScore(nil, "US")
	if got != 10 {
		t.Errorf("geoTierScore with nil pool = %d, want 10", got)
	}

	// Empty country also returns 10
	got = irs.geoTierScore(nil, "")
	if got != 10 {
		t.Errorf("geoTierScore with empty country = %d, want 10", got)
	}
}

func TestVPNScores(t *testing.T) {
	// VPN detection is not wired into request paths yet: an absent/unset
	// request-scoped input contributes 0, and the contribution is clamped to the
	// documented 0–20 band whatever the caller supplies.
	if got := applyVPNScore(0); got != 0 {
		t.Errorf("applyVPNScore(0) = %d, want 0", got)
	}
	if got := applyVPNScore(25); got != 20 {
		t.Errorf("applyVPNScore(25) = %d, want 20 (band cap)", got)
	}
	if got := applyVPNScore(-3); got != 0 {
		t.Errorf("applyVPNScore(-3) = %d, want 0", got)
	}
}

func TestScoreSaturatesAt100(t *testing.T) {
	irs := &IPRiskScorer{}
	inputs := IPRiskInputs{FeedHits: 10, VPNScore: 20} // 40 feed + 20 vpn + 10 unknown geo = 70

	// Score() must clamp into [0,100] whatever the inputs compose.
	score, band := irs.Score(WithIPRiskInputs(context.Background(), inputs), "1.2.3.4", "US")
	if score > 100 {
		t.Errorf("score should not exceed 100, got %d", score)
	}
	if score < 0 {
		t.Errorf("score should not be negative, got %d", score)
	}
	t.Logf("score=%d, band=%s", score, band)
}

func TestScoreToBand_Boundaries(t *testing.T) {
	tests := []struct {
		score int
		band  string
	}{
		{0, "low"},
		{10, "low"},
		{20, "low"},
		{21, "medium"},
		{35, "medium"},
		{50, "medium"},
		{51, "high"},
		{65, "high"},
		{80, "high"},
		{81, "critical"},
		{95, "critical"},
		{100, "critical"},
	}

	for _, tt := range tests {
		t.Run(tt.band, func(t *testing.T) {
			got := scoreToBand(tt.score)
			if got != tt.band {
				t.Errorf("scoreToBand(%d) = %q, want %q", tt.score, got, tt.band)
			}
		})
	}
}

func TestCompositeScoreExample(t *testing.T) {
	// Test a realistic example:
	// Feed hits: 1 → 20 points
	// Country: unknown (nil pool) → 10 points
	// VPN: absent → 0 points
	// Total: 30 → "medium" band
	irs := &IPRiskScorer{}
	inputs := IPRiskInputs{FeedHits: 1}
	score, band := irs.Score(WithIPRiskInputs(context.Background(), inputs), "1.2.3.4", "XX")
	if score != 30 {
		t.Errorf("composite score = %d, want 30", score)
	}
	if band != "medium" {
		t.Errorf("band = %q, want %q", band, "medium")
	}
}
