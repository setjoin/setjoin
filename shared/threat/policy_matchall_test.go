package threat

import (
	"testing"
	"time"
)

func TestMatchAllNewConditions(t *testing.T) {
	locs := map[int64]NamedLocation{7: {ID: 7, CIDRs: []string{"10.0.0.0/8"}, Trusted: true}}
	ctx := PolicyEvalContext{SourceIP: "10.0.0.5", Country: "RU", ClientType: "imap", RequestTime: time.Now()}
	platform := "ios"

	// All-pass: location_in 7 + country_in RU + device_platform ios.
	cond := map[string]interface{}{
		"location_in":     float64(7),
		"country_in":      []interface{}{"RU"},
		"device_platform": "ios",
	}
	if !matchAll(cond, ctx, "unknown", "low", "low", platform, locs) {
		t.Fatal("expected all new conditions to match")
	}
	// One fails (platform mismatch) → whole AND fails.
	if matchAll(cond, ctx, "unknown", "low", "low", "android", locs) {
		t.Fatal("platform mismatch must fail the AND")
	}
}
