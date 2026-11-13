package threat

import (
	"context"
	"testing"
)

// TestIPRiskInputsFromContextNil pins the nil-context guard: a nil context
// must yield the zero value (no feed hits, no VPN score) instead of panicking
// on the Value lookup.
func TestIPRiskInputsFromContextNil(t *testing.T) {
	inputs := ipRiskInputsFromContext(nil)
	if inputs.FeedHits != 0 || inputs.VPNScore != 0 {
		t.Fatalf("nil ctx inputs = %+v, want zero value", inputs)
	}
	if got := ipRiskInputsFromContext(context.Background()); got.FeedHits != 0 || got.VPNScore != 0 {
		t.Fatalf("ctx without inputs = %+v, want zero value", got)
	}
}
