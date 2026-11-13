package exchangeartifact

import (
	"testing"
	"time"
)

// TestVerifyReceiptWithMaxAgeDisabledBound pins the explicit opt-out: with a
// non-positive maxAge the lifetime policy is disabled and verification reduces
// to plain VerifyReceipt semantics (an OLD receipt still verifies).
func TestVerifyReceiptWithMaxAgeDisabledBound(t *testing.T) {
	receipt, keys, issued := receiptTestFixture(t)

	// Plain VerifyReceipt enforces a small future-slack, not an age bound —
	// an aged receipt verifies when the bound is disabled.
	now := issued.Add(365 * 24 * time.Hour)
	for _, maxAge := range []time.Duration{0, -1 * time.Hour} {
		if err := VerifyReceiptWithMaxAge(receipt, keys, now, maxAge); err != nil {
			t.Fatalf("VerifyReceiptWithMaxAge(maxAge=%v) = %v, want disabled bound (nil)", maxAge, err)
		}
	}
}
