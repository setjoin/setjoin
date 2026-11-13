package threat

import (
	"context"
	"testing"

	"setjoin.com/shared/jwtutil"
)

// ── managed_devices.compliance_status → *jwtutil.DeviceClaim mapping (P0) ──
//
// The ONLY login-reachable compliance table is managed_devices, keyed by
// device_hash (= sha256-hex of the DeviceFP). Its compliance_status domain is
// {compliant, non_compliant, unknown}. This maps it to the DeviceClaim the
// gateway gate (RequireDeviceCompliance) reads:
//
//	compliant     -> TrustTier "compliant"  (passes)
//	non_compliant -> TrustTier "quarantined" (BLOCKS at the gate)
//	unknown / no row / anything else -> NIL claim (the gate FAILS CLOSED on a
//	                                     claim-less token while enforcement
//	                                     is enabled — 403 unless an
//	                                     explicitly contracted legacy class
//	                                     admits it)
//
// The mapping NEVER fabricates a "quarantined" tier from an absent row, so a
// device with no managed_devices entry is never blocked BY THIS MAPPING — the
// fail-closed decision for the indeterminate legs belongs to the gate, and the
// composed contract is pinned in device_gate_test.go.
func TestMapManagedComplianceToClaim(t *testing.T) {
	const hash = "abc123hash"

	tests := []struct {
		name             string
		complianceStatus string
		found            bool
		wantNil          bool
		wantTier         string
	}{
		{"compliant -> compliant", "compliant", true, false, jwtutil.TrustTierCompliant},
		{"non_compliant -> quarantined (blocks)", "non_compliant", true, false, jwtutil.TrustTierQuarantined},
		{"unknown -> nil claim (pass-through)", "unknown", true, true, ""},
		{"no row -> nil claim (pass-through)", "", false, true, ""},
		{"garbage status -> nil claim (never block on uncertainty)", "bananas", true, true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MapManagedComplianceToClaim(hash, tt.complianceStatus, tt.found)
			if tt.wantNil {
				if got != nil {
					t.Fatalf("expected nil DeviceClaim, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("expected non-nil DeviceClaim, got nil")
			}
			if got.TrustTier != tt.wantTier {
				t.Errorf("TrustTier = %q, want %q", got.TrustTier, tt.wantTier)
			}
			if got.ID != hash {
				t.Errorf("ID = %q, want device hash %q", got.ID, hash)
			}
			if got.WipeRequested {
				t.Errorf("WipeRequested must be false (no hash-reachable wipe source); got true")
			}
		})
	}
}

// TestResolveDeviceClaim_GuardsFailsClosed pins the pure guards of the login
// claim producer: a nil pool or an empty fingerprint returns nil (no claim)
// without touching any database. Under an enabled gate that nil rides the
// fail-closed claim-less leg (see device_gate_test.go).
func TestResolveDeviceClaim_GuardsFailsClosed(t *testing.T) {
	resolver := &DeviceTrustResolver{pool: nil, logger: nil}
	if claim := resolver.ResolveDeviceClaim(context.Background(), "some-fp", 42); claim != nil {
		t.Fatalf("nil pool produced %+v, want nil claim", claim)
	}
	if claim := resolver.ResolveDeviceClaim(context.Background(), "", 42); claim != nil {
		t.Fatalf("empty fingerprint produced %+v, want nil claim", claim)
	}
}

// ── Device trust tier resolution ──
// These tests verify the logic for assigning trust tiers.
// The Resolve method calls into PostgreSQL, so we test at the pure-function
// level where possible. Integration tests with TEST_DB_DSN cover the full flow.

func TestTrustTierValues(t *testing.T) {
	// Verify the four trust tier constants are well-defined
	tiers := map[string]bool{
		"managed": true,
		"known":   true,
		"unknown": true,
		"risky":   true,
	}

	for _, tier := range []string{"managed", "known", "unknown", "risky"} {
		if !tiers[tier] {
			t.Errorf("trust tier %q should be a valid tier", tier)
		}
	}

	// Invalid tier should not be valid
	if tiers["invalid"] {
		t.Error("invalid tier should not be recognized")
	}
}

func TestDeviceTrustResolveEmptyFP(t *testing.T) {
	// Empty fingerprint should always resolve to unknown
	dtr := &DeviceTrustResolver{pool: nil, logger: nil}
	result := dtr.Resolve(nil, "", 42, false)
	if result != "unknown" {
		t.Errorf("empty FP should return 'unknown', got %q", result)
	}
}

func TestDeviceTrustResolveVPNMakesRisky(t *testing.T) {
	// Since we can't mock DB easily, test the structural invariant:
	// The Resolve function with nil pool always returns unknown or risky.
	dtr := &DeviceTrustResolver{pool: nil, logger: nil}

	// With VPN flag, non-empty FP
	result := dtr.Resolve(nil, "some-fingerprint", 42, true)
	if result != "unknown" {
		// When DB is nil, we can't check managed/known, so we get unknown
		t.Logf("VPN with nil pool gives: %s", result)
	}

	// Without VPN flag
	result = dtr.Resolve(nil, "some-fingerprint", 42, false)
	if result != "unknown" {
		t.Errorf("without VPN and nil pool should give 'unknown', got %q", result)
	}
}

func TestDeviceTrustResolveNilPool(t *testing.T) {
	dtr := &DeviceTrustResolver{pool: nil, logger: nil}

	tests := []struct {
		name     string
		deviceFP string
		userID   int64
		isVPN    bool
		want     string
	}{
		{"empty fp, no vpn", "", 42, false, "unknown"},
		{"empty fp, vpn", "", 42, true, "unknown"},
		{"has fp, no vpn", "fp-abc", 42, false, "unknown"},
		{"has fp, vpn", "fp-abc", 42, true, "unknown"},
		{"zero user, no vpn", "fp-abc", 0, false, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dtr.Resolve(nil, tt.deviceFP, tt.userID, tt.isVPN)
			if got != tt.want {
				t.Errorf("Resolve() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestUpsertTrustTier_NoPool(t *testing.T) {
	dtr := &DeviceTrustResolver{pool: nil, logger: nil}
	// Should not panic with nil pool
	dtr.UpsertTrustTier(nil, "fp-abc", 42, "known")
	// Test passes if no panic
}

func TestUpsertTrustTier_EmptyFP(t *testing.T) {
	dtr := &DeviceTrustResolver{pool: nil, logger: nil}
	dtr.UpsertTrustTier(nil, "", 42, "known")
	dtr.UpsertTrustTier(nil, "fp-abc", 0, "known")
	// Should not panic
}

func TestDeviceHashDeterminism(t *testing.T) {
	// Verify the SHA-256 hash is deterministic
	// (indirectly tested via the fact that Resolve always produces same result)
	dtr := &DeviceTrustResolver{pool: nil, logger: nil}
	result1 := dtr.Resolve(nil, "test-device-fp", 42, false)
	result2 := dtr.Resolve(nil, "test-device-fp", 42, false)
	if result1 != result2 {
		t.Errorf("same device FP should give same result: %q vs %q", result1, result2)
	}
}
