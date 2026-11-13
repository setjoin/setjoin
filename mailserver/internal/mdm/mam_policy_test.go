package mdm

import (
	"testing"
)

// ── MAM policy merge unit tests (no DB required) ─────────────────────────

// Integration test coverage for ResolveMAMPolicy with real DB:
// See mailserver/sql/tests/ for pgTAP tests and e2e tests for full flow.

func TestMergePolicies_PerDeviceOverridesGlobal(t *testing.T) {
	global := map[string]string{
		"require_pin":       "true",
		"pin_length":        "6",
		"block_screenshots": "false",
	}
	group := map[string]string{}
	perDevice := map[string]string{
		"block_screenshots": "true",
	}

	merged := mergePolicies(global, group, perDevice)

	if merged["require_pin"] != "true" {
		t.Errorf("expected require_pin=true, got %s", merged["require_pin"])
	}
	if merged["pin_length"] != "6" {
		t.Errorf("expected pin_length=6, got %s", merged["pin_length"])
	}
	if merged["block_screenshots"] != "true" {
		t.Errorf("expected block_screenshots=true (per-device override), got %s", merged["block_screenshots"])
	}
}

func TestMergePolicies_GroupOverridesGlobal(t *testing.T) {
	global := map[string]string{
		"require_pin": "true",
		"pin_length":  "4",
	}
	group := map[string]string{
		"pin_length": "8",
	}
	perDevice := map[string]string{}

	merged := mergePolicies(global, group, perDevice)

	if merged["require_pin"] != "true" {
		t.Errorf("expected require_pin=true, got %s", merged["require_pin"])
	}
	if merged["pin_length"] != "8" {
		t.Errorf("expected pin_length=8 (group override), got %s", merged["pin_length"])
	}
}

func TestMergePolicies_EmptyAll(t *testing.T) {
	merged := mergePolicies(nil, nil, nil)
	if len(merged) != 0 {
		t.Errorf("expected empty map, got %d entries", len(merged))
	}
}

func TestMergePolicies_NoGlobal(t *testing.T) {
	group := map[string]string{
		"require_pin": "true",
	}
	perDevice := map[string]string{
		"require_pin": "false",
	}
	merged := mergePolicies(nil, group, perDevice)
	if merged["require_pin"] != "false" {
		t.Errorf("expected require_pin=false (per-device wins), got %s", merged["require_pin"])
	}
}

func TestComputePolicyVersion(t *testing.T) {
	v := computePolicyVersion(
		map[string]string{"a": "1", "b": "2"},
		map[string]string{"c": "3"},
		map[string]string{"d": "4", "e": "5"},
	)
	if v != 5 {
		t.Errorf("expected version=5 (total policies), got %d", v)
	}
}

func TestComputePolicyVersion_Empty(t *testing.T) {
	v := computePolicyVersion()
	if v != 0 {
		t.Errorf("expected version=0 for empty layers, got %d", v)
	}
}
