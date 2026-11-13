package mdm

import (
	"encoding/json"
	"testing"
)

func TestPolicyChangeNotification_Marshal(t *testing.T) {
	n := PolicyChangeNotification{
		DeviceID: 42,
		Version:  43,
		Action:   "policy_updated",
	}

	data, err := json.Marshal(n)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var parsed PolicyChangeNotification
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if parsed.DeviceID != 42 {
		t.Errorf("expected device_id=42, got %d", parsed.DeviceID)
	}
	if parsed.Version != 43 {
		t.Errorf("expected version=43, got %d", parsed.Version)
	}
	if parsed.Action != "policy_updated" {
		t.Errorf("expected action=policy_updated, got %s", parsed.Action)
	}
}

func TestPolicyChangeActions(t *testing.T) {
	valid := map[string]bool{
		"policy_updated":       true,
		"device_locked":        true,
		"device_unlocked":      true,
		"device_wiped":         true,
		"profile_changed":      true,
		"wipe_armed":           true,
		"group_policy_updated": true,
		"invalid_action":       false,
	}

	for action, want := range valid {
		got := isValidPolicyAction(action)
		if got != want {
			t.Errorf("isValidPolicyAction(%q) = %v, want %v", action, got, want)
		}
	}
}

// TestGroupPolicyUpdated_PassesEmitValidation pins the round-2 regression: the
// admin group-policy routes emit "group_policy_updated", which was missing
// from validPolicyActions, so NotifyPolicyChange failed validation BEFORE
// pg_notify was reached and both group routes answered 500 after successful
// mutations. The action must pass emit-side validation (the full route —
// working notify → 200, injected failure → 5xx — is proven end-to-end by
// TestMAMGroupPolicies_NotifyFailure_5xx in internal/admin).
func TestGroupPolicyUpdated_PassesEmitValidation(t *testing.T) {
	if !isValidPolicyAction("group_policy_updated") {
		t.Fatal("group_policy_updated rejected by validPolicyActions: the admin group-policy routes would 500 after every successful mutation")
	}
	payload := BuildNotifyPayload(0, 0, "group_policy_updated")
	n, err := ParseNotifyPayload(payload)
	if err != nil {
		t.Fatalf("ParseNotifyPayload failed: %v", err)
	}
	if n.Action != "group_policy_updated" || n.DeviceID != 0 || n.Version != 0 {
		t.Errorf("group-policy payload round-trip mismatch: got %+v", n)
	}
}

func TestBuildNotifyPayload(t *testing.T) {
	payload := BuildNotifyPayload(42, 43, "device_locked")
	if payload == "" {
		t.Error("expected non-empty payload")
	}

	var n PolicyChangeNotification
	if err := json.Unmarshal([]byte(payload), &n); err != nil {
		t.Fatalf("failed to parse payload: %v", err)
	}
	if n.Action != "device_locked" {
		t.Errorf("expected action=device_locked, got %s", n.Action)
	}
}

func TestParseNotifyPayload_RoundTrip(t *testing.T) {
	payload := BuildNotifyPayload(7, 99, "policy_updated")
	n, err := ParseNotifyPayload(payload)
	if err != nil {
		t.Fatalf("ParseNotifyPayload failed: %v", err)
	}
	if n.DeviceID != 7 || n.Version != 99 || n.Action != "policy_updated" {
		t.Errorf("round-trip mismatch: got %+v", n)
	}
}

func TestParseNotifyPayload_Malformed(t *testing.T) {
	// The gateway goroutine relies on a non-nil error (not a silent drop) so a
	// corrupt payload is logged rather than discarded.
	if _, err := ParseNotifyPayload("{not json"); err == nil {
		t.Error("expected error for malformed payload, got nil")
	}
}
