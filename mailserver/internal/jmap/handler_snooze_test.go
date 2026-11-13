package jmap

import (
	"encoding/json"
	"testing"
)

// TestVendorCapabilityDeclared verifies the setjoin vendor capability URN is
// present so the nonstandard snoozeUntil property is auditable in one place.
func TestVendorCapabilityDeclared(t *testing.T) {
	if VendorCapability != "urn:setjoin:params:jmap:mail" {
		t.Fatalf("VendorCapability = %q, want urn:setjoin:params:jmap:mail", VendorCapability)
	}
}

// TestSplitSnoozeUpdates separates patches carrying snoozeUntil from ordinary
// Email/set update patches so each is routed to the correct reducer.
func TestSplitSnoozeUpdates(t *testing.T) {
	tests := []struct {
		name        string
		update      string
		wantSnooze  []string // message ids expected in the snooze bucket
		wantOrdinal []string // message ids expected in the ordinary update bucket
	}{
		{
			name:        "pure snooze patch",
			update:      `{"42":{"snoozeUntil":"2026-06-13T18:00:00Z"}}`,
			wantSnooze:  []string{"42"},
			wantOrdinal: nil,
		},
		{
			name:        "ordinary patch untouched",
			update:      `{"42":{"keywords":{"$seen":true}}}`,
			wantSnooze:  nil,
			wantOrdinal: []string{"42"},
		},
		{
			name:        "mixed patch splits both ways",
			update:      `{"42":{"snoozeUntil":"2026-06-13T18:00:00Z"},"43":{"keywords":{"$seen":true}}}`,
			wantSnooze:  []string{"42"},
			wantOrdinal: []string{"43"},
		},
		{
			name:        "null snoozeUntil is not a snooze",
			update:      `{"42":{"snoozeUntil":null}}`,
			wantSnooze:  nil,
			wantOrdinal: []string{"42"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var raw map[string]json.RawMessage
			if err := json.Unmarshal([]byte(tc.update), &raw); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			snooze, ordinary := splitSnoozeUpdates(raw)
			assertKeys(t, "snooze", snooze, tc.wantSnooze)
			assertKeys(t, "ordinary", ordinary, tc.wantOrdinal)
		})
	}
}

func assertKeys(t *testing.T, label string, got map[string]json.RawMessage, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s bucket: got %d keys %v, want %d keys %v", label, len(got), keysOf(got), len(want), want)
	}
	for _, k := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("%s bucket missing key %q", label, k)
		}
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestParseSnoozeUntil pulls the RFC3339 timestamp out of a snooze patch.
func TestParseSnoozeUntil(t *testing.T) {
	ts, ok := parseSnoozeUntil(json.RawMessage(`{"snoozeUntil":"2026-06-13T18:00:00Z"}`))
	if !ok {
		t.Fatal("expected ok=true for valid snoozeUntil")
	}
	if ts.Hour() != 18 {
		t.Errorf("parsed hour = %d, want 18", ts.Hour())
	}
	if _, ok := parseSnoozeUntil(json.RawMessage(`{"keywords":{"$seen":true}}`)); ok {
		t.Error("expected ok=false when snoozeUntil absent")
	}
	if _, ok := parseSnoozeUntil(json.RawMessage(`{"snoozeUntil":"not-a-date"}`)); ok {
		t.Error("expected ok=false for unparseable snoozeUntil")
	}
}

// TestParseSnoozeUntilJSFormat covers JavaScript's Date.toISOString() output,
// which always includes sub-second precision (e.g. "2026-06-14T08:00:00.000Z").
// Go's time.RFC3339 has no fractional-seconds field and fails for such strings,
// so parseSnoozeUntil must accept RFC3339Nano as well.
func TestParseSnoozeUntilJSFormat(t *testing.T) {
	cases := []struct {
		input string
		hour  int
	}{
		// JS Date.toISOString() with .000 milliseconds
		{`{"snoozeUntil":"2026-06-14T08:00:00.000Z"}`, 8},
		// JS Date.toISOString() with non-zero milliseconds
		{`{"snoozeUntil":"2026-06-14T08:00:00.123Z"}`, 8},
		// Plain RFC3339 without fractional seconds still works
		{`{"snoozeUntil":"2026-06-14T08:00:00Z"}`, 8},
	}
	for _, tc := range cases {
		ts, ok := parseSnoozeUntil(json.RawMessage(tc.input))
		if !ok {
			t.Errorf("parseSnoozeUntil(%s) returned ok=false, want ok=true", tc.input)
			continue
		}
		if ts.Hour() != tc.hour {
			t.Errorf("parseSnoozeUntil(%s) hour = %d, want %d", tc.input, ts.Hour(), tc.hour)
		}
	}
}
