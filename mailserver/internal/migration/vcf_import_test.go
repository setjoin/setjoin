package migration

import (
	"encoding/json"
	"testing"

	"setjoin.com/mailserver/internal/carddav"
)

// TestParseNField verifies the vCard N field parser.
// vCard N format: "Family;Given;Additional;Prefix;Suffix"
// parts[0] = Family = last name, parts[1] = Given = first name.
func TestParseNField(t *testing.T) {
	cases := []struct {
		n         string
		wantFirst string
		wantLast  string
	}{
		{"Smith;John;;;", "John", "Smith"},
		{"Doe;Jane;;", "Jane", "Doe"},
		{"Smith;John;Robert;;", "John", "Smith"}, // Additional name present
		{"Onlyname", "", "Onlyname"},             // No semicolon — family only
		{"", "", ""},
		{";Given", "Given", ""},   // No family name
		{"Family;", "", "Family"}, // Empty given name
	}
	for _, c := range cases {
		gotFirst := parseFirstName(c.n)
		gotLast := parseLastName(c.n)
		if gotFirst != c.wantFirst {
			t.Errorf("parseFirstName(%q) = %q, want %q", c.n, gotFirst, c.wantFirst)
		}
		if gotLast != c.wantLast {
			t.Errorf("parseLastName(%q) = %q, want %q", c.n, gotLast, c.wantLast)
		}
	}
}

// TestVcardValuesToJSON_AddressKey verifies that vcardValuesToJSON uses "address"
// as the value key (not "value") to match the CardDAV native path and the export
// reader firstJSONValue(emails, "address").
func TestVcardValuesToJSON_AddressKey(t *testing.T) {
	vals := []carddav.VCardValue{
		{Type: "work", Value: "alice@example.com"},
		{Type: "home", Value: "alice@home.test"},
	}
	raw := vcardValuesToJSON(vals, "address")
	var parsed []map[string]any
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		t.Fatalf("vcardValuesToJSON produced invalid JSON: %v (got %s)", err, raw)
	}
	if len(parsed) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(parsed))
	}
	// "address" key must be present; "value" key must not be present.
	if addr, ok := parsed[0]["address"].(string); !ok || addr != "alice@example.com" {
		t.Errorf(`parsed[0]["address"] = %v, want "alice@example.com"`, parsed[0]["address"])
	}
	if _, hasValue := parsed[0]["value"]; hasValue {
		t.Errorf(`parsed[0] must not have "value" key; export reader looks for "address"`)
	}
}

// TestVcardValuesToJSON_PerFieldKey verifies each field type uses its canonical
// value key — phones must be "number" and urls "url", NOT "address". A single
// shared key (the pre-fix bug) blanked phone/url export (csv_import.go reads
// firstJSONValue(phones, "number", ...)).
func TestVcardValuesToJSON_PerFieldKey(t *testing.T) {
	cases := []struct {
		key  string
		want string
	}{
		{"number", "+15551234567"},
		{"url", "https://example.com"},
	}
	for _, c := range cases {
		raw := vcardValuesToJSON([]carddav.VCardValue{{Type: "work", Value: c.want}}, c.key)
		var parsed []map[string]any
		if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
			t.Fatalf("key %q: invalid JSON: %v (got %s)", c.key, err, raw)
		}
		if got, _ := parsed[0][c.key].(string); got != c.want {
			t.Errorf("key %q: parsed[0][%q] = %v, want %q", c.key, c.key, parsed[0][c.key], c.want)
		}
		if _, hasAddr := parsed[0]["address"]; hasAddr {
			t.Errorf("key %q: must not emit an \"address\" key", c.key)
		}
	}
}

// TestVcardValuesToJSON_ControlChars verifies that control characters
// (newline, tab, carriage return) are properly JSON-escaped.
// The old jsonEscape only handled \ and " — this was a data-corruption bug.
func TestVcardValuesToJSON_ControlChars(t *testing.T) {
	vals := []carddav.VCardValue{
		{Type: "note", Value: "line1\nline2\ttab\r"},
	}
	raw := vcardValuesToJSON(vals, "address")
	// Must parse as valid JSON — stdlib json.Marshal handles all RFC 8259 escapes.
	var parsed []map[string]any
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		t.Fatalf("vcardValuesToJSON with control chars produced invalid JSON: %v (got %s)", err, raw)
	}
	addr, _ := parsed[0]["address"].(string)
	if addr != "line1\nline2\ttab\r" {
		t.Errorf("address round-trip mismatch: got %q", addr)
	}
}

// TestVcardAddressesToJSON_ControlChars verifies that vcardAddressesToJSON
// also correctly handles control characters via json.Marshal.
func TestVcardAddressesToJSON_ControlChars(t *testing.T) {
	vals := []carddav.VCardAddress{
		{Type: "work", Street: "123\nMain St", City: "Springfield"},
	}
	raw := vcardAddressesToJSON(vals)
	var parsed []map[string]any
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		t.Fatalf("vcardAddressesToJSON with control chars produced invalid JSON: %v (got %s)", err, raw)
	}
	street, _ := parsed[0]["street"].(string)
	if street != "123\nMain St" {
		t.Errorf("street round-trip mismatch: got %q", street)
	}
}

// TestVcardValuesToJSON_NilEmpty verifies nil and empty slices produce valid "[]".
func TestVcardValuesToJSON_NilEmpty(t *testing.T) {
	for _, vals := range [][]carddav.VCardValue{nil, {}} {
		raw := vcardValuesToJSON(vals, "address")
		var parsed []map[string]any
		if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
			t.Fatalf("invalid JSON for nil/empty input: %v (got %s)", err, raw)
		}
		if len(parsed) != 0 {
			t.Errorf("expected empty array, got %d entries", len(parsed))
		}
	}
}
