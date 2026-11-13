package backup

import (
	"encoding/json"
	"testing"
)

func TestManifestRoundTrip(t *testing.T) {
	m := Manifest{
		Timestamp: "2026-05-21T03:00:00Z",
		Type:      "full",
		Hashes:    []string{"abc123", "def456"},
		Count:     2,
		TotalSize: 1234567,
	}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var m2 Manifest
	if err := json.Unmarshal(data, &m2); err != nil {
		t.Fatal(err)
	}
	if m2.Count != 2 || m2.TotalSize != 1234567 {
		t.Errorf("round-trip: got count=%d size=%d", m2.Count, m2.TotalSize)
	}
	if m2.Type != "full" {
		t.Errorf("round-trip: got type=%q", m2.Type)
	}
}

func TestManifestFields(t *testing.T) {
	m := Manifest{
		Timestamp: "2026-05-21T03:00:00Z",
		Type:      "incr",
		Hashes:    []string{"abc123"},
		Count:     1,
		TotalSize: 1024,
	}
	if m.Count != 1 {
		t.Error("Count field incorrect")
	}
	if m.TotalSize != 1024 {
		t.Error("TotalSize field incorrect")
	}
}
