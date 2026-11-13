package migration

import (
	"strings"
	"testing"
)

func TestParseCSV(t *testing.T) {
	data := "First Name,Last Name,E-mail Address\nAlice,Smith,alice@x.test\nBob,Lee,bob@x.test\n"
	rows, mapping, err := ParseCSV(data)
	if err != nil {
		t.Fatalf("ParseCSV error: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("len(rows) = %d, want 2", len(rows))
	}
	if mapping.Email != 2 {
		t.Errorf("mapping.Email = %d, want 2", mapping.Email)
	}
	if rows[0][mapping.Email] != "alice@x.test" {
		t.Errorf("rows[0][email] = %q, want alice@x.test", rows[0][mapping.Email])
	}
}

func TestParseCSV_EmptyFails(t *testing.T) {
	if _, _, err := ParseCSV(""); err == nil {
		t.Error("expected error for empty CSV")
	}
}

func TestParseCSV_HeaderOnly(t *testing.T) {
	rows, _, err := ParseCSV("First Name,Last Name\n")
	if err != nil {
		t.Fatalf("ParseCSV error: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("len(rows) = %d, want 0", len(rows))
	}
}

func TestParseCSV_RaggedRows(t *testing.T) {
	// Ragged rows (fewer fields than the header) must be tolerated, not rejected.
	data := "First Name,Last Name,E-mail Address\nAlice,Smith\n"
	rows, _, err := ParseCSV(data)
	if err != nil {
		t.Fatalf("ParseCSV ragged error: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("len(rows) = %d, want 1", len(rows))
	}
}

func TestExportCSV(t *testing.T) {
	// ExportCSV is pure (string → string). A header row + one data row per contact.
	contacts := []ExportContact{
		{FirstName: "Alice", LastName: "Smith", Email: "alice@x.test", Company: "Acme"},
		{FirstName: "Bob", LastName: "Lee", Email: "bob@x.test"},
	}
	out, err := ExportCSV(contacts)
	if err != nil {
		t.Fatalf("ExportCSV error: %v", err)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("len(lines) = %d, want 3 (header + 2 rows)", len(lines))
	}
	if !strings.HasPrefix(lines[0], "First Name,Last Name,") {
		t.Errorf("header = %q, want Outlook-style header", lines[0])
	}
	if !strings.Contains(lines[1], "alice@x.test") {
		t.Errorf("row 1 = %q, want alice@x.test", lines[1])
	}
	// Round-trips back through the importer's mapping.
	rows, mapping, err := ParseCSV(out)
	if err != nil {
		t.Fatalf("re-parse error: %v", err)
	}
	if len(rows) != 2 || rows[0][mapping.Email] != "alice@x.test" {
		t.Errorf("export round-trip failed: rows=%v mapping.Email=%d", rows, mapping.Email)
	}
}
