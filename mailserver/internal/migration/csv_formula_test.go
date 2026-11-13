package migration

// Tests for the Setjoin CSV formula-neutralization convention (CWE-1236):
// ExportCSV prefixes exactly one literal apostrophe to any cell whose first
// character is '=', '+', '-', '@', tab, CR, or an apostrophe; only an explicitly
// Setjoin-dialect-identified import (ParseCSVDialect with CSVDialectSetjoin, the
// mode ImportCSV applies) strips exactly one leading apostrophe. Ordinary CSV
// imports keep literal cells. The mapping is injective: "+123" exports as
// "'+123" while "'+123" exports as "''+123", and both re-import to their exact
// distinct originals.

import (
	"encoding/csv"
	"strings"
	"testing"
)

// formulaCorpus is the formula-injection corpus: DDE, hyperlink, quoted-formula,
// arithmetic, @-macro, and leading tab/CR control-character forms. Every entry
// must export defanged — no leading formula metacharacter or control may reach a
// serialized cell.
var formulaCorpus = []string{
	"=cmd|'/c calc'!A0",                          // DDE payload
	"=HYPERLINK(\"http://evil.test\",\"click\")", // hyperlink payload
	"=\"cmd\"&A1",                                // quoted formula with embedded double quotes
	"+123",                                       // arithmetic
	"-1+SUM(A1:A9)",                              // negative-formula
	"@SUM(1)",                                    // @-macro form
	"\tcmd",                                      // leading tab
	"\r=cmd",                                     // leading CR
	"'already-quoted",                            // literal leading apostrophe (kept injective)
}

// exportDataRows re-parses an ExportCSV document and returns its data rows
// (header dropped). Parse-back is the ground truth for what a spreadsheet
// consumes from the serialized bytes.
func exportDataRows(t *testing.T, out string) [][]string {
	t.Helper()
	r := csv.NewReader(strings.NewReader(out))
	r.FieldsPerRecord = -1
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("re-parse export: %v", err)
	}
	if len(records) == 0 {
		t.Fatal("empty export")
	}
	return records[1:]
}

// TestExportCSVFormulaCorpusDefanged proves crafted (VCF/CSV-sourced) contact
// fields export defanged: every corpus cell serializes with the apostrophe first,
// so no leading formula metacharacter or control reaches a cell and DDE/hyperlink
// attempts are inert.
func TestExportCSVFormulaCorpusDefanged(t *testing.T) {
	for _, payload := range formulaCorpus {
		out, err := ExportCSV([]ExportContact{{
			FirstName: payload,
			FullName:  payload,
			Notes:     payload,
		}})
		if err != nil {
			t.Fatalf("ExportCSV(%q): %v", payload, err)
		}
		rows := exportDataRows(t, out)
		if len(rows) != 1 {
			t.Fatalf("payload %q: len(rows) = %d, want 1", payload, len(rows))
		}
		for _, idx := range []int{0, 2, 7} { // FirstName, FullName, Notes
			cell := rows[0][idx]
			if cell != "'"+payload {
				t.Errorf("payload %q: serialized cell %q, want %q (apostrophe prefix, not quoting)", payload, cell, "'"+payload)
			}
			if strings.HasPrefix(cell, "=") || strings.HasPrefix(cell, "+") ||
				strings.HasPrefix(cell, "-") || strings.HasPrefix(cell, "@") ||
				strings.HasPrefix(cell, "\t") || strings.HasPrefix(cell, "\r") {
				t.Errorf("payload %q: leading formula metacharacter reached cell %q", payload, cell)
			}
		}
	}
}

// TestExportCSVQuotedFormulaStillNeutralized pins the quoted-formula case: a
// field carrying "=SUM(1,2)" serializes quoted (it contains a comma), and the
// neutralized first cell character must still be the apostrophe inside the
// quotes — proving quoting alone does not neutralize.
func TestExportCSVQuotedFormulaStillNeutralized(t *testing.T) {
	out, err := ExportCSV([]ExportContact{{FirstName: "=SUM(1,2)"}})
	if err != nil {
		t.Fatalf("ExportCSV: %v", err)
	}
	// The apostrophe must sit immediately before the formula's leading '=' in the
	// serialized bytes, whether the writer quotes the cell or not. An unescaped
	// cell would serialize with a quote or comma there instead.
	if !strings.Contains(out, "'=SUM(1,2)") {
		t.Fatalf("serialized output %q does not carry the apostrophe immediately before the formula", out)
	}
	// Parse-back: the cell a spreadsheet consumer sees starts with the apostrophe.
	rows := exportDataRows(t, out)
	if rows[0][0] != "'=SUM(1,2)" {
		t.Errorf("cell = %q, want %q", rows[0][0], "'=SUM(1,2)")
	}
}

// TestExportCSVLeadingControlsNeutralized covers the leading tab and CR
// control-character forms explicitly.
func TestExportCSVLeadingControlsNeutralized(t *testing.T) {
	for _, payload := range []string{"\t", "\r", "\tx", "\r=y", "\t\ttab\ttab"} {
		out, err := ExportCSV([]ExportContact{{FirstName: payload, Notes: payload}})
		if err != nil {
			t.Fatalf("ExportCSV(%q): %v", payload, err)
		}
		rows := exportDataRows(t, out)
		if rows[0][0] != "'"+payload || rows[0][7] != "'"+payload {
			t.Errorf("payload %q: cells = %q/%q, want apostrophe-prefixed %q", payload, rows[0][0], rows[0][7], "'"+payload)
		}
	}
}

// TestCSVFormulaRoundTripInjective is the reversibility/injectivity unit for both
// input forms: "+123" and "'+123" export to the distinct cell strings "'+123" and
// the apostrophe-doubled form, and re-import under the explicitly identified
// Setjoin dialect restores each exact distinct original — no collision.
func TestCSVFormulaRoundTripInjective(t *testing.T) {
	out, err := ExportCSV([]ExportContact{
		{FirstName: "+123", Email: "plus@x.test"},
		{FirstName: "'+123", Email: "apos@x.test"},
	})
	if err != nil {
		t.Fatalf("ExportCSV: %v", err)
	}

	// Distinct serialized cells, verbatim: '+123 and ''+123 (rows of 8 columns;
	// only FirstName and Email set → 3 empty cells between, 4 trailing).
	if !strings.Contains(out, "\n'+123,,,plus@x.test,,,,") {
		t.Errorf("output %q missing serialized '+123 cell", out)
	}
	if !strings.Contains(out, "\n''+123,,,apos@x.test,,,,") {
		t.Errorf("output %q missing serialized ''+123 cell", out)
	}

	// Setjoin-dialect re-import: exact distinct originals.
	rows, _, err := ParseCSVDialect(out, CSVDialectSetjoin)
	if err != nil {
		t.Fatalf("ParseCSVDialect(setjoin): %v", err)
	}
	if rows[0][0] != "+123" || rows[1][0] != "'+123" {
		t.Errorf("dialect re-import = %q, %q; want %q, %q", rows[0][0], rows[1][0], "+123", "'+123")
	}
	if rows[0][0] == rows[1][0] {
		t.Error("distinct originals collided after round-trip")
	}
}

// TestParseCSVDialectDefaultKeepsLiterals asserts the default import path
// preserves ordinary CSV literals: an external file whose cell is "'+123"
// imports as "'+123" (never rewritten to "+123"), with and without a dialect
// value; only CSVDialectSetjoin unescapes.
func TestParseCSVDialectDefaultKeepsLiterals(t *testing.T) {
	external := "First Name,E-mail Address\n'+123,a@x.test\n''+1,b@x.test\nplain,c@x.test\n"

	for _, tc := range []struct {
		name    string
		dialect string
		want    []string
	}{
		{"explicit empty dialect", "", []string{"'+123", "''+1", "plain"}},
		{"unknown dialect", "bogus", []string{"'+123", "''+1", "plain"}},
		{"setjoin dialect", CSVDialectSetjoin, []string{"+123", "'+1", "plain"}},
	} {
		rows, _, err := ParseCSVDialect(external, tc.dialect)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		for i, want := range tc.want {
			if rows[i][0] != want {
				t.Errorf("%s: row %d cell = %q, want %q", tc.name, i, rows[i][0], want)
			}
		}
	}

	// The plain parser keeps literal semantics (csv_import.go behavior today).
	litRows, _, err := ParseCSV(external)
	if err != nil {
		t.Fatalf("ParseCSV: %v", err)
	}
	if litRows[0][0] != "'+123" || litRows[1][0] != "''+1" {
		t.Errorf("ParseCSV rewrote literals: %q, %q", litRows[0][0], litRows[1][0])
	}
}

// TestExportCSVOrdinaryValuesUnchanged proves ordinary values (no leading
// metacharacter/apostrophe; internal apostrophes and dashes included) export and
// re-import byte-identical, with no prefix added.
func TestExportCSVOrdinaryValuesUnchanged(t *testing.T) {
	cells := []string{
		"Alice", "Smith", "Alice Smith", "alice@x.test",
		"Acme Corp", "Lead Engineer", "0571-8888", "met at Bob's Shop",
	}
	out, err := ExportCSV([]ExportContact{
		{
			FirstName: cells[0], LastName: cells[1], FullName: cells[2],
			Email: cells[3], Company: cells[4], JobTitle: cells[5],
			Phone: cells[6], Notes: cells[7],
		},
	})
	if err != nil {
		t.Fatalf("ExportCSV: %v", err)
	}
	rows := exportDataRows(t, out)
	for i, want := range cells {
		if rows[0][i] != want {
			t.Errorf("cell %d = %q, want unchanged %q", i, rows[0][i], want)
		}
	}
	// Dialect re-import is identical for ordinary values.
	drows, _, err := ParseCSVDialect(out, CSVDialectSetjoin)
	if err != nil {
		t.Fatalf("ParseCSVDialect: %v", err)
	}
	for i, want := range cells {
		if drows[0][i] != want {
			t.Errorf("dialect re-import cell %d = %q, want %q", i, drows[0][i], want)
		}
	}
}

// TestCSVFormulaEscapeUnescapeInverse proves UnescapeCSVCell is the exact inverse
// of EscapeCSVCell over the corpus, ordinary values, and edge forms, and that the
// escape is injective (distinct originals never collide).
func TestCSVFormulaEscapeUnescapeInverse(t *testing.T) {
	values := append([]string{}, formulaCorpus...)
	values = append(values,
		"", "plain", "Bob's Shop", "'", "''x",
		"+", "-", "=", "@", "\t", "\r",
	)
	for _, v := range values {
		if got := UnescapeCSVCell(EscapeCSVCell(v)); got != v {
			t.Errorf("inverse broken: %q -> %q -> %q", v, EscapeCSVCell(v), got)
		}
	}
	seen := make(map[string]string)
	for _, v := range values {
		e := EscapeCSVCell(v)
		if prev, ok := seen[e]; ok && prev != v {
			t.Errorf("escape collision: %q and %q both serialize to %q", prev, v, e)
		}
		seen[e] = v
	}
}
