package migration

import (
	"context"
	"encoding/csv"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// CSVDialectSetjoin identifies CSV input as a Setjoin ExportCSV file. It is the
// ONLY import dialect that applies the formula-neutralization unescape
// (UnescapeCSVCell); every other value — including "" — keeps the parser's literal
// semantics, so an external file's "'+123" cell imports as "'+123", never
// rewritten to "+123".
const CSVDialectSetjoin = "setjoin"

// ParseCSV reads CSV data (with a header row) and returns the data rows plus the
// auto-detected column mapping. Ragged rows are tolerated. Empty input is an error.
// Cells are literal: a leading apostrophe is preserved verbatim.
func ParseCSV(data string) ([][]string, Mapping, error) {
	return ParseCSVDialect(data, "")
}

// ParseCSVDialect is ParseCSV with dialect handling. When dialect is
// CSVDialectSetjoin — i.e. the input is explicitly identified as a Setjoin
// ExportCSV file — every cell of every data row gets the export-dialect unescape
// (UnescapeCSVCell), inverting the EscapeCSVCell prefix ExportCSV applied. The
// header row is never unescaped. Any other dialect, including "", returns cells
// literally.
func ParseCSVDialect(data, dialect string) ([][]string, Mapping, error) {
	r := csv.NewReader(strings.NewReader(data))
	r.FieldsPerRecord = -1 // tolerate ragged rows
	records, err := r.ReadAll()
	if err != nil {
		return nil, emptyMapping(), fmt.Errorf("csv parse: %w", err)
	}
	if len(records) == 0 {
		return nil, emptyMapping(), fmt.Errorf("empty csv")
	}
	rows := records[1:]
	if dialect == CSVDialectSetjoin {
		for _, row := range rows {
			unescapeRow(row)
		}
	}
	mapping := DetectMapping(records[0])
	return rows, mapping, nil
}

// unescapeRow rewrites a parsed data row in place, stripping exactly one leading
// apostrophe from every cell that begins with one (the Setjoin export dialect).
func unescapeRow(row []string) {
	for j, c := range row {
		row[j] = UnescapeCSVCell(c)
	}
}

// EscapeCSVCell applies the Setjoin CSV export formula-neutralization convention
// (CWE-1236): it prepends exactly one literal apostrophe to any cell whose first
// character is '=', '+', '-', '@', tab, CR, or an apostrophe, and returns every
// other cell unchanged. The prefix keeps spreadsheet formula/DDE/hyperlink
// evaluation of attacker-influenced contact fields inert — ordinary CSV quoting
// does NOT neutralize formulas, so the apostrophe prefix, not quoting, is the
// neutralization. Escaping apostrophe-led cells too keeps the mapping injective:
// "+123" exports as "'+123" while a cell already led by an apostrophe exports
// with that apostrophe doubled. All contact fields
// are attacker-influenced and escaped alike, whatever their import source (CSV or
// VCF). UnescapeCSVCell is the exact inverse, applied only under CSVDialectSetjoin.
func EscapeCSVCell(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r', '\'':
		return "'" + s
	}
	return s
}

// UnescapeCSVCell is the exact inverse of EscapeCSVCell: it strips exactly one
// leading apostrophe from a cell that begins with one and leaves every other cell
// unchanged. It must be applied ONLY to input explicitly identified as
// Setjoin-dialect export (dialect CSVDialectSetjoin); ordinary CSV imports keep
// literal cells, so an external file's "'+123" stays "'+123".
func UnescapeCSVCell(s string) string {
	if strings.HasPrefix(s, "'") {
		return s[1:]
	}
	return s
}

// CSVHeaders returns just the header row of a CSV document (for the preview step).
func CSVHeaders(data string) ([]string, error) {
	r := csv.NewReader(strings.NewReader(data))
	r.FieldsPerRecord = -1
	header, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("csv header: %w", err)
	}
	return header, nil
}

// ImportCSV maps each row to a VCard and inserts it via the shared contact
// path (reuses contactStore.insert from vcf_import.go). p_mapping may override
// the auto-detected mapping (e.g. when the user corrects columns in the UI); a
// mapping with no email column falls back to the auto-detected one. Rows with
// a blank email cell are skipped. strategy ∈ {"" (default insert), "skip",
// "overwrite"}. dialect applies the formula-neutralization unescape ONLY for
// CSVDialectSetjoin (input explicitly identified as a Setjoin export); every
// other value — including "" — imports cells literally, preserving external
// leading apostrophes.
//
// Identity + strategies (D-5): every row carries a STABLE derived UID
// (csv_mapping.RowToVCard — namespaced hash of the decoded, canonicalized
// email, falling back to the decoded name when the file has no email column).
// Against the existing (addressbook_id, vcard_uid) uniqueness constraint that
// means:
//
//   - "skip"     — an already-imported row is skipped (re-import → 0 new rows);
//   - "overwrite"— the row UPSERTS in place (contact id and group memberships
//     preserved, payload refreshed); absent rows insert;
//   - ""         — plain INSERT semantics: re-importing the same row is a
//     duplicate-key ROW ERROR, deliberately surfaced (not
//     silently skipped) so the default strategy stays
//     distinguishable from "skip".
//
// ImportCSVOwned is the only CSV import entry point (CONTACTS-002 r2): the
// CONTACTS-002 r1 legacy unscoped ImportCSV wrapper was deleted after its last
// caller moved to the owned form — every caller must pass the gate-verified
// ownerMailboxID that owns addressBookID, and every statement re-checks that
// pair in its own WHERE (R3). A foreign or vanished book yields row errors and
// zero writes, never a cross-tenant insert.
func ImportCSVOwned(ctx context.Context, pool *pgxpool.Pool, data string, addressBookID, ownerMailboxID int64, mapping Mapping, strategy, dialect string) (imported, skipped int, errs []string) {
	return importCSVInto(ctx, contactStore{pool: pool, ownerMailboxID: ownerMailboxID}, data, addressBookID, mapping, strategy, dialect)
}

func importCSVInto(ctx context.Context, store contactStore, data string, addressBookID int64, mapping Mapping, strategy, dialect string) (imported, skipped int, errs []string) {
	rows, detected, err := ParseCSVDialect(data, dialect)
	if err != nil {
		return 0, 0, []string{err.Error()}
	}
	if mapping.Email < 0 {
		mapping = detected // fall back to auto-detected when the caller didn't map email
	}

	for i, row := range rows {
		select {
		case <-ctx.Done():
			return imported, skipped, errs
		default:
		}

		// Skip rows with no email — a recipient-less contact is not useful here.
		if mapping.Email >= 0 && mapping.Email < len(row) && strings.TrimSpace(row[mapping.Email]) == "" {
			skipped++
			continue
		}

		vc := mapping.RowToVCard(row, addressBookID)
		if vc.UID == "" {
			// No decodable identity (no email cell and no name to fall back
			// to — csv_mapping.RowToVCard): such a row would re-import as an
			// unmatchable duplicate every time, so it is skipped like the
			// blank-email case above.
			skipped++
			continue
		}
		switch strategy {
		case "skip":
			if store.exists(ctx, addressBookID, vc.UID) {
				skipped++
				continue
			}
		case "overwrite":
			// D-5: overwrite is an atomic, ownership-scoped UPSERT — the
			// existing row updates IN PLACE (contact id and contact-group
			// memberships preserved); an absent row inserts. The pre-D-5
			// remove+insert shape retired a live contact id every re-import.
			if err := store.upsert(ctx, addressBookID, &vc); err != nil {
				errs = append(errs, fmt.Sprintf("row %d: %v", i+2, err)) // +2: header + 1-indexed
				continue
			}
			imported++
			continue
		}

		if err := store.insert(ctx, addressBookID, &vc); err != nil {
			errs = append(errs, fmt.Sprintf("row %d: %v", i+2, err)) // +2: header + 1-indexed
			continue
		}
		imported++
	}
	return imported, skipped, errs
}

// ExportContact is one row of a CSV export.
type ExportContact struct {
	FirstName string
	LastName  string
	FullName  string
	Email     string
	Company   string
	JobTitle  string
	Phone     string
	Notes     string
}

// exportHeader is the Outlook-compatible column order; it round-trips back through
// DetectMapping/ParseCSV on re-import.
var exportHeader = []string{
	"First Name", "Last Name", "Display Name", "E-mail Address",
	"Company", "Job Title", "Mobile Phone", "Notes",
}

// ExportCSV renders contacts as an Outlook-compatible CSV string (header + rows).
// Every data cell is neutralized per the Setjoin formula-injection convention
// (EscapeCSVCell): a cell whose first character is '=', '+', '-', '@', tab, CR or
// an apostrophe is prefixed with one literal apostrophe, so no spreadsheet
// formula/DDE/hyperlink payload can execute from attacker-influenced contact
// fields (quoting alone does not neutralize). The prefix on apostrophe-led cells
// keeps the mapping injective: "+123" exports as "'+123" and an apostrophe-led
// cell exports with the apostrophe doubled.
// Re-import with dialect CSVDialectSetjoin (ParseCSVDialect/ImportCSVOwned)
// inverts it exactly; every other consumer sees the literal leading apostrophe.
func ExportCSV(contacts []ExportContact) (string, error) {
	var sb strings.Builder
	w := csv.NewWriter(&sb)
	if err := w.Write(exportHeader); err != nil {
		return "", fmt.Errorf("csv header: %w", err)
	}
	for _, c := range contacts {
		if err := w.Write([]string{
			EscapeCSVCell(c.FirstName),
			EscapeCSVCell(c.LastName),
			EscapeCSVCell(c.FullName),
			EscapeCSVCell(c.Email),
			EscapeCSVCell(c.Company),
			EscapeCSVCell(c.JobTitle),
			EscapeCSVCell(c.Phone),
			EscapeCSVCell(c.Notes),
		}); err != nil {
			return "", fmt.Errorf("csv row: %w", err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return "", fmt.Errorf("csv flush: %w", err)
	}
	return sb.String(), nil
}

// ExportContactsForAddressBook loads a mailbox-owned address book's contacts and
// renders them to CSV. Ownership is enforced by the caller: addressBookID must be
// pre-verified to belong to the requesting mailbox (R1/R3) before this is invoked.
func ExportContactsForAddressBook(ctx context.Context, pool *pgxpool.Pool, addressBookID int64) (string, error) {
	rows, err := pool.Query(ctx, `
		SELECT COALESCE(first_name,''), COALESCE(last_name,''), COALESCE(display_name,''),
		       COALESCE(company,''), COALESCE(job_title,''),
		       COALESCE(emails,'[]'::jsonb), COALESCE(phones,'[]'::jsonb), COALESCE(notes,'')
		FROM contacts
		WHERE addressbook_id = $1
		ORDER BY display_name`,
		addressBookID,
	)
	if err != nil {
		return "", fmt.Errorf("contacts query: %w", err)
	}
	defer rows.Close()

	var out []ExportContact
	for rows.Next() {
		var first, last, display, company, jobTitle, notes string
		var emails, phones []map[string]any
		if err := rows.Scan(&first, &last, &display, &company, &jobTitle, &emails, &phones, &notes); err != nil {
			return "", fmt.Errorf("contacts scan: %w", err)
		}
		out = append(out, ExportContact{
			FirstName: first,
			LastName:  last,
			FullName:  display,
			Email:     firstJSONValue(emails, "address"),
			Company:   company,
			JobTitle:  jobTitle,
			Phone:     firstJSONValue(phones, "number", "value"),
			Notes:     notes,
		})
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("contacts iterate: %w", err)
	}
	return ExportCSV(out)
}

// firstJSONValue returns the first non-empty value under any of the given keys in
// the first element of a JSONB array (emails/phones store [{type,address,...}]).
func firstJSONValue(arr []map[string]any, keys ...string) string {
	if len(arr) == 0 {
		return ""
	}
	for _, k := range keys {
		if v, ok := arr[0][k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}
