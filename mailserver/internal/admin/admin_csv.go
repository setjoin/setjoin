package admin

import "setjoin.com/mailserver/internal/migration"

// escapeCSVCells is the single WRITER seam every admin CSV export route
// (trace Export, audit ExportCSV, threat viewCSV, chat-compliance
// writeAuditCSV) passes each data record through immediately before
// csv.Writer.Write. It applies the repo's one formula-neutralization
// authority — migration.EscapeCSVCell (CWE-1236 / OWASP CSV Injection) — to
// every cell: a cell whose first character is '=', '+', '-', '@', tab, CR or
// an apostrophe is prefixed with one literal apostrophe, so attacker- or
// data-influenced cells (SMTP addresses and trace details, audit notes, auth
// failure usernames/reasons, threat-feed sources, channel audit notes) can
// never evaluate as spreadsheet formulas/DDE/hyperlinks when an admin opens
// an export. Ordinary CSV quoting does NOT neutralize formulas — the
// apostrophe prefix is the neutralization; this helper adds no semantics of
// its own so the convention stays bound to its single tested implementation
// (no second authority, no per-site copy).
func escapeCSVCells(cells []string) []string {
	out := make([]string, len(cells))
	for i, c := range cells {
		out[i] = migration.EscapeCSVCell(c)
	}
	return out
}
