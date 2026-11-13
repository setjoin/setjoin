package admin

// ER5 re-anchor (occ_286efd3c, rule injection.csv-formula): the sealed anchor
// pointed at the SMTP inbound path, which holds no CSV code — the real
// formula-injection surface is the ADMIN CSV export writers (trace Export,
// audit ExportCSV, threat viewCSV, chat-compliance writeAuditCSV). These tests
// pin the writer-seam neutralization (escapeCSVCells → migration.EscapeCSVCell,
// the repo's single tested authority) per export site: crafted formula/DDE
// cells must round-trip neutralized, benign cells must pass through unchanged.

import (
	"context"
	"encoding/csv"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

// csvFormulaInjectionCorpus is the shared crafted-cell corpus (OWASP CSV
// injection set): the `want` column is the exact post-neutralization cell —
// a single literal leading apostrophe on every formula-led cell (=, +, -, @,
// tab, CR) and on apostrophe-led cells (injective doubling), benign cells
// verbatim.
var csvFormulaInjectionCorpus = []struct {
	name string
	in   string
	want string
}{
	{"dde-payload", `=cmd|' /C calc'!A0`, `'=cmd|' /C calc'!A0`},
	{"at-function", `@SUM(1+1)`, `'@SUM(1+1)`},
	{"minus-lead", `-2+3+cmd|' /C calc'!A0`, `'-2+3+cmd|' /C calc'!A0`},
	{"plus-lead", `+1+1`, `'+1+1`},
	{"leading-tab", "\t=1+1", "'\t=1+1"},
	{"leading-cr", "\r=cmd", "'\r=cmd"},
	{"apostrophe-lead", "'already-quoted", "''already-quoted"},
	{"benign-email", "plain@example.com", "plain@example.com"},
	{"benign-ip", "192.0.2.1", "192.0.2.1"},
	{"benign-empty", "", ""},
	{"benign-embedded-equals", "delivered=ok", "delivered=ok"},
}

// parseExportCSV parses a full export body into records via a real CSV reader,
// so every assertion below is on the POST-SERIALIZATION cell bytes (the form a
// spreadsheet application actually ingests) — not on in-memory slices.
// FieldsPerRecord is relaxed: the chat-compliance export deliberately prefixes
// narrow `# verification` metadata rows ahead of the 8-column data header (a
// pre-existing artifact format), so the document is ragged by design.
func parseExportCSV(t *testing.T, body string) [][]string {
	t.Helper()
	r := csv.NewReader(strings.NewReader(body))
	r.FieldsPerRecord = -1
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("parse exported csv: %v\nbody:\n%s", err, body)
	}
	return records
}

// TestEscapeCSVCells_FormulaCorpus is the seam unit: every corpus cell must
// neutralize exactly per the shared convention, and the escaped record must
// round-trip a real csv.Writer→csv.Reader cycle with the neutralization
// intact (the apostrophe prefix, not quoting, is what defuses the formula).
func TestEscapeCSVCells_FormulaCorpus(t *testing.T) {
	for _, tc := range csvFormulaInjectionCorpus {
		t.Run(tc.name, func(t *testing.T) {
			got := escapeCSVCells([]string{tc.in})
			if len(got) != 1 || got[0] != tc.want {
				t.Fatalf("escapeCSVCells(%q) = %q, want %q", tc.in, got, tc.want)
			}

			// Round-trip through the real serialization the handlers use. A
			// lone empty cell serializes to a blank line, which a csv.Reader
			// renders as no record — the degenerate case is verified at the
			// escape layer above only.
			if tc.in == "" {
				return
			}
			var sb strings.Builder
			w := csv.NewWriter(&sb)
			if err := w.Write(got); err != nil {
				t.Fatalf("csv write: %v", err)
			}
			w.Flush()
			records := parseExportCSV(t, sb.String())
			if len(records) != 1 || len(records[0]) != 1 || records[0][0] != tc.want {
				t.Fatalf("round-trip of %q = %v, want [[%q]] — neutralization must survive serialization", tc.in, records, tc.want)
			}
		})
	}
}

// TestTraceExportCSV_FormulaInjectionGuard seeds a message_trace row whose
// SMTP-derived cells are crafted formula/DDE payloads and asserts the admin
// trace CSV export neutralizes every crafted cell while benign cells
// (message_id, occurred_at) round-trip unchanged.
func TestTraceExportCSV_FormulaInjectionGuard(t *testing.T) {
	pool := testsupport.OpenTestPool(t) // skips if DB_DSN unset
	h := NewTraceHandler(pool, pgxutil.WorkerPool{Pool: pool}, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	ctx := context.Background()

	msgID := fmt.Sprintf("tracecsvguard-%d@example.test", time.Now().UnixNano())
	craftedFrom := `=cmd|' /C calc'!A0@evil.test`
	craftedRcpt := `@SUM(1+1)@evil.test`
	craftedHost := "\t=tabbed.evil.example"
	_, err := pool.Exec(ctx, `
		INSERT INTO message_trace (message_id, event, from_addr, rcpt_addr, remote_host, details, occurred_at)
		VALUES ($1, 'deferred', $2, $3, $4, $5, now())`,
		msgID, craftedFrom, craftedRcpt, craftedHost, `{"status":"deferred"}`)
	if err != nil {
		t.Fatalf("insert crafted trace row: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM message_trace WHERE message_id = $1`, msgID) //nolint:errcheck
	})

	// Filter by a wildcard-free substring of the crafted rcpt (unique to this
	// row) plus the benign event enum; url.Values percent-encodes the '+' so
	// it stays a literal plus in the ILIKE needle.
	q := url.Values{"event": {"deferred"}, "to": {"SUM(1+1)@evil.test"}}
	req := httptest.NewRequest(http.MethodGet, "/admin/trace/export?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	h.Export(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("trace export: want 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	records := parseExportCSV(t, rec.Body.String())
	if len(records) < 2 {
		t.Fatalf("trace export = %v, want header + at least one data row", records)
	}
	wantHeader := []string{"message_id", "event", "from_addr", "rcpt_addr", "remote_host", "details", "occurred_at"}
	for i, col := range wantHeader {
		if records[0][i] != col {
			t.Fatalf("header[%d] = %q, want %q", i, records[0][i], col)
		}
	}

	found := false
	for _, r := range records[1:] {
		if r[0] != msgID {
			continue
		}
		found = true
		// The crafted event is 'deferred' (benign enum) — unchanged.
		if r[1] != "deferred" {
			t.Errorf("event cell = %q, want deferred verbatim", r[1])
		}
		// Crafted cells must round-trip NEUTRALIZED: the serialized cell begins
		// with the defusing apostrophe, not with a formula character.
		if want := "'" + craftedFrom; r[2] != want {
			t.Errorf("from_addr cell = %q, want %q", r[2], want)
		}
		if want := "'" + craftedRcpt; r[3] != want {
			t.Errorf("rcpt_addr cell = %q, want %q", r[3], want)
		}
		if want := "'" + craftedHost; r[4] != want {
			t.Errorf("remote_host cell = %q, want %q", r[4], want)
		}
		// Benign JSON details cell round-trips as the jsonb-normalized text (a
		// '{'-led cell is not formula-led, and the guard must not mangle it).
		if r[5] != `{"status": "deferred"}` {
			t.Errorf("details cell = %q, want the jsonb text {\"status\": \"deferred\"}", r[5])
		}
		// Benign timestamp unchanged.
		if _, err := time.Parse(time.RFC3339, r[6]); err != nil {
			t.Errorf("occurred_at cell %q is not the verbatim RFC3339 value: %v", r[6], err)
		}
	}
	if !found {
		t.Fatalf("seeded row %s not found in export:\n%s", msgID, rec.Body.String())
	}
}

// TestAuditExportCSV_FormulaInjectionGuard seeds an admin_audit_log row with a
// crafted formula payload in its free-text notes and asserts the audit CSV
// export neutralizes the notes cell while benign cells (ip, action) round-trip
// unchanged.
func TestAuditExportCSV_FormulaInjectionGuard(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewAuditHandler(pool, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	ctx := context.Background()

	action := "tracecsvguard-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	craftedNotes := `=cmd|' /C calc'!A0`
	if _, err := pool.Exec(ctx, `
		INSERT INTO admin_audit_log (ip, action, target_type, notes)
		VALUES ('192.0.2.77', $1, 'csv-guard', $2)`,
		action, craftedNotes); err != nil {
		t.Fatalf("insert crafted audit row: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM admin_audit_log WHERE action = $1`, action) //nolint:errcheck
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/audit-log/export?action="+action, nil)
	rec := httptest.NewRecorder()
	h.ExportCSV(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("audit export: want 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	records := parseExportCSV(t, rec.Body.String())
	if len(records) < 2 {
		t.Fatalf("audit export = %v, want header + at least one data row", records)
	}
	found := false
	for _, r := range records[1:] {
		if r[4] != action { // "Action" column
			continue
		}
		found = true
		if want := "'" + craftedNotes; r[7] != want {
			t.Errorf("notes cell = %q, want %q", r[7], want)
		}
		if r[3] != "192.0.2.77/32" { // inet::text renders the /32 prefix
			t.Errorf("ip cell = %q, want verbatim 192.0.2.77/32", r[3])
		}
	}
	if !found {
		t.Fatalf("seeded audit row (action %s) not found in export:\n%s", action, rec.Body.String())
	}
}

// TestThreatAttemptsCSVExport_FormulaInjectionGuard drives the real
// viewCSV seam over the attempts view: crafted attack-derived cells
// (target_username, failure_reason) must export neutralized; benign cells
// (source_ip, protocol, occurred_at) must round-trip unchanged.
func TestThreatAttemptsCSVExport_FormulaInjectionGuard(t *testing.T) {
	pool := openThreatTestPool(t)
	h := NewThreatHandler(pool, nil, threatTestLogger())
	ctx := context.Background()

	// The test schema seeds the 2026-05 auth_attempts partition only — pin the
	// fixture there (same convention as TestThreatAttemptsIntegration).
	craftedUser := `=cmd|' /C calc'!A0`
	craftedReason := `@SUM(1+1)`
	if _, err := pool.Exec(ctx, `
		INSERT INTO auth_attempts (source_ip, target_username, protocol, outcome, failure_reason, occurred_at)
		VALUES ('192.0.2.91', $1, 'http', 'failure', $2, '2026-05-20 01:00:02+00'::timestamptz)`,
		craftedUser, craftedReason); err != nil {
		t.Fatalf("insert crafted auth_attempt: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM auth_attempts WHERE target_username = $1`, craftedUser) //nolint:errcheck
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/threat/attempts?format=csv&limit=500", nil)
	req.SetPathValue("view", "attempts")
	rec := httptest.NewRecorder()
	h.View(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("threat attempts csv: want 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	records := parseExportCSV(t, rec.Body.String())
	if len(records) < 2 {
		t.Fatalf("threat csv = %v, want header + at least one data row", records)
	}
	wantHeader := []string{"source_ip", "target_username", "protocol", "outcome", "failure_reason", "geo_country", "occurred_at"}
	for i, col := range wantHeader {
		if records[0][i] != col {
			t.Fatalf("header[%d] = %q, want %q", i, records[0][i], col)
		}
	}
	found := false
	for _, r := range records[1:] {
		if r[0] != "192.0.2.91" {
			continue
		}
		found = true
		if want := "'" + craftedUser; r[1] != want {
			t.Errorf("target_username cell = %q, want %q", r[1], want)
		}
		if r[2] != "http" {
			t.Errorf("protocol cell = %q, want verbatim http", r[2])
		}
		if want := "'" + craftedReason; r[4] != want {
			t.Errorf("failure_reason cell = %q, want %q", r[4], want)
		}
	}
	if !found {
		t.Fatalf("seeded attempts row not found in export:\n%s", rec.Body.String())
	}
}

// TestChatComplianceAuditCSV_FormulaInjectionGuard seeds a chat_audit_log act
// whose free-text notes are a crafted formula payload and asserts the
// compliance CSV export neutralizes the notes cell while benign cells
// (ip, action, target id) round-trip unchanged. The fixed `# verification`
// metadata rows are server constants and must stay literal.
func TestChatComplianceAuditCSV_FormulaInjectionGuard(t *testing.T) {
	h, pool, _ := newChatComplianceHandlerForTest(t)
	actorID := ssCreateUser(t, pool)
	viewer := ccViewClaims(actorID)
	channelID := ccCreateChannel(t, pool, "channel", ccStrPtr("csv-formula-guard"), actorID)

	action := "csvguard.act"
	craftedNotes := `=cmd|' /C calc'!A0`
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO chat_audit_log (channel_id, id, user_id, ip, action, target_type, target_id, notes)
		VALUES ($1, 1, $2, '192.0.2.92', $3, 'chat_channel', $1, $4)`,
		channelID, actorID, action, craftedNotes); err != nil {
		t.Fatalf("insert crafted chat audit act: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM chat_audit_log WHERE channel_id = $1`, channelID) //nolint:errcheck
	})

	req := httptest.NewRequest("GET", fmt.Sprintf("/admin/chat-channels/%d/audit?format=csv", channelID), nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), viewer))
	req.SetPathValue("id", strconv.FormatInt(channelID, 10))
	rec := httptest.NewRecorder()
	h.GetAudit(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Content-Type"), "text/csv") {
		t.Fatalf("GetAudit csv: want 200 text/csv, got %d %s body=%s", rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
	}

	records := parseExportCSV(t, rec.Body.String())
	found := false
	for _, r := range records {
		// The two `# verification` metadata rows are server-generated
		// constants — they must remain literal (never mangled by the guard).
		if len(r) > 0 && strings.HasPrefix(r[0], "#") {
			continue
		}
		if len(r) < 8 {
			continue
		}
		if r[4] != action { // Action column
			continue
		}
		found = true
		if want := "'" + craftedNotes; r[7] != want {
			t.Errorf("notes cell = %q, want %q", r[7], want)
		}
		if r[3] != "192.0.2.92/32" { // inet::text renders the /32 prefix
			t.Errorf("ip cell = %q, want verbatim 192.0.2.92/32", r[3])
		}
		if want := strconv.FormatInt(channelID, 10); r[6] != want {
			t.Errorf("target id cell = %q, want verbatim %q", r[6], want)
		}
	}
	if !found {
		t.Fatalf("seeded chat audit act (action %s) not found in export:\n%s", action, rec.Body.String())
	}
}
