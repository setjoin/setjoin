// Package contacts provides HTTP handlers for contact CSV import/export. The
// parsing/encoding lives in internal/migration (alongside the vCard importer); this
// package is the thin authenticated HTTP surface that resolves the caller's mailbox,
// enforces address-book ownership, and delegates to migration.ParseCSV/ImportCSV/
// ExportContactsForAddressBook.
package contacts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/carddav"
	"setjoin.com/mailserver/internal/migration"
	"setjoin.com/shared/httputil"
)

// maxUploadBytes caps a CSV upload to keep a hostile client from exhausting memory.
const maxUploadBytes = 10 << 20 // 10 MiB

// ImportHandler serves /contacts/import/csv (+ /preview), /contacts/import/vcf,
// /contacts/export/csv, and /contacts/export/vcf.
type ImportHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewImportHandler constructs an ImportHandler. A nil pool is valid for the
// pool-free preview path (used in tests); import/export require a live pool.
func NewImportHandler(pool *pgxpool.Pool, logger *slog.Logger) *ImportHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &ImportHandler{pool: pool, logger: logger}
}

// ServeHTTP routes on the path suffix. Mounted under /contacts/ in main.go behind
// requireAuth(requireApp("contacts")).
func (h *ImportHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/import/csv/preview"):
		h.preview(w, r)
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/import/csv"):
		h.importCSV(w, r)
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/import/vcf"):
		h.importVCF(w, r)
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/export/csv"):
		h.exportCSV(w, r)
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/export/vcf"):
		h.exportVCF(w, r)
	default:
		httputil.WriteError(w, http.StatusNotFound, "not found")
	}
}

// readUploadedCSV reads the multipart "file" part, capped at maxUploadBytes.
func (h *ImportHandler) readUploadedCSV(w http.ResponseWriter, r *http.Request) (string, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	// Body is hard-capped by MaxBytesReader above, so the form parse is bounded.
	if err := r.ParseMultipartForm(maxUploadBytes); err != nil { //nolint:gosec // G120: bounded by MaxBytesReader
		httputil.WriteError(w, http.StatusBadRequest, "invalid upload")
		return "", false
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "missing file")
		return "", false
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "could not read file")
		return "", false
	}
	return string(data), true
}

// previewResponse is the mapping-step payload the UI renders before importing.
type previewResponse struct {
	Headers []string          `json:"headers"`
	Mapping migration.Mapping `json:"mapping"`
	Sample  [][]string        `json:"sample"`
}

// preview parses the CSV and returns headers + auto-mapping + the first 3 rows. No DB.
func (h *ImportHandler) preview(w http.ResponseWriter, r *http.Request) {
	if auth.UserFromContext(r.Context()) == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	data, ok := h.readUploadedCSV(w, r)
	if !ok {
		return
	}

	headers, mapping, err := parseHeaderAndMapping(data)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	rows, _, _ := migration.ParseCSV(data)
	sample := rows
	if len(sample) > 3 {
		sample = sample[:3]
	}
	httputil.WriteJSON(w, http.StatusOK, previewResponse{Headers: headers, Mapping: mapping, Sample: sample})
}

// importResponse is the result of an import run.
type importResponse struct {
	Imported int      `json:"imported"`
	Skipped  int      `json:"skipped"`
	Errors   []string `json:"errors"`
}

// importCSV runs the import after verifying the address book belongs to the caller.
func (h *ImportHandler) importCSV(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if h.pool == nil {
		httputil.WriteError(w, http.StatusInternalServerError, "no database")
		return
	}

	data, ok := h.readUploadedCSV(w, r)
	if !ok {
		return
	}
	addressBookID, err := strconv.ParseInt(r.FormValue("addressBookId"), 10, 64)
	if err != nil || addressBookID <= 0 {
		httputil.WriteError(w, http.StatusBadRequest, "invalid addressBookId")
		return
	}
	strategy := r.FormValue("strategy") // "", "skip", "overwrite"

	// dialect selects the import dialect. Only migration.CSVDialectSetjoin (input
	// explicitly identified as a Setjoin export) applies the formula-neutralization
	// unescape; absent/"" keeps the parser's literal cells. Unknown values fail
	// closed with 400 rather than being silently treated as literal.
	dialect := r.FormValue("dialect")
	if dialect != "" && dialect != migration.CSVDialectSetjoin {
		httputil.WriteError(w, http.StatusBadRequest, "invalid dialect")
		return
	}

	// Optional mapping override (JSON). Falls back to auto-detected when absent or
	// when it carries no email column.
	mapping := migration.Mapping{Email: -1}
	if raw := strings.TrimSpace(r.FormValue("mapping")); raw != "" {
		if err := json.Unmarshal([]byte(raw), &mapping); err != nil {
			httputil.WriteError(w, http.StatusBadRequest, "invalid mapping")
			return
		}
	}

	// R3 ownership: the address book must belong to the caller's mailbox. The
	// gate stays for fail-closed HTTP semantics (403 before any statement
	// runs) and returns the verified mailbox id, which is threaded into every
	// import statement so ownership is re-checked in the same WHERE as each
	// mutation — no statement acts on request-owned ids alone (no TOCTOU even
	// if a re-parenting feature appears).
	mailboxID, owned, err := h.ownedMailboxForBook(r, addressBookID, u.UserID)
	if err != nil {
		h.logger.Error("import addressbook ownership check failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if !owned {
		httputil.WriteError(w, http.StatusForbidden, "address book not found")
		return
	}

	imported, skipped, errs := migration.ImportCSVOwned(r.Context(), h.pool, data, addressBookID, mailboxID, mapping, strategy, dialect)
	if imported > 0 {
		h.notifyContactImport(r, mailboxID)
	}
	httputil.WriteJSON(w, http.StatusOK, importResponse{Imported: imported, Skipped: skipped, Errors: errs})
}

// importVCF runs a vCard (.vcf) import after verifying address-book ownership. vCard
// is self-describing, so there is no mapping/preview step — just strategy + result.
// It mirrors importCSV: same upload reader, same ownership (IDOR) gate, same notify.
func (h *ImportHandler) importVCF(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if h.pool == nil {
		httputil.WriteError(w, http.StatusInternalServerError, "no database")
		return
	}

	data, ok := h.readUploadedCSV(w, r)
	if !ok {
		return
	}
	addressBookID, err := strconv.ParseInt(r.FormValue("addressBookId"), 10, 64)
	if err != nil || addressBookID <= 0 {
		httputil.WriteError(w, http.StatusBadRequest, "invalid addressBookId")
		return
	}
	strategy := r.FormValue("strategy") // "", "skip", "overwrite", "rename"

	mailboxID, owned, err := h.ownedMailboxForBook(r, addressBookID, u.UserID)
	if err != nil {
		h.logger.Error("import addressbook ownership check failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if !owned {
		httputil.WriteError(w, http.StatusForbidden, "address book not found")
		return
	}

	// mailboxID is the gate-verified owner; ImportVCFOwned re-checks the
	// (book, mailbox) pair in every statement (R3 — see importCSV).
	imported, skipped, errs := migration.ImportVCFOwned(r.Context(), h.pool, data, addressBookID, mailboxID, strategy)
	if imported > 0 {
		h.notifyContactImport(r, mailboxID)
	}
	httputil.WriteJSON(w, http.StatusOK, importResponse{Imported: imported, Skipped: skipped, Errors: errs})
}

// notifyContactImport bumps addressbooks.jmap_state + fans a contact push after a
// bulk import. The CSV/VCF paths INSERT contacts directly (bypassing the
// jmap_contact reducer that normally bumps the state token), so without this the
// imported rows never advance jmap_state / pg_notify — other sessions and
// Contact/changes delta-sync stay stale until an unrelated change. Best-effort: the
// contacts are already persisted, so a notify failure is logged, not surfaced.
func (h *ImportHandler) notifyContactImport(r *http.Request, mailboxID int64) {
	if _, err := h.pool.Exec(r.Context(),
		`SELECT notify_contact_state($1, 'contact_created', NULL)`, mailboxID); err != nil {
		h.logger.Warn("contact import notify failed", "error", err)
	}
}

// exportCSV renders a mailbox-owned address book's contacts as a CSV download.
// Serialization neutralizes spreadsheet formula injection per the Setjoin CSV
// convention (migration.EscapeCSVCell, applied by ExportCSV): cells led by '=',
// '+', '-', '@', tab, CR or an apostrophe carry one literal apostrophe prefix, so
// no attacker-influenced contact field can execute a formula/DDE payload in a
// spreadsheet; only a dialect=CSVDialectSetjoin re-import unescapes them.
func (h *ImportHandler) exportCSV(w http.ResponseWriter, r *http.Request) {
	h.exportAddressBook(w, r, "text/csv; charset=utf-8", "contacts.csv",
		func(ctx context.Context, addressBookID, _ int64) (string, error) {
			return migration.ExportContactsForAddressBook(ctx, h.pool, addressBookID)
		})
}

// exportVCF renders either a single owned contact (?contactId=) or a whole
// mailbox-owned address book (?addressBookId=) as a .vcf download. Serialization is
// carddav.ExportVCard/ExportVCards, which reuse contactToVCard so the file stays
// byte-compatible with the CardDAV GET path.
func (h *ImportHandler) exportVCF(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("contactId") != "" {
		h.exportContactVCF(w, r)
		return
	}
	h.exportAddressBook(w, r, "text/vcard; charset=utf-8", "contacts.vcf",
		func(ctx context.Context, addressBookID, userID int64) (string, error) {
			return carddav.ExportVCards(ctx, h.pool, addressBookID, userID)
		})
}

// exportContactVCF streams a single owned contact as "<slug>.vcf" — the "forward as
// business card" surface. Ownership (R1/R3) is verified by joining
// contacts -> addressbooks -> mailboxes.user_id = caller before rendering.
func (h *ImportHandler) exportContactVCF(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if h.pool == nil {
		httputil.WriteError(w, http.StatusInternalServerError, "no database")
		return
	}
	contactID, err := strconv.ParseInt(r.URL.Query().Get("contactId"), 10, 64)
	if err != nil || contactID <= 0 {
		httputil.WriteError(w, http.StatusBadRequest, "invalid contactId")
		return
	}

	owned, err := h.ownedMailboxForContact(r, contactID, u.UserID)
	if err != nil {
		h.logger.Error("export contact ownership check failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if !owned {
		httputil.WriteError(w, http.StatusForbidden, "contact not found")
		return
	}

	vcard, displayName, err := carddav.ExportVCard(r.Context(), h.pool, contactID, u.UserID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			httputil.WriteError(w, http.StatusNotFound, "contact not found")
			return
		}
		h.logger.Error("export contact failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "export failed")
		return
	}
	w.Header().Set("Content-Type", "text/vcard; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+vcfFilename(displayName)+"\"")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, vcard)
}

// vcfFilename slugs a display name into a safe "<slug>.vcf" filename, falling back to
// "contact.vcf" when the name is empty or all-punctuation.
func vcfFilename(displayName string) string {
	var b strings.Builder
	lastDash := true // suppress a leading dash
	for _, r := range strings.ToLower(displayName) {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		case !lastDash:
			b.WriteByte('-')
			lastDash = true
		}
	}
	slug := strings.Trim(b.String(), "-")
	if slug == "" {
		slug = "contact"
	}
	return slug + ".vcf"
}

// exportAddressBook is the shared gate+stream logic behind exportCSV/exportVCF:
// auth, addressBookId parsing, ownership (R1/R3), then render + download headers.
// render does the format-specific serialization query and receives the verified
// caller's user id so serialization-side statements can carry the ownership
// filter in-query (defense in depth on top of this gate).
func (h *ImportHandler) exportAddressBook(w http.ResponseWriter, r *http.Request, contentType, filename string, render func(ctx context.Context, addressBookID, userID int64) (string, error)) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if h.pool == nil {
		httputil.WriteError(w, http.StatusInternalServerError, "no database")
		return
	}
	addressBookID, err := strconv.ParseInt(r.URL.Query().Get("addressBookId"), 10, 64)
	if err != nil || addressBookID <= 0 {
		httputil.WriteError(w, http.StatusBadRequest, "invalid addressBookId")
		return
	}

	_, owned, err := h.ownedMailboxForBook(r, addressBookID, u.UserID)
	if err != nil {
		h.logger.Error("export addressbook ownership check failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if !owned {
		httputil.WriteError(w, http.StatusForbidden, "address book not found")
		return
	}

	body, err := render(r.Context(), addressBookID, u.UserID)
	if err != nil {
		h.logger.Error("export contacts failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "export failed")
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, body)
}

// ownedMailboxForBook resolves the mailbox that owns addressBookID AND belongs to
// userID (R1/R3 — the IDOR gate). The join is mailboxes.user_id = $2 (the user's own
// mailboxes), never a request-supplied id. Returns (mailboxID, true, nil) when owned;
// (0, false, nil) when the book doesn't exist or isn't the caller's; (0, false, err)
// on a real DB error. The returned mailbox id is what the import notify uses.
func (h *ImportHandler) ownedMailboxForBook(r *http.Request, addressBookID, userID int64) (int64, bool, error) {
	var mailboxID int64
	err := h.pool.QueryRow(r.Context(), `
		SELECT mb.id FROM addressbooks ab
		JOIN mailboxes mb ON mb.id = ab.mailbox_id
		WHERE ab.id = $1 AND mb.user_id = $2`,
		addressBookID, userID,
	).Scan(&mailboxID)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return mailboxID, true, nil
}

// ownedMailboxForContact resolves whether contactID belongs (transitively via its
// address book) to a mailbox owned by userID (R1/R3 — the IDOR gate), mirroring
// ownedMailboxForBook. The join is mailboxes.user_id = $2 (the user's own
// mailboxes), never a request-supplied id.
func (h *ImportHandler) ownedMailboxForContact(r *http.Request, contactID, userID int64) (bool, error) {
	var exists bool
	err := h.pool.QueryRow(r.Context(), `
		SELECT true FROM contacts c
		JOIN addressbooks ab ON ab.id = c.addressbook_id
		JOIN mailboxes mb ON mb.id = ab.mailbox_id
		WHERE c.id = $1 AND mb.user_id = $2`,
		contactID, userID,
	).Scan(&exists)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return exists, nil
}

// parseHeaderAndMapping returns the header row + detected mapping, or an error for
// empty/invalid CSV.
func parseHeaderAndMapping(data string) ([]string, migration.Mapping, error) {
	if strings.TrimSpace(data) == "" {
		return nil, migration.Mapping{}, errors.New("empty csv")
	}
	headers, err := migration.CSVHeaders(data)
	if err != nil {
		return nil, migration.Mapping{}, fmt.Errorf("could not parse csv header")
	}
	return headers, migration.DetectMapping(headers), nil
}
