package admin

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"setjoin.com/mailserver/internal/audit"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/mailserver/internal/mimeutil"
	"setjoin.com/shared/envutil"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/pgxutil"
)

// ImportExportHandler handles mailbox import (MBOX/EML) and export.
type ImportExportHandler struct {
	minio  *minio.Client
	pool   *pgxpool.Pool
	bucket string
	logger *slog.Logger
}

const (
	mailboxZIPMaxEntries       = 10_000
	mailboxZIPMaxExpandedBytes = int64(2 << 30)
	mailboxZIPMaxEntryBytes    = int64(128 << 20)
	mailboxZIPMaxRatio         = uint64(100)
)

var (
	createMailboxImportTemp = os.CreateTemp
	chmodMailboxImportTemp  = func(file *os.File) error { return file.Chmod(0o600) }
	syncMailboxImportTemp   = func(file *os.File) error { return file.Sync() }
)

// NewImportExportHandler creates a handler.
func NewImportExportHandler(minio *minio.Client, workerPool pgxutil.WorkerPool, bucket string, logger *slog.Logger) *ImportExportHandler {
	return &ImportExportHandler{minio: minio, pool: workerPool.Pool, bucket: bucket, logger: logger}
}

// Scope-denial sentinels for the mailbox import/export seam. The out-of-scope
// wording mirrors the sibling admin seam (admin_spam.go reach check).
var (
	errMailboxOutOfScope = errors.New("target mailbox not within your administrative scope")
	errMailboxNotFound   = errors.New("mailbox not found")
	// errAuthorityRevoked is reported by importRawMessage when the reducer's
	// statement-level authorization predicate inserted ZERO rows because the
	// actor's authority was revoked between this handler's canReachMailbox fast
	// path and the INSERT itself (round-3 Astra HOLD: a revocation during a slow
	// multipart upload must not stop subsequent inserts — it must make them
	// no-ops, and the handler reports them failed).
	errAuthorityRevoked = errors.New("administrative authority was revoked during import")
)

// mailboxExportRecheckEvery bounds how many streamed messages are served
// between fast-path reach re-checks during a long export. The export SELECT's
// admin_can_reach_mailbox predicate is the statement-level authority for which
// rows exist; this interval re-validation only stops the post-query stream
// early when authority is revoked mid-stream. Var seam for tests.
var mailboxExportRecheckEvery = 50

// canReachMailbox enforces the per-request admin domain scope for
// mailbox-targeted import/export before any data access — the same seam
// admin_spam.go applies to user-targeted mutations (`SELECT admin_can_reach`).
// Authority is DB-resolved per request (claims + admin_can_reach /
// admin_effective_authority); there is deliberately no context shortcut and
// no token-lifetime logic here.
//
//   - No authenticated caller → fail closed (routes are permission-guarded, so
//     this should never happen; the seam must not become an implicit allow).
//   - Owner-present mailbox → `admin_can_reach(actor, owner)` decides for EVERY
//     caller, including callers with no DomainScope in context: genuinely
//     global admins pass it (an active assignment with NULL domain and NULL
//     scope_type covers every target), while an OU/set-confined assignment
//     without a domain does NOT — such a caller also leaves the resolver's
//     DomainScope unset, so a `scope == 0 → allow` shortcut was a privilege
//     escalation (round-2 HOLD) and must not come back.
//   - Owner-less mailbox (distribution/shared) → admin_can_reach cannot decide
//     (no owner user row). The caller must hold LIVE DB-resolved authority on
//     the MAILBOX'S OWN domain (admin_effective_authority: scope =
//     mb.domain_id, round-6 Astra HOLD) — the cached context claim never
//     admits by itself. With no domain scope in context, only a caller whose
//     DB-resolved authority is genuinely global
//     (admin_effective_authority: scope IS NULL AND is_unconfined) passes.
func canReachMailbox(ctx context.Context, pool *pgxpool.Pool, mbID int64) error {
	claims := auth.UserFromContext(ctx)
	if claims == nil {
		return errMailboxOutOfScope
	}
	scope := middleware.DomainScopeFromContext(ctx)
	var ownerID, domainID *int64
	err := pool.QueryRow(ctx,
		`SELECT mb.user_id, mb.domain_id FROM mailboxes mb WHERE mb.id = $1`, mbID,
	).Scan(&ownerID, &domainID)
	if errors.Is(err, pgx.ErrNoRows) {
		// Fail closed without an existence oracle.
		return errMailboxNotFound
	}
	if err != nil {
		return fmt.Errorf("mailbox scope lookup failed: %w", err)
	}
	if ownerID != nil {
		// Owned mailbox: admin_can_reach is the sole authority, for every caller.
		var ok bool
		if err := pool.QueryRow(ctx, `SELECT admin_can_reach($1, $2)`, claims.UserID, *ownerID).Scan(&ok); err != nil {
			return fmt.Errorf("mailbox reach check failed: %w", err)
		}
		if ok {
			return nil
		}
		return errMailboxOutOfScope
	}
	// Owner-less arm (distribution/shared mailboxes admin_can_reach cannot
	// decide): LIVE authority scoped to the MAILBOX'S OWN domain — the SQL
	// twin of the admin_can_reach_mailbox ELSE arm. The cached context claim
	// and the old `*domainID == scope` comparison never admit by themselves:
	// round-6 Astra HOLD — that cached-domain allow arm let a domain-A actor
	// reach an owner-less domain-B mailbox and kept the export mid-stream
	// re-check (exportStreamRevoked) admitting after revocation.
	if domainID != nil && *domainID > 0 {
		var dbScoped bool
		if err := pool.QueryRow(ctx,
			`SELECT EXISTS (
			   SELECT 1 FROM admin_effective_authority($1) a
			    WHERE a.scope = $2)`,
			claims.UserID, *domainID,
		).Scan(&dbScoped); err != nil {
			return fmt.Errorf("mailbox domain-authority check failed: %w", err)
		}
		if dbScoped {
			return nil
		}
	}
	if scope == 0 {
		// No domain scope in context is not authority by itself. Require the
		// caller's DB-resolved authority to be genuinely global: some active
		// grant with NULL domain (scope IS NULL) AND no OU/set narrowing
		// (is_unconfined). An OU-only/no-domain assignment fails is_unconfined.
		var dbGlobal bool
		if err := pool.QueryRow(ctx,
			`SELECT a.scope IS NULL AND a.is_unconfined FROM admin_effective_authority($1) a`,
			claims.UserID,
		).Scan(&dbGlobal); err != nil {
			return fmt.Errorf("mailbox global-authority check failed: %w", err)
		}
		if dbGlobal {
			return nil
		}
	}
	return errMailboxOutOfScope
}

// writeMailboxScopeError maps canReachMailbox failures onto HTTP responses.
func (h *ImportExportHandler) writeMailboxScopeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errMailboxOutOfScope):
		httputil.WriteError(w, http.StatusForbidden, "target mailbox not within your administrative scope")
	case errors.Is(err, errMailboxNotFound):
		httputil.WriteError(w, http.StatusNotFound, "mailbox not found")
	default:
		h.logger.Error("mailbox scope check failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
	}
}

// Import accepts MBOX, EML, or ZIP-of-EML uploads and inserts messages into a mailbox.
func (h *ImportExportHandler) Import(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	mbIDStr := r.PathValue("id")
	mbID, err := strconv.ParseInt(mbIDStr, 10, 64)
	if err != nil || mbID <= 0 {
		httputil.WriteError(w, http.StatusBadRequest, "invalid mailbox id")
		return
	}

	// Scope seam: a domain-scoped admin may only import into mailboxes within
	// reach. Enforced before the upload body is read and before any insert.
	//
	// S/MIME-style note: this check is FAST-PATH UX only. The authority is the
	// statement-level predicate inside import_message
	// (admin_can_reach_mailbox, evaluated in the INSERT's WHERE): a revocation
	// while this slow multipart upload is being processed yields zero inserted
	// rows, and every skipped message is reported in the failed list below.
	if err := canReachMailbox(ctx, h.pool, mbID); err != nil {
		h.writeMailboxScopeError(w, err)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 50<<20)
	if err := r.ParseMultipartForm(50 << 20); err != nil { //nolint:gosec // G120: bounded by MaxBytesReader (50MB) above
		httputil.WriteError(w, http.StatusBadRequest, "invalid multipart form")
		return
	}
	file, hdr, err := r.FormFile("file")
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "file required")
		return
	}
	defer file.Close()

	folderIDStr := r.FormValue("folder_id")
	var tagID *int64
	if folderIDStr != "" {
		if fid, err := strconv.ParseInt(folderIDStr, 10, 64); err == nil && fid > 0 {
			// Map folder ID to tag ID for tag-based message system
			tagID = h.folderToTag(ctx, mbID, fid)
		}
	}

	var imported int
	var failed []map[string]any

	name := strings.ToLower(hdr.Filename)
	switch {
	case strings.HasSuffix(name, ".mbox"):
		imported, failed = h.importMBOX(ctx, mbID, tagID, file)
	case strings.HasSuffix(name, ".eml"):
		imported, failed = h.importEML(ctx, mbID, tagID, file)
	case strings.HasSuffix(name, ".zip"):
		imported, failed = h.importZIP(ctx, mbID, tagID, file)
	default:
		httputil.WriteError(w, http.StatusBadRequest, "unsupported file type (use .mbox, .eml, or .zip)")
		return
	}

	// Audit the import: an admin injecting MBOX/EML/ZIP content into another user's
	// mailbox by path id is at least as forensically relevant as the other audited
	// admin writes. Record actor, target mailbox, file, and counts via the audit_write
	// choke point. Non-fatal: a failed audit must not fail an otherwise-done import.
	var actor int64
	if claims := auth.UserFromContext(ctx); claims != nil {
		actor = claims.UserID
	}
	after, _ := json.Marshal(map[string]any{"file": hdr.Filename, "imported": imported, "failed": len(failed)})
	if err := audit.Write(ctx, h.pool, audit.Entry{
		Actor: actor, Action: "mailbox.import", TargetType: "mailbox", TargetID: &mbID,
		After: after, IP: httputil.ClientIP(r), Tier: "core",
	}); err != nil {
		h.logger.Error("mailbox import audit failed", "error", err, "mailbox", mbID)
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"imported": imported,
		"failed":   failed,
	})
}

func (h *ImportExportHandler) importMBOX(ctx context.Context, mbID int64, tagID *int64, r io.Reader) (int, []map[string]any) {
	// MBOX format: messages separated by lines starting with "From "
	data, err := io.ReadAll(r)
	if err != nil {
		return 0, []map[string]any{{"error": "Failed to read import file. The file may be corrupted."}}
	}

	// Split on "From " lines at start of line
	var msgs [][]byte
	var current []byte
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(line) > 5 && bytes.Equal(line[:5], []byte("From ")) && (len(current) == 0 || current[len(current)-1] == '\n') {
			if len(current) > 0 {
				msgs = append(msgs, current)
			}
			current = nil
			continue
		}
		current = append(current, line...)
		current = append(current, '\n')
	}
	if len(current) > 0 {
		msgs = append(msgs, current)
	}

	var imported int
	var failed []map[string]any
	for i, raw := range msgs {
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		if err := h.importRawMessage(ctx, mbID, tagID, raw); err != nil {
			h.logger.Error("import mbox message failed", "index", i, "error", err)
			failed = append(failed, map[string]any{"index": i, "error": importFailureText(err)})
		} else {
			imported++
		}
	}
	return imported, failed
}

func (h *ImportExportHandler) importEML(ctx context.Context, mbID int64, tagID *int64, r io.Reader) (int, []map[string]any) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return 0, []map[string]any{{"error": "Failed to read import file. The file may be corrupted."}}
	}
	if err := h.importRawMessage(ctx, mbID, tagID, raw); err != nil {
		h.logger.Error("import eml failed", "error", err)
		return 0, []map[string]any{{"error": importFailureText(err)}}
	}
	return 1, nil
}

func (h *ImportExportHandler) importZIP(ctx context.Context, mbID int64, tagID *int64, r io.Reader) (int, []map[string]any) {
	staged, err := createMailboxImportTemp("", "setjoin-mailbox-import-*.zip")
	if err != nil {
		return 0, []map[string]any{{"error": "Failed to stage the import file."}}
	}
	stagedPath := staged.Name()
	defer func() {
		_ = staged.Close()
		_ = os.Remove(stagedPath)
	}()
	if err := chmodMailboxImportTemp(staged); err != nil {
		return 0, []map[string]any{{"error": "Failed to stage the import file."}}
	}
	compressed, err := io.Copy(staged, io.LimitReader(r, (50<<20)+1))
	if err != nil || compressed > 50<<20 {
		return 0, []map[string]any{{"error": "ZIP file exceeds the safe import limits."}}
	}
	if err := syncMailboxImportTemp(staged); err != nil {
		return 0, []map[string]any{{"error": "Failed to stage the import file."}}
	}
	zr, err := zip.NewReader(staged, compressed)
	if err != nil {
		return 0, []map[string]any{{"error": "Invalid ZIP file. The file may be corrupted."}}
	}
	if err := validateMailboxZIP(zr.File); err != nil {
		h.logger.Warn("mailbox ZIP rejected", "error", err)
		return 0, []map[string]any{{"error": "ZIP file exceeds the safe import limits."}}
	}

	var imported int
	var expanded int64
	var failed []map[string]any
	for _, f := range zr.File {
		if err := ctx.Err(); err != nil {
			failed = append(failed, map[string]any{"error": "Import cancelled before completion."})
			break
		}
		if !strings.HasSuffix(strings.ToLower(f.Name), ".eml") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			h.logger.Error("import zip entry failed", "file", f.Name, "error", err)
			failed = append(failed, map[string]any{"file": f.Name, "error": "Failed to process file inside ZIP."})
			continue
		}
		remaining := mailboxZIPMaxExpandedBytes - expanded
		entryLimit := min(mailboxZIPMaxEntryBytes, remaining)
		raw, err := readMailboxZIPEntry(rc, entryLimit)
		if err != nil {
			h.logger.Error("import zip entry failed", "file", f.Name, "error", err)
			failed = append(failed, map[string]any{"file": f.Name, "error": "Failed to process file inside ZIP."})
			continue
		}
		expanded += int64(len(raw))
		if err := h.importRawMessage(ctx, mbID, tagID, raw); err != nil {
			h.logger.Error("import zip entry failed", "file", f.Name, "error", err)
			failed = append(failed, map[string]any{"file": f.Name, "error": importFailureText(err)})
		} else {
			imported++
		}
	}
	return imported, failed
}

func readMailboxZIPEntry(rc io.ReadCloser, entryLimit int64) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(rc, entryLimit+1))
	closeErr := rc.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil && int64(len(raw)) > entryLimit {
		err = fmt.Errorf("expanded entry exceeds import budget")
	}
	return raw, err
}

func validateMailboxZIP(files []*zip.File) error {
	if len(files) > mailboxZIPMaxEntries {
		return fmt.Errorf("entry count %d exceeds %d", len(files), mailboxZIPMaxEntries)
	}
	var declared uint64
	for _, f := range files {
		if f.UncompressedSize64 > uint64(mailboxZIPMaxEntryBytes) {
			return fmt.Errorf("entry %q exceeds expanded entry limit", f.Name)
		}
		if f.UncompressedSize64 > 0 {
			if f.CompressedSize64 == 0 || f.UncompressedSize64 > f.CompressedSize64*mailboxZIPMaxRatio {
				return fmt.Errorf("entry %q exceeds compression-ratio limit", f.Name)
			}
		}
		declared += f.UncompressedSize64
		if declared > uint64(mailboxZIPMaxExpandedBytes) {
			return fmt.Errorf("archive exceeds expanded-byte limit")
		}
	}
	return nil
}

func (h *ImportExportHandler) importRawMessage(ctx context.Context, mbID int64, tagID *int64, raw []byte) error {
	rawStr := string(raw)
	msgID := mimeutil.ExtractHeader(rawStr, "Message-ID")
	if msgID == "" {
		msgID = fmt.Sprintf("<imported-%s@%d>", envutil.RandomID(), time.Now().Unix())
	}
	subject := mimeutil.ExtractHeader(rawStr, "Subject")
	fromAddr, fromName := mimeutil.ParseFrom(mimeutil.ExtractHeader(rawStr, "From"))
	toAddrs := mimeutil.ParseAddressList(mimeutil.ExtractHeader(rawStr, "To"))
	ccAddrs := mimeutil.ParseAddressList(mimeutil.ExtractHeader(rawStr, "Cc"))
	bccAddrs := mimeutil.ParseAddressList(mimeutil.ExtractHeader(rawStr, "Bcc"))
	inReplyTo := mimeutil.ExtractHeader(rawStr, "In-Reply-To")
	references := mimeutil.ExtractHeader(rawStr, "References")
	bodyText := mimeutil.ExtractBodyText(rawStr)
	bodyHTML := mimeutil.ExtractBodyHTML(rawStr)

	dateStr := mimeutil.ExtractHeader(rawStr, "Date")
	var msgDate *time.Time
	if dateStr != "" {
		if t, err := http.ParseTime(dateStr); err == nil {
			msgDate = &t
		}
	}

	// Upload raw to MinIO
	hash := sha256.Sum256(raw)
	ref := hex.EncodeToString(hash[:])
	_, err := h.minio.PutObject(ctx, h.bucket, ref, bytes.NewReader(raw), int64(len(raw)), minio.PutObjectOptions{
		ContentType: "message/rfc822",
	})
	if err != nil {
		return fmt.Errorf("minio upload failed: %w", err)
	}

	// Statement-level authorization (round 3): the actor claims ride INTO the
	// reducer call so the INSERT's WHERE predicate (admin_can_reach_mailbox) —
	// not the handler's earlier canReachMailbox fast path — is the authority at
	// execution time. A revocation during this upload makes import_message
	// return NULL with zero inserted rows; the caller reports the message
	// failed. No authenticated actor (unreachable past the route guard) still
	// fails closed: actor 0 matches no assignment.
	var actorID int64
	if claims := auth.UserFromContext(ctx); claims != nil {
		actorID = claims.UserID
	}
	scope := middleware.DomainScopeFromContext(ctx)

	var newID *int64
	// Named notation for the authorization params: they ride past the vestigial
	// p_user_id/p_list_id tail, so positional drift can never silently land the
	// actor in a param the reducer ignores.
	if err := h.pool.QueryRow(ctx,
		`SELECT import_message($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18,
		    p_actor_id => $19, p_domain_scope => $20)`,
		mbID, tagID, msgID, subject, fromAddr, fromName,
		toAddrs, ccAddrs, bccAddrs, inReplyTo, references,
		bodyText, bodyHTML, len(raw), false, false, ref, msgDate,
		actorID, scope,
	).Scan(&newID); err != nil {
		return err
	}
	if newID == nil {
		// The reducer's statement predicate no-op'd the INSERT: authority was
		// revoked between the route seam and this statement.
		return errAuthorityRevoked
	}
	return nil
}

// importFailureText maps importRawMessage failures onto the per-message error
// text. Statement-level revocation (import_message inserted zero rows because
// the actor's authority was revoked mid-upload) gets its own wording so the
// response distinguishes it from malformed-content failures.
func importFailureText(err error) string {
	if errors.Is(err, errAuthorityRevoked) {
		return "Not imported: administrative authority was revoked during the import."
	}
	return "Import failed for this message. The file may be malformed."
}

// Export streams messages from a mailbox as MBOX or ZIP-of-EML.
func (h *ImportExportHandler) Export(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	mbIDStr := r.PathValue("id")
	mbID, err := strconv.ParseInt(mbIDStr, 10, 64)
	if err != nil || mbID <= 0 {
		httputil.WriteError(w, http.StatusBadRequest, "invalid mailbox id")
		return
	}

	// Scope seam: a domain-scoped admin may only export mailboxes within reach.
	// Enforced before the folder/tag resolution and before any message row is read.
	//
	// S/MIME-style note: this check is FAST-PATH UX only. The authority is the
	// admin_can_reach_mailbox predicate INSIDE the export SELECT below (a
	// revocation between this seam and the query empties the row set at the
	// query level), plus the per-batch stream re-check below for the long
	// object-streaming phase after the query snapshot.
	if err := canReachMailbox(ctx, h.pool, mbID); err != nil {
		h.writeMailboxScopeError(w, err)
		return
	}

	format := r.URL.Query().Get("format")
	if format != "mbox" && format != "eml" {
		format = "eml"
	}
	folderIDStr := r.URL.Query().Get("folder_id")
	var tagID *int64
	if folderIDStr != "" {
		if fid, err := strconv.ParseInt(folderIDStr, 10, 64); err == nil && fid > 0 {
			tagID = h.folderToTag(ctx, mbID, fid)
		}
	}

	// Actor claims for the statement-level predicate below. A nil claims is
	// unreachable (the seam above fails closed first) and still fails closed:
	// actor 0 matches no assignment, so the query returns zero rows.
	var actorID int64
	if claims := auth.UserFromContext(ctx); claims != nil {
		actorID = claims.UserID
	}
	scope := middleware.DomainScopeFromContext(ctx)

	rows, err := h.pool.Query(ctx,
		`SELECT m.id, m.message_id, m.raw_ref
		 FROM messages m
		 WHERE m.mailbox_id = $1
		   AND admin_can_reach_mailbox($2, $3, $1)
		   AND ($4::BIGINT IS NULL OR EXISTS (
		     SELECT 1 FROM message_tags mt
		     WHERE mt.message_id = m.id AND mt.received_at = m.received_at AND mt.tag_id = $4
		   ))
		 ORDER BY m.received_at DESC`,
		mbID, actorID, scope, tagID)
	if err != nil {
		h.logger.Error("export query failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	var msgs []msgRef
	for rows.Next() {
		var m msgRef
		if err := rows.Scan(&m.id, &m.messageID, &m.rawRef); err == nil {
			msgs = append(msgs, m)
		}
	}

	if format == "mbox" {
		w.Header().Set("Content-Type", "application/mbox")
		w.Header().Set("Content-Disposition", `attachment; filename="export.mbox"`)
		for i, m := range msgs {
			if h.exportStreamRevoked(ctx, mbID, i) {
				break
			}
			h.streamMBOXMessage(ctx, w, m)
		}
		return
	}

	// ZIP of EMLs
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="export.zip"`)
	zw := zip.NewWriter(w)
	defer zw.Close()

	for i, m := range msgs {
		if h.exportStreamRevoked(ctx, mbID, i) {
			break
		}
		name := fmt.Sprintf("%d_%s.eml", i+1, safeFilename(m.messageID))
		fw, err := zw.Create(name)
		if err != nil {
			continue
		}
		h.copyRawMessage(ctx, fw, m.rawRef)
	}
}

// exportStreamRevoked is the per-batch mid-stream re-validation for the export
// loops: the query's admin_can_reach_mailbox predicate decided which rows
// exist, but a stream over a large mailbox outlives that snapshot, so reach is
// re-checked every mailboxExportRecheckEvery messages and the stream stops
// (bytes already flushed cannot be unsent) when authority was revoked. Round 6:
// the re-check consults LIVE mailbox-own-domain authority even for owner-less
// mailboxes — the old cached-domain allow arm kept owner-less exports streaming
// after the assignment was revoked.
func (h *ImportExportHandler) exportStreamRevoked(ctx context.Context, mbID int64, i int) bool {
	if mailboxExportRecheckEvery <= 0 || i == 0 || i%mailboxExportRecheckEvery != 0 {
		return false
	}
	if err := canReachMailbox(ctx, h.pool, mbID); err == nil {
		return false
	}
	h.logger.Warn("export stream stopped: administrative authority revoked mid-stream",
		"mailbox", mbID, "messages_served", i)
	return true
}

type msgRef struct {
	id        int64
	messageID string
	rawRef    string
}

func (h *ImportExportHandler) streamMBOXMessage(ctx context.Context, w io.Writer, m msgRef) {
	obj, err := h.minio.GetObject(ctx, h.bucket, m.rawRef, minio.GetObjectOptions{})
	if err != nil {
		return
	}
	defer obj.Close()

	// MBOX separator line
	fmt.Fprintf(w, "From %s %s\n", m.messageID, time.Now().Format(time.RFC1123))
	io.Copy(w, obj)
	io.WriteString(w, "\n")
}

func (h *ImportExportHandler) copyRawMessage(ctx context.Context, w io.Writer, rawRef string) {
	obj, err := h.minio.GetObject(ctx, h.bucket, rawRef, minio.GetObjectOptions{})
	if err != nil {
		return
	}
	defer obj.Close()
	io.Copy(w, obj)
}

func safeFilename(s string) string {
	s = strings.Trim(s, "<>")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")
	s = strings.ReplaceAll(s, ":", "_")
	if len(s) > 80 {
		s = s[:80]
	}
	if s == "" {
		s = "message"
	}
	return s
}

// randomID generates a 16-byte hex random string (reused from smtp package).
// folderToTag maps a legacy folder ID to the corresponding tag ID for the same mailbox.
func (h *ImportExportHandler) folderToTag(ctx context.Context, mbID int64, folderID int64) *int64 {
	var tagID int64
	err := h.pool.QueryRow(ctx,
		`SELECT t.id FROM tags t
		 JOIN folders f ON f.mailbox_id = t.mailbox_id AND f.name = t.name
		 WHERE f.id = $1 AND f.mailbox_id = $2`,
		folderID, mbID,
	).Scan(&tagID)
	if err != nil {
		return nil
	}
	return &tagID
}
