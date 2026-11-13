// Office→PDF renditions (spec §8.3, P3 Task 14): the preview worker converts
// pending office-format versions to a PDF rendition via an admin-configured
// DRIVE_PREVIEW_CMD sidecar (headless LibreOffice), chunks + stores the PDF
// through the same content-addressed path P1's chunks use (so P5's WORM/
// retention hook covers renditions for free — spec §8.3), and attaches via
// drive_preview_attach (worker pool, BYPASSRLS). No sidecar configured =>
// inert (the client falls back to a metadata card, spec §8.3). Also serves
// GET /drive/versions/{id}/preview (registered in handler.go), which
// lazily kicks a 'none' version to 'pending' via drive_preview_request.
package drive

import (
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
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/minio/minio-go/v7"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/pgxutil"
)

// ── worker ───────────────────────────────────────────────────────────────

const (
	previewWorkerInterval = 15 * time.Second
	previewBatchSize      = 5 // at-most-N-per-tick (ponytail, see PreviewWorker doc)
	previewCmdTimeout     = 2 * time.Minute
)

// Preview conversion admission bounds (er5-s11, sealed anchor
// cand-drive-preview-exhaustion): a pending version is user-content — without
// caps, one oversized office document turns a render into an unbounded disk
// write (assembled plaintext source) and one oversized sidecar output into an
// unbounded heap buffer (os.ReadFile of the produced PDF) + unbounded chunk
// storage. Both bounds are hard failure ceilings, far above any legitimate
// rendition (the 25 MiB/message mail cap and the sidecar's own 2-minute
// timeout are the practical limits below them). Package vars ONLY as a test
// seam; production always sees these values.
var (
	maxPreviewSourceBytes = int64(64 << 20) // 64 MiB assembled plaintext source cap
	maxPreviewOutputBytes = int64(64 << 20) // 64 MiB produced-PDF cap
)

// boundedWriter caps the bytes written through it, so the source-assembly
// copy fails at the bound instead of trusting the manifest's declared sizes
// (declared size_bytes is metadata; what the copy streams is the truth).
type boundedWriter struct {
	w     io.Writer
	limit int64
	n     int64
}

func (b *boundedWriter) Write(p []byte) (int, error) {
	if b.n+int64(len(p)) > b.limit {
		return 0, fmt.Errorf("preview source exceeds the %d byte input admission bound", b.limit)
	}
	n, err := b.w.Write(p)
	b.n += int64(n)
	return n, err
}

// PreviewWorker drains pending office-version renditions. Separate from the
// P1 maintenance Worker (worker.go) — different cadence (renders should
// appear promptly; the P1 sweep is a 5-minute journal/GC tick) and a
// different dependency (the DRIVE_PREVIEW_CMD sidecar path).
type PreviewWorker struct {
	pool   pgxutil.WorkerPool
	store  objectStore
	bucket string
	cmd    string // DRIVE_PREVIEW_CMD template ("{in}"/"{outdir}" placeholders); "" = inert
	logger *slog.Logger
}

// NewPreviewWorker builds the rendition worker. cmd is the raw
// DRIVE_PREVIEW_CMD value; an empty string makes Run a no-op (spec §8.3
// metadata-card fallback — no sidecar deployed).
func NewPreviewWorker(pool pgxutil.WorkerPool, store objectStore, bucket, cmd string, logger *slog.Logger) *PreviewWorker {
	return &PreviewWorker{pool: pool, store: store, bucket: bucket, cmd: cmd, logger: logger}
}

// Run starts the ticker loop; exits cleanly when ctx is cancelled. When cmd
// is unconfigured it logs once and returns immediately — no ticking, no
// claim, matching the spec §8.3 "no sidecar => inert" contract.
func (w *PreviewWorker) Run(ctx context.Context) {
	if w.cmd == "" {
		w.logger.Debug("drive preview worker: DRIVE_PREVIEW_CMD not configured, inert (metadata-card fallback)")
		return
	}
	w.logger.Info("drive preview worker started", "interval", previewWorkerInterval)
	ticker := time.NewTicker(previewWorkerInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			w.logger.Info("drive preview worker stopped")
			return
		case <-ticker.C:
			w.tick(ctx)
		}
	}
}

type previewPendingVersion struct {
	id    int64
	scope string
}

// tick claims up to previewBatchSize pending versions and renders each.
// ponytail: plain SELECT, no FOR UPDATE SKIP LOCKED — a duplicate render
// across two gateway instances (or two overlapping ticks of the same one, if
// a render outlasts the tick interval) is a benign idempotent race:
// drive_preview_attach's chunk INSERT is ON CONFLICT DO NOTHING and its
// version_chunks replace is "last attach wins". Upgrade to a per-row
// pg_try_advisory_lock claim if duplicate renders ever matter (extra sidecar
// CPU, not a correctness bug).
func (w *PreviewWorker) tick(ctx context.Context) {
	rows, err := w.pool.Query(ctx, `
		SELECT v.id, CASE WHEN s.classification = 'regular' THEN 'g' ELSE 's' || s.id END
		  FROM drive_file_versions v JOIN drive_spaces s ON s.id = v.space_id
		 WHERE v.preview_status = 'pending'
		 ORDER BY v.id
		 LIMIT $1`, previewBatchSize)
	if err != nil {
		w.logger.Warn("drive preview worker: claim query failed", "error", err)
		return
	}
	var batch []previewPendingVersion
	for rows.Next() {
		var pv previewPendingVersion
		if err := rows.Scan(&pv.id, &pv.scope); err != nil {
			rows.Close()
			w.logger.Warn("drive preview worker: claim scan failed", "error", err)
			return
		}
		batch = append(batch, pv)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		w.logger.Warn("drive preview worker: claim rows error", "error", err)
		return
	}

	for _, pv := range batch {
		if err := w.render(ctx, pv); err != nil {
			w.logger.Warn("drive preview worker: render failed", "version_id", pv.id, "error", err)
			if _, aerr := w.pool.Exec(ctx, `SELECT drive_preview_attach($1, NULL, NULL, 'failed')`, pv.id); aerr != nil {
				w.logger.Warn("drive preview worker: mark-failed attach failed", "version_id", pv.id, "error", aerr)
			}
		}
	}
}

// render assembles one pending version's content chunks into a plaintext
// temp file (server-side plaintext temp is fine — this is the server, not
// the P3 client vault), runs the DRIVE_PREVIEW_CMD sidecar against it,
// chunks + stores the produced PDF, and attaches it as 'ready'. Any error
// returned here is turned into a 'failed' attach by the caller (tick).
func (w *PreviewWorker) render(ctx context.Context, pv previewPendingVersion) error {
	manifest, err := w.contentManifest(ctx, pv.id)
	if err != nil {
		return fmt.Errorf("read content manifest: %w", err)
	}
	if len(manifest) == 0 {
		return errors.New("empty content manifest")
	}
	if err := validateManifestSize(manifest); err != nil {
		return err
	}

	srcFile, err := os.CreateTemp("", "drive-preview-src-*")
	if err != nil {
		return fmt.Errorf("create temp source: %w", err)
	}
	srcPath := srcFile.Name()
	defer func() { _ = os.Remove(srcPath) }()
	budget := &boundedWriter{w: srcFile, limit: maxPreviewSourceBytes}
	for _, c := range manifest {
		obj, err := w.store.GetObject(ctx, w.bucket, c.storageRef, minio.GetObjectOptions{})
		if err != nil {
			_ = srcFile.Close()
			return fmt.Errorf("fetch content chunk %s: %w", c.storageRef, err)
		}
		_, cerr := io.Copy(budget, obj)
		_ = obj.Close()
		if cerr != nil {
			_ = srcFile.Close()
			return fmt.Errorf("write content chunk %s: %w", c.storageRef, cerr)
		}
	}
	if err := srcFile.Close(); err != nil {
		return fmt.Errorf("close temp source: %w", err)
	}

	outDir, err := os.MkdirTemp("", "drive-preview-out-*")
	if err != nil {
		return fmt.Errorf("create temp outdir: %w", err)
	}
	defer func() { _ = os.RemoveAll(outDir) }()

	if err := runPreviewCmd(ctx, w.cmd, srcPath, outDir); err != nil {
		return fmt.Errorf("sidecar: %w", err)
	}

	pdfPath, err := findProducedPDF(outDir)
	if err != nil {
		return err
	}
	// Output bound: stat BEFORE reading, so an oversized (or runaway) sidecar
	// product is refused without ever buffering its bytes in heap.
	if info, serr := os.Stat(pdfPath); serr != nil {
		return fmt.Errorf("stat produced PDF: %w", serr)
	} else if info.Size() > maxPreviewOutputBytes {
		return fmt.Errorf("produced PDF exceeds the %d byte output admission bound", maxPreviewOutputBytes)
	}
	pdfBytes, err := os.ReadFile(pdfPath) //nolint:gosec // G304: pdfPath is server-generated (os.MkdirTemp + os.ReadDir over that same dir in findProducedPDF), never request input
	if err != nil {
		return fmt.Errorf("read produced PDF: %w", err)
	}
	if len(pdfBytes) == 0 {
		return errors.New("sidecar produced an empty PDF")
	}

	whole := sha256.Sum256(pdfBytes)
	previewSha := hex.EncodeToString(whole[:])

	type outChunk struct {
		Sha256 string `json:"sha256"`
		Size   int    `json:"size"`
	}
	var outManifest []outChunk
	for off := 0; off < len(pdfBytes); off += int(driveChunkSize) {
		end := off + int(driveChunkSize)
		if end > len(pdfBytes) {
			end = len(pdfBytes)
		}
		chunk := pdfBytes[off:end]
		sum := sha256.Sum256(chunk)
		sha := hex.EncodeToString(sum[:])
		key := "drive/" + pv.scope + "/" + sha
		if _, err := w.store.PutObject(ctx, w.bucket, key, bytes.NewReader(chunk), int64(len(chunk)),
			minio.PutObjectOptions{ContentType: "application/pdf"}); err != nil {
			return fmt.Errorf("store preview chunk: %w", err)
		}
		outManifest = append(outManifest, outChunk{Sha256: sha, Size: len(chunk)})
	}

	manifestJSON, err := json.Marshal(outManifest)
	if err != nil {
		return fmt.Errorf("marshal preview manifest: %w", err)
	}
	if _, err := w.pool.Exec(ctx, `SELECT drive_preview_attach($1, $2, $3, 'ready')`,
		pv.id, previewSha, string(manifestJSON)); err != nil {
		return fmt.Errorf("attach: %w", err)
	}
	return nil
}

// validateManifestSize applies the input admission bound to the manifest's
// declared chunk sizes BEFORE any storage fetch: a manifest that already
// exceeds maxPreviewSourceBytes is rejected fail-fast (the boundedWriter then
// still enforces the same bound on the bytes actually streamed, so a lying
// manifest cannot round the check).
func validateManifestSize(manifest []manifestChunk) error {
	var declared int64
	for _, c := range manifest {
		declared += c.sizeBytes
	}
	if declared > maxPreviewSourceBytes {
		return fmt.Errorf("version declares %d source bytes, over the %d byte input admission bound", declared, maxPreviewSourceBytes)
	}
	return nil
}

// contentManifest reads a version's content-stream chunk manifest on the
// worker (BYPASSRLS) pool — cross-tenant by design, same posture as the P1
// maintenance worker.
func (w *PreviewWorker) contentManifest(ctx context.Context, versionID int64) ([]manifestChunk, error) {
	rows, err := w.pool.Query(ctx, `
		SELECT c.storage_ref, c.size_bytes
		  FROM drive_version_chunks vc
		  JOIN drive_chunks c ON c.scope_key = vc.scope_key AND c.sha256 = vc.chunk_sha256
		 WHERE vc.version_id = $1 AND vc.stream = 'content'
		 ORDER BY vc.ordinal`, versionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []manifestChunk
	for rows.Next() {
		var c manifestChunk
		if err := rows.Scan(&c.storageRef, &c.sizeBytes); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// runPreviewCmd substitutes the {in}/{outdir} placeholders into the
// admin-configured DRIVE_PREVIEW_CMD template and runs it through the shell
// (the template is admin-set, not user input; the two substituted values are
// server-generated temp paths — no user input ever reaches the command
// line), capped at previewCmdTimeout.
func runPreviewCmd(ctx context.Context, cmdTemplate, inPath, outDir string) error {
	cmdline := strings.NewReplacer("{in}", inPath, "{outdir}", outDir).Replace(cmdTemplate)
	cctx, cancel := context.WithTimeout(ctx, previewCmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, "sh", "-c", cmdline) //nolint:gosec // G204: cmdTemplate is DRIVE_PREVIEW_CMD, an admin-set env var (not request input); inPath/outDir are server-generated temp paths substituted into it
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w (output: %s)", err, bytes.TrimSpace(out))
	}
	return nil
}

// findProducedPDF locates the single *.pdf the sidecar wrote into outDir
// (the `soffice --headless --convert-to pdf --outdir` convention).
func findProducedPDF(outDir string) (string, error) {
	entries, err := os.ReadDir(outDir)
	if err != nil {
		return "", fmt.Errorf("read outdir: %w", err)
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".pdf") {
			return filepath.Join(outDir, e.Name()), nil
		}
	}
	return "", errors.New("sidecar produced no .pdf in outdir")
}

// ── route: GET /drive/versions/{id}/preview ───────────────────────────────

// previewMeta is what getPreview needs: the render-gate/audit fields
// (mirrors versionMeta in content.go) plus the preview-specific state.
type previewMeta struct {
	spaceID        int64
	classification string
	status         string
	auditReads     bool
}

// previewMetaAndManifest resolves a version's preview state + (if ready) its
// preview-stream manifest, membership-scoped (R1) in one query — a
// non-member gets the same errVersionNotFound as content.go's equivalent, no
// membership oracle.
func (h *Handler) previewMetaAndManifest(ctx context.Context, userID, versionID int64) (previewMeta, []manifestChunk, error) {
	var pm previewMeta
	err := dbscope.RunUserScoped(ctx, h.pool, userID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			SELECT v.space_id, s.classification, v.preview_status,
			       COALESCE((drive_policy_resolve(v.space_id)->>'audit_reads')::boolean, false)
			  FROM drive_file_versions v
			  JOIN drive_spaces s ON s.id = v.space_id
			 WHERE v.id = $2
			   AND drive_runtime_has_node_capability($1, v.file_node_id, 'preview')
			   AND `+chatAttachmentLiveSQL("v.id", "$1")+``, userID, versionID).
			Scan(&pm.spaceID, &pm.classification, &pm.status, &pm.auditReads)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return previewMeta{}, nil, errVersionNotFound
	}
	if err != nil {
		return previewMeta{}, nil, err
	}
	if pm.status != "ready" {
		return pm, nil, nil
	}
	var manifest []manifestChunk
	err = dbscope.RunUserScoped(ctx, h.pool, userID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT c.storage_ref, c.size_bytes
			  FROM drive_version_chunks vc
			  JOIN drive_chunks c ON c.scope_key = vc.scope_key AND c.sha256 = vc.chunk_sha256
			 WHERE vc.version_id = $1 AND vc.stream = 'preview'
			 ORDER BY vc.ordinal`, versionID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c manifestChunk
			if err := rows.Scan(&c.storageRef, &c.sizeBytes); err != nil {
				return err
			}
			manifest = append(manifest, c)
		}
		return rows.Err()
	})
	return pm, manifest, err
}

// auditPreview writes a G3-deduped 'preview' audit row via the shared
// auditDedup helper (content.go) — same 15-minute window as auditView's
// 'view' rows, distinct action so the two streams (original content vs.
// rendition) are distinguishable in the chain.
func (h *Handler) auditPreview(ctx context.Context, userID, spaceID, versionID int64) error {
	return h.auditDedup(ctx, userID, spaceID, versionID, "preview")
}

// getPreview serves GET /drive/versions/{id}/preview: lazily requests a
// rendition on first open (status 'none' -> drive_preview_request), streams
// it with Range support once ready, and 404s (RFC 7807) otherwise. Only the
// server-generated preview stream is returned; exact preview authority is
// checked before version metadata is revealed.
func (h *Handler) getPreview(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	versionID, ok := httputil.ParseIDPath(w, r, "id", "invalid version id")
	if !ok {
		return
	}

	ctx := r.Context()
	pm, manifest, err := h.previewMetaAndManifest(ctx, claims.UserID, versionID)
	if err != nil {
		if errors.Is(err, errVersionNotFound) {
			httputil.WriteProblemStatus(w, http.StatusNotFound, "version not found")
			return
		}
		writeDriveProblem(w, r, err)
		return
	}

	if pm.status == "none" {
		var newStatus string
		reqErr := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT drive_preview_request($1, $2)`, claims.UserID, versionID).Scan(&newStatus)
		})
		if reqErr != nil {
			writeDriveProblem(w, r, reqErr)
			return
		}
		pm.status = newStatus
	}

	if pm.status != "ready" {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusNotFound,
			Type:   "https://setjoin.com/problems/drive/preview-not-ready",
			Detail: "preview rendition not ready (status=" + pm.status + ")",
		})
		return
	}

	if pm.classification != "regular" || pm.auditReads {
		if err := h.auditPreview(ctx, claims.UserID, pm.spaceID, versionID); err != nil {
			writeDriveProblem(w, r, err)
			return
		}
	}

	var size int64
	for _, c := range manifest {
		size += c.sizeBytes
	}

	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", "inline")
	w.Header().Set("Accept-Ranges", "bytes")

	rangeHeader := r.Header.Get("Range")
	if rangeHeader == "" {
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		w.WriteHeader(http.StatusOK)
		h.streamManifest(ctx, w, manifest, 0, size-1, false)
		return
	}
	start, end, ok := parseSingleRange(rangeHeader, size)
	if !ok {
		httputil.WriteProblemStatus(w, http.StatusRequestedRangeNotSatisfiable, "invalid or multipart Range")
		return
	}
	w.Header().Set("Content-Range", "bytes "+strconv.FormatInt(start, 10)+"-"+strconv.FormatInt(end, 10)+"/"+strconv.FormatInt(size, 10))
	w.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
	w.WriteHeader(http.StatusPartialContent)
	h.streamManifest(ctx, w, manifest, start, end, true)
}
