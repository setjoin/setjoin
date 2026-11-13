package drive

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/minio/minio-go/v7"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
)

// registerContentRoutes registers the version + content routes on mux.
// Split out of NewHandler (Task 20) to keep the route list readable as it
// grows across tasks — mirrors registerChunkRoutes' non-existence: Task 19
// registered inline since it was only two routes; this one gets its own
// function because handler.go's NewHandler is already long.
func (h *Handler) registerContentRoutes(mux router) {
	mux.HandleFunc("POST /drive/files/{id}/versions", h.postVersion)
	mux.HandleFunc("POST /drive/files/{id}/versions/{versionId}/restore", h.restoreVersion)
	mux.HandleFunc("GET /drive/files/{id}/versions", h.listVersions)
	mux.HandleFunc("GET /drive/versions/{id}/content", h.getContent)
}

type restoreVersionBody struct {
	BaseVersionID *int64  `json:"baseVersionId"`
	Note          *string `json:"note"`
	DeviceLabel   *string `json:"deviceLabel"`
	BranchID      *int64  `json:"branchId"`
}

// restoreVersion clones the already-authorized source manifest entirely on
// the server.  The reducer binds source+target, re-checks download and modify
// authority, and delegates the actual save to drive_file_put_version so locks,
// conflicts, quota, audit, journal, and retention semantics stay single-sourced.
func (h *Handler) restoreVersion(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	nodeID, ok := httputil.ParseIDPath(w, r, "id", "invalid node id")
	if !ok {
		return
	}
	sourceVersionID, ok := httputil.ParseIDPath(w, r, "versionId", "invalid version id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var body restoreVersionBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}

	ctx := r.Context()
	var out json.RawMessage
	var manifest json.RawMessage
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx,
			`SELECT drive_file_restore_version($1, $2, $3, $4, $5, $6, $7)`,
			claims.UserID, nodeID, sourceVersionID, body.BaseVersionID,
			body.Note, body.DeviceLabel, body.BranchID).Scan(&out); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `
			SELECT COALESCE(jsonb_agg(
			         jsonb_build_object('sha256', vc.chunk_sha256, 'size', c.size_bytes)
			         ORDER BY vc.ordinal), '[]'::jsonb)
			  FROM drive_version_chunks vc
			  JOIN drive_chunks c
			    ON c.scope_key = vc.scope_key AND c.sha256 = vc.chunk_sha256
			 WHERE vc.version_id = $1 AND vc.stream = 'content'`, sourceVersionID).Scan(&manifest)
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}

	// Re-applying a GxP retention horizon is a storage side effect after the
	// transactional metadata save, identical to the ordinary upload path.
	if pending, ok := h.applyGxpWormIfNeeded(ctx, claims.UserID, nodeID, manifest); ok {
		out = mergeJSONField(out, "wormPending", pending)
	}
	writeJSON(w, http.StatusCreated, out)
}

const maxVersionBodyBytes = 1 << 20 // 1 MiB — a 6 GiB file is ~1536 manifest entries, ~150 KB (spec §3.1)

// ── versions ─────────────────────────────────────────────────────────────

type postVersionBody struct {
	ContentSha256 string          `json:"contentSha256"`
	Size          int64           `json:"size"`
	ContentType   *string         `json:"contentType"`
	BaseVersionID *int64          `json:"baseVersionId"`
	Manifest      json.RawMessage `json:"manifest"`
	Note          *string         `json:"note"`
	DeviceLabel   *string         `json:"deviceLabel"`
	// BranchID (P4): a save ref — nil means main. Bug fix (found during P4
	// Task 17, FolderMirror branch-sibling wiring): drive_file_put_version
	// grew p_branch_id in its Task 4 upgrade but this handler never decoded
	// or forwarded it, so every save silently landed on main regardless of
	// what the caller asked for.
	BranchID *int64 `json:"branchId"`
}

// postVersion is a thin 1:1 translation to drive_file_put_version — the
// reducer owns every decision (manifest shape, anti-oracle proof, quota,
// conflict-sibling, retain_until bookkeeping). The reducer's JSONB result
// (versionId/conflict/branchId/headVersionId/wormPending) rides straight
// through as the response body.
func (h *Handler) postVersion(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	nodeID, ok := httputil.ParseIDPath(w, r, "id", "invalid node id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxVersionBodyBytes)
	var body postVersionBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	manifest := body.Manifest
	if len(manifest) == 0 {
		manifest = json.RawMessage(`[]`)
	}

	ctx := r.Context()
	var out json.RawMessage
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT drive_file_put_version($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			claims.UserID, nodeID, body.ContentSha256, body.Size, body.ContentType,
			body.BaseVersionID, string(manifest), body.Note, body.DeviceLabel, body.BranchID).Scan(&out)
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}

	// P5 G1: the reducer's own wormPending is always false (bookkeeping only —
	// drive_file_put_version.sql's comment). For a gxp space, apply the real
	// storage Object-Lock now that the manifest is committed and override
	// wormPending with the derived outcome; a non-gxp space (ok=false) keeps
	// the reducer's answer unchanged.
	if pending, ok := h.applyGxpWormIfNeeded(ctx, claims.UserID, nodeID, manifest); ok {
		out = mergeJSONField(out, "wormPending", pending)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write(out)
}

type versionOut struct {
	ID              int64    `json:"id"`
	ParentVersionID *int64   `json:"parentVersionId"`
	ConflictOf      *int64   `json:"conflictOf"`
	Sha256          string   `json:"sha256"`
	Size            int64    `json:"size"`
	ContentType     *string  `json:"contentType"`
	Author          int64    `json:"author"`
	DeviceLabel     *string  `json:"deviceLabel"`
	Note            *string  `json:"note"`
	PreviewStatus   string   `json:"previewStatus"`
	CreatedAt       string   `json:"createdAt"`
	BranchID        *int64   `json:"branchId"`
	Labels          []string `json:"labels"`
}

func (h *Handler) listVersions(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	nodeID, ok := httputil.ParseIDPath(w, r, "id", "invalid node id")
	if !ok {
		return
	}
	ctx := r.Context()
	var out []versionOut
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT v.id, v.parent_version_id, v.conflict_of, v.content_sha256, v.size_bytes,
			       v.content_type, v.author_user_id, v.device_label, v.note, v.preview_status, v.created_at
			  FROM drive_file_versions v
			 WHERE v.file_node_id = $2
			   AND drive_runtime_has_node_capability($1, v.file_node_id, 'read_metadata')
			 ORDER BY v.id DESC`, claims.UserID, nodeID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var v versionOut
			var createdAt time.Time
			if err := rows.Scan(&v.ID, &v.ParentVersionID, &v.ConflictOf, &v.Sha256, &v.Size,
				&v.ContentType, &v.Author, &v.DeviceLabel, &v.Note, &v.PreviewStatus, &createdAt); err != nil {
				return err
			}
			v.CreatedAt = createdAt.UTC().Format(time.RFC3339)
			v.Labels = []string{}
			out = append(out, v)
		}
		return rows.Err()
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	writeJSONList(w, out)
}

// ── content ──────────────────────────────────────────────────────────────

// versionMeta is what getContent needs to decide the render gate, the audit
// dedupe window, and how to stream — resolved in one membership-scoped read.
type versionMeta struct {
	spaceID        int64
	classification string
	size           int64
	contentType    *string
	auditReads     bool
}

type manifestChunk struct {
	storageRef string
	sizeBytes  int64
}

var errVersionNotFound = errors.New("drive: version not found or caller not a member")

func (h *Handler) versionMetaAndManifest(ctx context.Context, userID, versionID int64) (versionMeta, []manifestChunk, error) {
	var vm versionMeta
	var manifest []manifestChunk
	err := dbscope.RunUserScoped(ctx, h.pool, userID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			SELECT v.space_id, s.classification, v.size_bytes, v.content_type,
			       COALESCE((drive_policy_resolve(v.space_id)->>'audit_reads')::boolean, false)
			  FROM drive_file_versions v
			  JOIN drive_spaces s ON s.id = v.space_id
			 WHERE v.id = $2
			   AND drive_runtime_has_node_capability($1, v.file_node_id, 'download')
			   AND `+chatAttachmentLiveSQL("v.id", "$1")+``, userID, versionID).
			Scan(&vm.spaceID, &vm.classification, &vm.size, &vm.contentType, &vm.auditReads)
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `
			SELECT c.storage_ref, c.size_bytes
			  FROM drive_version_chunks vc
			  JOIN drive_chunks c ON c.scope_key = vc.scope_key AND c.sha256 = vc.chunk_sha256
			 WHERE vc.version_id = $1 AND vc.stream = 'content'
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
	if errors.Is(err, pgx.ErrNoRows) {
		return versionMeta{}, nil, errVersionNotFound
	}
	return vm, manifest, err
}

// auditView writes a G3-deduped 'view' audit row: at most one per (space,
// user, version) per 15-minute window, so repeated reads of an open document
// don't spam the tamper-evident chain.
func (h *Handler) auditView(ctx context.Context, userID, spaceID, versionID int64) error {
	return h.auditDedup(ctx, userID, spaceID, versionID, "view")
}

// auditDedup writes a G3-deduped audit row for the given closed-catalog
// action: at most one per (space, user, action, version) per 15-minute
// window, so repeated reads/opens of the same target don't spam the
// tamper-evident chain. Shared by auditView ('view', the content route) and
// auditPreview ('preview', the P3 rendition route) — same shape, distinct
// action so the two streams stay distinguishable in the chain.
func (h *Handler) auditDedup(ctx context.Context, userID, spaceID, versionID int64, action string) error {
	return dbscope.RunUserScoped(ctx, h.pool, userID, func(tx pgx.Tx) error {
		var dup bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS(SELECT 1 FROM drive_audit_log
			 WHERE space_id = $1 AND user_id = $2 AND action = $3 AND target_id = $4
			   AND occurred_at > now() - interval '15 minutes')`,
			spaceID, userID, action, versionID).Scan(&dup); err != nil {
			return err
		}
		if dup {
			return nil
		}
		_, err := tx.Exec(ctx, `SELECT drive_access_audit($1, $2, $3, 'version', $4, NULL, NULL, NULL, NULL)`,
			userID, spaceID, action, versionID)
		return err
	})
}

// getContent streams a version's assembled content, with RFC 7233 single-
// range support. Authorization is the exact server-side download capability;
// a caller-controlled header is never accepted as an authority signal.
func (h *Handler) getContent(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	versionID, ok := httputil.ParseIDPath(w, r, "id", "invalid version id")
	if !ok {
		return
	}

	ctx := r.Context()
	// Guest G4: decide original-byte authority before resolving the requested
	// version. The reducer is a no-op for members and returns constant-shaped
	// BZ215 for every view-only/inactive/unentitled guest posture, so a saved
	// version id cannot become an existence oracle.
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT drive_content_download_require($1)`, claims.UserID)
		return err
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}

	vm, manifest, err := h.versionMetaAndManifest(ctx, claims.UserID, versionID)
	if err != nil {
		if errors.Is(err, errVersionNotFound) {
			httputil.WriteProblemStatus(w, http.StatusNotFound, "version not found")
			return
		}
		writeDriveProblem(w, r, err)
		return
	}
	if originalContentGateBlocked(w, r, vm.classification) {
		return
	}

	if vm.classification != "regular" || vm.auditReads {
		if err := h.auditView(ctx, claims.UserID, vm.spaceID, versionID); err != nil {
			writeDriveProblem(w, r, err)
			return
		}
	}

	contentType := "application/octet-stream"
	if vm.contentType != nil && *vm.contentType != "" {
		contentType = *vm.contentType
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", "inline")
	w.Header().Set("Accept-Ranges", "bytes")
	// Uploader-supplied bytes + Content-Type served inline on the app origin
	// (a chat/shared-space peer can upload text/html or image/svg+xml): nosniff
	// + a sandbox CSP so it can't execute as a top-level document — the
	// content deep-link authenticates via the access_token cookie.
	httputil.SetUntrustedBlobHeaders(w)

	rangeHeader := r.Header.Get("Range")
	if rangeHeader == "" {
		w.Header().Set("Content-Length", strconv.FormatInt(vm.size, 10))
		w.WriteHeader(http.StatusOK)
		h.streamManifest(ctx, w, manifest, 0, vm.size-1, false)
		return
	}

	start, end, ok := parseSingleRange(rangeHeader, vm.size)
	if !ok {
		httputil.WriteProblemStatus(w, http.StatusRequestedRangeNotSatisfiable, "invalid or multipart Range")
		return
	}
	w.Header().Set("Content-Range", "bytes "+strconv.FormatInt(start, 10)+"-"+strconv.FormatInt(end, 10)+"/"+strconv.FormatInt(vm.size, 10))
	w.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
	w.WriteHeader(http.StatusPartialContent)
	h.streamManifest(ctx, w, manifest, start, end, true)
}

// streamManifest writes manifest chunks [start,end] (absolute file byte
// offsets, inclusive) to w. ranged selects whether each chunk fetch is
// narrowed with minio.GetObjectOptions.SetRange — false for the whole-file
// 200 path (every chunk read in full, no Range calls at all).
func (h *Handler) streamManifest(ctx context.Context, w http.ResponseWriter, manifest []manifestChunk, start, end int64, ranged bool) {
	firstOrdinal, skipInFirst := chunkRange(start, driveChunkSize)
	lastOrdinal, _ := chunkRange(end, driveChunkSize)
	for ord := firstOrdinal; ord <= lastOrdinal && int(ord) < len(manifest); ord++ {
		c := manifest[ord]
		opts := minio.GetObjectOptions{}
		if ranged {
			lo := int64(0)
			if ord == firstOrdinal {
				lo = skipInFirst
			}
			hi := c.sizeBytes - 1
			if ord == lastOrdinal {
				chunkStart := ord * driveChunkSize
				hi = end - chunkStart
			}
			if err := opts.SetRange(lo, hi); err != nil {
				h.logger.Error("drive: content range set failed", "error", err)
				return
			}
		}
		obj, err := h.store.GetObject(ctx, h.bucket, c.storageRef, opts)
		if err != nil {
			h.logger.Error("drive: content chunk fetch failed", "key", c.storageRef, "error", err)
			return
		}
		if _, err := io.Copy(w, obj); err != nil {
			h.logger.Warn("drive: content stream interrupted", "key", c.storageRef, "error", err)
			_ = obj.Close()
			return
		}
		_ = obj.Close()
	}
}

// driveChunkSize is the fixed v1 chunk size (spec §3.1) — every manifest
// chunk is exactly this size except the file's last chunk.
const driveChunkSize int64 = 4 * 1024 * 1024

// chunkRange maps an absolute file byte offset to its manifest ordinal and
// the byte to skip within that chunk. O(1) because chunkSize is fixed.
func chunkRange(offset, chunkSize int64) (ordinal, skipInChunk int64) {
	return offset / chunkSize, offset % chunkSize
}

// parseSingleRange parses an RFC 7233 "Range: bytes=start-end" header for a
// SINGLE range (a comma — a multipart range request — is rejected: ok=false,
// the caller 416s). Supports "start-end" and the open-ended "start-" form;
// clamps end to size-1. The suffix "-N" (last N bytes) form is not needed by
// any P1 client (chunked upload/download always knows absolute offsets) and
// is deliberately not implemented — ok=false, same 416 as any other
// unsupported form.
func parseSingleRange(header string, size int64) (start, end int64, ok bool) {
	const prefix = "bytes="
	if !strings.HasPrefix(header, prefix) {
		return 0, 0, false
	}
	spec := strings.TrimPrefix(header, prefix)
	if strings.Contains(spec, ",") {
		return 0, 0, false // multipart range — unsupported, 416
	}
	dash := strings.IndexByte(spec, '-')
	if dash <= 0 { // no dash, or a "-N" suffix-length form — both rejected
		return 0, 0, false
	}
	startStr, endStr := spec[:dash], spec[dash+1:]
	start, err := strconv.ParseInt(startStr, 10, 64)
	if err != nil || start < 0 || start >= size {
		return 0, 0, false
	}
	if endStr == "" {
		end = size - 1
	} else {
		end, err = strconv.ParseInt(endStr, 10, 64)
		if err != nil || end < start {
			return 0, 0, false
		}
		if end >= size {
			end = size - 1
		}
	}
	return start, end, true
}
