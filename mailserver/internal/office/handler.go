// Package office is the protocol edge for provider-neutral Office editing.
// It parses WOPI, enforces transport limits, and delegates every authority
// decision and durable mutation to office_* / drive_* reducers.
package office

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
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"

	"setjoin.com/mailserver/internal/drive"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/reducererr"
	"setjoin.com/shared/toggle"
)

const (
	maxWOPIFileBytes = int64(200 << 20)
	driveChunkBytes  = 4 << 20
)

type objectStore interface {
	drive.ChunkPromoter
	GetObject(context.Context, string, string, minio.GetObjectOptions) (io.ReadCloser, error)
}

type Handler struct {
	pool   *pgxpool.Pool
	store  objectStore
	bucket string
	flags  *toggle.FeatureFlags
	logger *slog.Logger
	mux    *http.ServeMux
	proof  *proofVerifier
}

func NewHandler(pool *pgxpool.Pool, store objectStore, bucket string, flags *toggle.FeatureFlags, logger *slog.Logger) *Handler {
	h := &Handler{pool: pool, store: store, bucket: bucket, flags: flags, logger: logger, mux: http.NewServeMux(), proof: newProofVerifier(nil)}
	h.mux.HandleFunc("GET /office/wopi/files/{id}", h.checkFileInfo)
	h.mux.HandleFunc("GET /office/wopi/files/{id}/contents", h.getFile)
	h.mux.HandleFunc("POST /office/wopi/files/{id}/contents", h.putFile)
	h.mux.HandleFunc("POST /office/wopi/files/{id}", h.lockOperation)
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.flags.IsEnabled(toggle.FeatureDrive) || !h.flags.IsEnabled(toggle.FeatureOfficeEditing) {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	h.mux.ServeHTTP(w, r)
}

type fileProjection struct {
	LaunchID          uuid.UUID       `json:"launchId"`
	SessionID         uuid.UUID       `json:"sessionId"`
	ActorUserID       int64           `json:"actorUserId"`
	SpaceID           int64           `json:"spaceId"`
	FileNodeID        int64           `json:"fileNodeId"`
	VersionID         int64           `json:"versionId"`
	FenceGeneration   int64           `json:"fenceGeneration"`
	ACLMode           string          `json:"aclMode"`
	ACLEpoch          int64           `json:"aclEpoch"`
	Name              string          `json:"name"`
	Size              int64           `json:"size"`
	ContentType       *string         `json:"contentType"`
	ContentSHA256     string          `json:"contentSha256"`
	CanWrite          bool            `json:"canWrite"`
	Manifest          []manifestChunk `json:"manifest"`
	ProviderID        string          `json:"providerId"`
	ProofMode         string          `json:"proofMode"`
	ProofDiscoveryURL string          `json:"proofDiscoveryUrl"`
	WOPIPublicBaseURL string          `json:"wopiPublicBaseUrl"`
}

type manifestChunk struct {
	StorageRef string `json:"storageRef"`
	SHA256     string `json:"sha256"`
	Size       int64  `json:"size"`
}

func hashToken(raw string) string {
	digest := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(digest[:])
}

func accessToken(r *http.Request) (string, bool) {
	token := r.URL.Query().Get("access_token")
	return token, token != "" && len(token) <= 4096
}

func fileID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid WOPI file id")
		return 0, false
	}
	return id, true
}

func (h *Handler) projection(ctx context.Context, id int64, token string) (fileProjection, error) {
	var raw []byte
	if err := h.pool.QueryRow(ctx, `SELECT office_wopi_file_query($1,$2)`, id, hashToken(token)).Scan(&raw); err != nil {
		return fileProjection{}, err
	}
	var out fileProjection
	if err := json.Unmarshal(raw, &out); err != nil {
		return fileProjection{}, fmt.Errorf("decode WOPI projection: %w", err)
	}
	return out, nil
}

func (h *Handler) authorize(w http.ResponseWriter, r *http.Request) (fileProjection, string, bool) {
	id, ok := fileID(w, r)
	if !ok {
		return fileProjection{}, "", false
	}
	token, ok := accessToken(r)
	if !ok {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "file not found")
		return fileProjection{}, "", false
	}
	p, err := h.projection(r.Context(), id, token)
	if err != nil {
		writeProblem(w, r, err)
		return fileProjection{}, "", false
	}
	if p.ProofMode != "test_disabled" {
		if p.ProofDiscoveryURL == "" || p.WOPIPublicBaseURL == "" ||
			h.proof.verify(r.Context(), r, token, p.ProofDiscoveryURL, p.WOPIPublicBaseURL) != nil {
			h.logger.Warn("office: rejected WOPI proof", "provider_id", p.ProviderID, "file_id", id)
			httputil.WriteProblemStatus(w, http.StatusNotFound, "file not found")
			return fileProjection{}, "", false
		}
	}
	return p, token, true
}

func (h *Handler) checkFileInfo(w http.ResponseWriter, r *http.Request) {
	p, _, ok := h.authorize(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"BaseFileName": p.Name, "OwnerId": strconv.FormatInt(p.SpaceID, 10),
		"Size": p.Size, "UserId": strconv.FormatInt(p.ActorUserID, 10),
		"UserFriendlyName": "Setjoin user", "Version": strconv.FormatInt(p.VersionID, 10),
		"SupportsLocks": true, "SupportsUpdate": true, "UserCanWrite": p.CanWrite,
		"ReadOnly": !p.CanWrite,
	})
}

func (h *Handler) getFile(w http.ResponseWriter, r *http.Request) {
	p, _, ok := h.authorize(w, r)
	if !ok {
		return
	}
	// DATA-INTEGRITY-FAIL-CLOSED (D-MAILSERVER-INTERNAL-OFFICE-003): the WOPI
	// data plane must never present unreadable content as a successful read.
	// All pre-flight checks happen BEFORE the response head is written, so an
	// unavailable manifest, a size disagreement, or a first-chunk open
	// failure is still expressible as a 500.
	var declared int64
	for _, chunk := range p.Manifest {
		declared += chunk.Size
	}
	if len(p.Manifest) == 0 || declared != p.Size {
		h.logger.Error("office: WOPI GetFile manifest is empty or disagrees with the declared size",
			"file_id", p.FileNodeID, "declared_size", p.Size, "manifest_total", declared)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "Office file content is unavailable")
		return
	}
	first, err := h.store.GetObject(r.Context(), h.bucket, p.Manifest[0].StorageRef, minio.GetObjectOptions{})
	if err != nil {
		h.logger.Error("office: WOPI GetFile object read failed", "error", err, "file_id", p.FileNodeID)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "Office file content is unavailable")
		return
	}
	if p.ContentType != nil {
		w.Header().Set("Content-Type", *p.ContentType)
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	w.Header().Set("Content-Length", strconv.FormatInt(p.Size, 10))
	w.Header().Set("X-WOPI-ItemVersion", strconv.FormatInt(p.VersionID, 10))
	w.WriteHeader(http.StatusOK)

	// Stream chunk-by-chunk with per-chunk SHA-256 verification against the
	// manifest. Once the head is written a 500 is no longer expressible, so a
	// store failure, truncation, or substitution mid-stream aborts the
	// connection (http.ErrAbortHandler): the editor observes an incomplete
	// body against the committed Content-Length — never a complete 200 over
	// unproven bytes.
	streamed := int64(0)
	obj := first
	for i, chunk := range p.Manifest {
		if i > 0 {
			var openErr error
			obj, openErr = h.store.GetObject(r.Context(), h.bucket, chunk.StorageRef, minio.GetObjectOptions{})
			if openErr != nil {
				h.logger.Error("office: WOPI GetFile object read failed mid-stream",
					"error", openErr, "file_id", p.FileNodeID, "chunk_index", i)
				panic(http.ErrAbortHandler)
			}
		}
		chunkHash := sha256.New()
		written, copyErr := io.CopyN(io.MultiWriter(w, chunkHash), obj, chunk.Size)
		closeErr := obj.Close()
		if copyErr != nil || closeErr != nil || written != chunk.Size ||
			hex.EncodeToString(chunkHash.Sum(nil)) != chunk.SHA256 {
			h.logger.Error("office: WOPI GetFile stream failed chunk verification",
				"copy_error", copyErr, "close_error", closeErr,
				"written", written, "want", chunk.Size, "file_id", p.FileNodeID, "chunk_index", i)
			panic(http.ErrAbortHandler)
		}
		streamed += written
	}
	if streamed != p.Size {
		h.logger.Error("office: WOPI GetFile streamed size disagrees with manifest",
			"file_id", p.FileNodeID, "streamed", streamed, "declared_size", p.Size)
		panic(http.ErrAbortHandler)
	}
}

func (h *Handler) putFile(w http.ResponseWriter, r *http.Request) {
	p, token, ok := h.authorize(w, r)
	if !ok {
		return
	}
	if !p.CanWrite {
		httputil.WriteProblemStatus(w, http.StatusForbidden, "file is read-only")
		return
	}
	var admitted bool
	if err := h.pool.QueryRow(r.Context(),
		`SELECT office_wopi_callback_allowed($1,$2,'modify_content')`,
		p.LaunchID, hashToken(token)).Scan(&admitted); err != nil {
		writeProblem(w, r, err)
		return
	}
	if !admitted {
		httputil.WriteProblemStatus(w, http.StatusForbidden, "Office write authority is no longer current")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxWOPIFileBytes)
	whole := sha256.New()
	manifest := make([]map[string]any, 0)
	total := int64(0)
	buf := make([]byte, driveChunkBytes)
	for {
		n, readErr := io.ReadFull(r.Body, buf)
		if readErr != nil && !errors.Is(readErr, io.ErrUnexpectedEOF) && !errors.Is(readErr, io.EOF) {
			var tooLarge *http.MaxBytesError
			if errors.As(readErr, &tooLarge) {
				httputil.WriteProblemStatus(w, http.StatusRequestEntityTooLarge, "Office save exceeds 200 MiB")
			} else {
				httputil.WriteProblemStatus(w, http.StatusBadRequest, "Office save body could not be read")
			}
			return
		}
		if n > 0 {
			part := append([]byte(nil), buf[:n]...)
			_, _ = whole.Write(part)
			total += int64(n)
			chunkDigest := sha256.Sum256(part)
			sha := hex.EncodeToString(chunkDigest[:])
			staged, err := drive.StageChunk(r.Context(), h.store, h.bucket, sha, bytes.NewReader(part), int64(n))
			if err != nil {
				h.logger.Error("office: stage WOPI chunk failed", "error", err, "file_id", p.FileNodeID)
				httputil.WriteProblemStatus(w, http.StatusInternalServerError, "Office save staging failed")
				return
			}
			err = dbscope.RunUserScoped(r.Context(), h.pool, p.ActorUserID, func(tx pgx.Tx) error {
				if p.ACLMode == "acl" {
					return drive.CommitStagedChunkBound(r.Context(), tx, h.store, h.bucket,
						p.ActorUserID, p.SpaceID, p.FileNodeID, p.ACLEpoch, staged)
				}
				return drive.CommitStagedChunk(r.Context(), tx, h.store, h.bucket,
					p.ActorUserID, p.SpaceID, staged)
			})
			staged.Cleanup(r.Context(), h.store, h.bucket)
			if err != nil {
				writeProblem(w, r, err)
				return
			}
			manifest = append(manifest, map[string]any{"sha256": staged.SHA256(), "size": int64(staged.Size())})
		}
		if errors.Is(readErr, io.EOF) || errors.Is(readErr, io.ErrUnexpectedEOF) {
			break
		}
	}
	manifestJSON, _ := json.Marshal(manifest)
	contentSHA := hex.EncodeToString(whole.Sum(nil))
	lockHash := nullableHeaderHash(r.Header.Get("X-WOPI-Lock"))
	opKey := strings.TrimSpace(r.Header.Get("X-Setjoin-Operation-Key"))
	if opKey == "" {
		d := sha256.Sum256([]byte(p.LaunchID.String() + ":" + strconv.FormatInt(p.VersionID, 10) + ":" + contentSHA))
		opKey = hex.EncodeToString(d[:])
	}
	var result []byte
	err := h.pool.QueryRow(r.Context(), `SELECT office_save_accept($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		p.LaunchID, hashToken(token), opKey, p.VersionID, contentSHA, total, p.ContentType,
		string(manifestJSON), lockHash).Scan(&result)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	var decoded map[string]any
	if err := json.Unmarshal(result, &decoded); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "Office save result invalid")
		return
	}
	if version, exists := decoded["versionId"]; exists {
		w.Header().Set("X-WOPI-ItemVersion", fmt.Sprint(version))
	}
	writeJSON(w, http.StatusOK, decoded)
}

func nullableHeaderHash(value string) any {
	if value == "" {
		return nil
	}
	return hashToken(value)
}

func (h *Handler) lockOperation(w http.ResponseWriter, r *http.Request) {
	p, token, ok := h.authorize(w, r)
	if !ok {
		return
	}
	override := strings.ToUpper(strings.TrimSpace(r.Header.Get("X-WOPI-Override")))
	lock := r.Header.Get("X-WOPI-Lock")
	if lock == "" || len(lock) > 4096 {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "X-WOPI-Lock is required")
		return
	}
	var out []byte
	err := h.pool.QueryRow(r.Context(), `SELECT office_wopi_lock_apply($1,$2,$3,$4,$5,$6)`,
		p.LaunchID, hashToken(token), override, lock, nullableHeaderValue(r.Header.Get("X-WOPI-OldLock")), 1800).Scan(&out)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	var result struct {
		Conflict    bool   `json:"conflict"`
		CurrentLock string `json:"currentLock"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "Office lock result invalid")
		return
	}
	if result.Conflict {
		w.Header().Set("X-WOPI-Lock", result.CurrentLock)
		w.Header().Set("X-WOPI-LockFailureReason", "The file is locked by another editor session")
		w.WriteHeader(http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func nullableHeaderValue(value string) any {
	if value == "" {
		return nil
	}
	return value
}

var problemOptions = reducererr.ProblemOptions{Namespace: "office", Slugs: map[string]string{
	"BZ321": "not-found", "BZ322": "invalid-arguments", "BZ323": "forbidden",
	"BZ324": "session-stale", "BZ325": "lock-conflict", "BZ326": "replay-conflict",
	"BZ327": "provider-unavailable",
}}

func writeProblem(w http.ResponseWriter, r *http.Request, err error) {
	reducererr.WriteProblem(w, r, err, problemOptions)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
