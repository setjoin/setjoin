package drive

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/minio/minio-go/v7"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
)

// maxChunkBytes is the fixed chunk size the spec locks P1 to (spec §3.1) —
// enforced server-side via http.MaxBytesReader so a client cannot bypass the
// client-side 4 MiB split.
const maxChunkBytes = 4 * 1024 * 1024

// chunkShaRe matches a lowercase hex SHA-256 — the only valid chunk key
// (mirrors blob's blobHashRe; drive keeps its own copy rather than importing
// blob, to avoid a cross-package dependency for one regexp literal).
var chunkShaRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// objectStore is the drive package's storage seam — the blob/handler.go seam
// (tmp-upload-then-promote), with ONE deliberate narrowing: GetObject returns
// io.ReadCloser, not the concrete *minio.Object blob's identical interface
// returns. content.go's Range-streaming test double cannot fabricate a real
// *minio.Object (no live MinIO in unit tests); io.ReadCloser is trivially
// fakeable (batch-1 correction #5). MinioStore below adapts *minio.Client to
// this narrower shape.
type objectStore interface {
	PutObject(ctx context.Context, bucket, object string, reader io.Reader, size int64, opts minio.PutObjectOptions) (minio.UploadInfo, error)
	CopyObject(ctx context.Context, dst minio.CopyDestOptions, src minio.CopySrcOptions) (minio.UploadInfo, error)
	RemoveObject(ctx context.Context, bucket, object string, opts minio.RemoveObjectOptions) error
	GetObject(ctx context.Context, bucket, object string, opts minio.GetObjectOptions) (io.ReadCloser, error)
	ListObjects(ctx context.Context, bucket string, opts minio.ListObjectsOptions) <-chan minio.ObjectInfo
}

// MinioStore adapts *minio.Client to objectStore. *minio.Client's real
// GetObject returns the concrete *minio.Object; Go's structural typing does
// NOT let a narrower-interface caller accept a wider concrete return type, so
// this one method needs an explicit adapter (PutObject/CopyObject/
// RemoveObject/ListObjects already match exactly and are promoted as-is).
type MinioStore struct{ *minio.Client }

func (m MinioStore) GetObject(ctx context.Context, bucket, object string, opts minio.GetObjectOptions) (io.ReadCloser, error) {
	return m.Client.GetObject(ctx, bucket, object, opts)
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// uploadScopeForSpace is the pre-storage half of drive_chunk_register's
// authorization. Guest G4 denies every guest upload independently of its
// derived role, so checking membership alone before PromoteChunk could write
// an unclaimable canonical object and only then fail BZ140 at registration.
// The reducer is single-homed: drive_chunk_register calls the same function
// again inside CommitStagedChunk, closing role-revocation races before it
// promotes canonical bytes or writes the claim.
func (h *Handler) uploadScopeForSpace(ctx context.Context, tx pgx.Tx, userID, spaceID int64) (string, error) {
	var scope string
	err := tx.QueryRow(ctx, `SELECT drive_chunk_upload_require($1, $2)`, userID, spaceID).Scan(&scope)
	return scope, err
}

func uploadBindingFromQuery(w http.ResponseWriter, r *http.Request) (targetID, epoch int64, bound bool, ok bool) {
	targetRaw, epochRaw := r.URL.Query().Get("target"), r.URL.Query().Get("aclEpoch")
	if targetRaw == "" && epochRaw == "" {
		return 0, 0, false, true
	}
	targetID, targetErr := strconv.ParseInt(targetRaw, 10, 64)
	epoch, epochErr := strconv.ParseInt(epochRaw, 10, 64)
	if targetErr != nil || epochErr != nil || targetID <= 0 || epoch < 0 {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "target and aclEpoch must be valid decimal integers")
		return 0, 0, false, false
	}
	return targetID, epoch, true, true
}

// requireSpaceParam parses the mandatory ?space= query param shared by the
// chunk routes. Invalid/absent input 400s before any DB or storage call.
func requireSpaceParam(w http.ResponseWriter, r *http.Request) (int64, bool) {
	spaceID, err := strconv.ParseInt(r.URL.Query().Get("space"), 10, 64)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "space query param is required")
		return 0, false
	}
	return spaceID, true
}

// headChunk answers the I-4 anti-oracle existence probe (spec §3.3): 200 iff
// the chunk exists AND the caller can prove possession (an upload claim of
// their own, or membership in a space that already references it via a
// currently history-visible version manifest) — 404 in EVERY other case, including "the chunk exists
// but you have no proof", so an existence check can never leak whether some
// OTHER tenant already holds identical bytes.
func (h *Handler) headChunk(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	sha := r.PathValue("sha256")
	if !chunkShaRe.MatchString(sha) {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid sha256")
		return
	}
	spaceID, ok := requireSpaceParam(w, r)
	if !ok {
		return
	}
	targetID, aclEpoch, bound, ok := uploadBindingFromQuery(w, r)
	if !ok {
		return
	}

	ctx := r.Context()
	var exists bool
	dbErr := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT EXISTS (
			  SELECT 1 FROM drive_chunks c
			  WHERE c.scope_key = (SELECT CASE WHEN s.classification='regular' THEN 'g' ELSE 's'||s.id END
			                         FROM drive_spaces s
			                        WHERE s.id = $2 AND drive_user_has_space_access($1,s.id))
			    AND c.sha256 = $3
			    AND (EXISTS (SELECT 1 FROM drive_upload_claims uc JOIN drive_spaces us ON us.id=$2
			                  WHERE us.acl_mode<>'acl' AND uc.scope_key=c.scope_key
			                    AND uc.sha256=c.sha256 AND uc.user_id=$1)
			      OR EXISTS (SELECT 1 FROM drive_upload_authorizations ua
			                  WHERE ua.scope_key=c.scope_key AND ua.sha256=c.sha256
			                    AND ua.user_id=$1 AND ua.space_id=$2 AND ua.expires_at>now()
			                    AND ($4::bigint IS NULL OR ua.target_node_id=$4)
			                    AND ($5::bigint IS NULL OR ua.acl_epoch=$5))
			      OR EXISTS (SELECT 1 FROM drive_version_chunks vc
			                  JOIN drive_file_versions v ON v.id = vc.version_id
			                 WHERE vc.scope_key = c.scope_key AND vc.chunk_sha256 = c.sha256
			                   AND drive_runtime_has_node_capability($1,v.file_node_id,'download')
			                   -- GUEST_HISTORY_FLOOR: drive_chunk_head
			                   AND `+chatAttachmentLiveSQL("v.id", "$1")+`)))`,
			claims.UserID, spaceID, sha,
			func() any {
				if bound {
					return targetID
				}
				return nil
			}(),
			func() any {
				if bound {
					return aclEpoch
				}
				return nil
			}()).Scan(&exists)
	})
	if dbErr != nil {
		writeDriveProblem(w, r, dbErr)
		return
	}
	if !exists {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "chunk not found")
		return
	}
	w.WriteHeader(http.StatusOK)
}

// putChunk is the tmp→verify→promote pipeline (spec §3.3, the blob/handler.go
// pattern): stream to a random temp key while hashing, verify the client-
// declared sha256 against the computed one, promote to the canonical
// drive/<scope>/<sha> key via CopyObject (never PutObject the canonical key
// directly — the same cross-tenant-dedup-safety reason blob.Put documents),
// then register the chunk via the reducer (server-side scope + role + size
// validation, upload-claim proof-of-possession for I-4).
func (h *Handler) putChunk(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	sha := r.PathValue("sha256")
	if !chunkShaRe.MatchString(sha) {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid sha256")
		return
	}
	spaceID, ok := requireSpaceParam(w, r)
	if !ok {
		return
	}
	targetID, aclEpoch, bound, ok := uploadBindingFromQuery(w, r)
	if !ok {
		return
	}

	ctx := r.Context()
	// Reject unauthorized callers before writing even a temporary object. The
	// same reducer runs again in CommitStagedChunk, after staging, so a role or
	// guest-status change during the upload still fails closed.
	scopeErr := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		var err error
		if bound {
			_, err = authorizeBoundUpload(ctx, tx, claims.UserID, spaceID, targetID, aclEpoch)
		} else {
			_, err = h.uploadScopeForSpace(ctx, tx, claims.UserID, spaceID)
		}
		return err
	})
	if scopeErr != nil {
		writeDriveProblem(w, r, scopeErr)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxChunkBytes)
	staged, err := StageChunk(ctx, h.store, h.bucket, sha, r.Body, -1)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		switch {
		case errors.As(err, &maxBytesErr):
			httputil.WriteProblemStatus(w, http.StatusRequestEntityTooLarge, "chunk exceeds the 4 MiB limit")
		case errors.Is(err, errChunkMismatch):
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "sha256 mismatch")
		case errors.Is(err, errChunkSize):
			httputil.WriteProblemStatus(w, http.StatusUnprocessableEntity, "chunk size must be 1..4194304 bytes")
		default:
			h.logger.Error("drive: chunk store failed", "sha256", sha, "error", err)
			httputil.WriteProblemStatus(w, http.StatusInternalServerError, "upload failed")
		}
		return
	}
	defer staged.Cleanup(ctx, h.store, h.bucket)

	var storeErr error
	regErr := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		if bound {
			storeErr = CommitStagedChunkBound(ctx, tx, h.store, h.bucket,
				claims.UserID, spaceID, targetID, aclEpoch, staged)
		} else {
			storeErr = CommitStagedChunk(ctx, tx, h.store, h.bucket, claims.UserID, spaceID, staged)
		}
		return storeErr
	})
	if regErr != nil {
		var storageFailure *chunkStorageError
		if errors.As(storeErr, &storageFailure) {
			h.logger.Error("drive: chunk store failed", "sha256", sha, "error", storeErr)
			httputil.WriteProblemStatus(w, http.StatusInternalServerError, "upload failed")
			return
		}
		writeDriveProblem(w, r, regErr)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// errChunkMismatch is PromoteChunk's sentinel for "computed sha256 != want" —
// the client-supplied URL hash did not match the actual body.
var errChunkMismatch = errors.New("drive: chunk sha256 mismatch")
var errChunkSize = errors.New("drive: chunk size out of range")

// ChunkPromoter is the narrow store surface PromoteChunk needs — exported so
// the meet ingest (worker plane, meet/worker.go) reuses the ONE
// tmp→verify→promote path instead of cloning it (single-homed; the canonical
// content-addressed key is only ever written via CopyObject, the blob.Put
// cross-tenant-dedup rule).
type ChunkPromoter interface {
	PutObject(ctx context.Context, bucket, object string, reader io.Reader, size int64, opts minio.PutObjectOptions) (minio.UploadInfo, error)
	CopyObject(ctx context.Context, dst minio.CopyDestOptions, src minio.CopySrcOptions) (minio.UploadInfo, error)
	RemoveObject(ctx context.Context, bucket, object string, opts minio.RemoveObjectOptions) error
}

// StagedChunk is a hash-verified tmp/upload object awaiting its canonical
// promotion. Its fields stay private so callers cannot manufacture a staged
// value that bypasses StageChunk's hash and size checks.
type StagedChunk struct {
	tempKey string
	sha256  string
	size    int32
}

// SHA256 and Size expose only the verified manifest facts needed by another
// trusted ingest adapter (currently the Office WOPI host). Callers still cannot
// construct a StagedChunk or bypass StageChunk/CommitStagedChunkBound.
func (s StagedChunk) SHA256() string { return s.sha256 }

// Size returns the authoritative number of bytes the object store accepted.
func (s *StagedChunk) Size() int32 { return s.size }

// Cleanup removes the temporary object. It is deliberately best-effort: the
// 24-hour tmp reaper is the crash/retry backstop.
func (s *StagedChunk) Cleanup(ctx context.Context, store ChunkPromoter, bucket string) {
	_ = store.RemoveObject(ctx, bucket, s.tempKey, minio.RemoveObjectOptions{})
}

// StageChunk streams a body to a random temporary key while hashing and
// validates both the declared SHA-256 and the fixed Drive chunk-size bound.
// No canonical object is written here, so this phase does not need a database
// transaction or distributed lock.
func StageChunk(ctx context.Context, store ChunkPromoter, bucket, want string, body io.Reader, size int64) (*StagedChunk, error) {
	if size != -1 && (size < 1 || size > maxChunkBytes) {
		return nil, fmt.Errorf("%w: %d not in (0, %d]", errChunkSize, size, maxChunkBytes)
	}
	hasher := sha256.New()
	tee := io.TeeReader(body, hasher)

	tempKey := "tmp/upload/" + randomHex(16)
	info, err := store.PutObject(ctx, bucket, tempKey, tee, size, minio.PutObjectOptions{ContentType: "application/octet-stream"})
	if err != nil {
		return nil, err
	}

	computed := hex.EncodeToString(hasher.Sum(nil))
	if computed != want {
		_ = store.RemoveObject(ctx, bucket, tempKey, minio.RemoveObjectOptions{})
		return nil, errChunkMismatch
	}
	if info.Size < 1 || info.Size > maxChunkBytes {
		_ = store.RemoveObject(ctx, bucket, tempKey, minio.RemoveObjectOptions{})
		return nil, fmt.Errorf("%w: %d not in (0, %d]", errChunkSize, info.Size, maxChunkBytes)
	}
	return &StagedChunk{tempKey: tempKey, sha256: want, size: int32(info.Size)}, nil
}

// lockChunkTx is the single cross-process serialization key shared by every
// canonical Drive object producer and remover. It is transaction-scoped, so
// it is safe behind PgBouncer transaction pooling and cannot leak to the next
// pooled request. A 64-bit hash collision only causes harmless extra waiting.
func lockChunkTx(ctx context.Context, tx pgx.Tx, scope, sha string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('drive-chunk:' || $1::text || ':' || $2::text, 0))`, scope, sha)
	return err
}

type chunkStorageError struct{ err error }

func (e *chunkStorageError) Error() string { return e.err.Error() }
func (e *chunkStorageError) Unwrap() error { return e.err }

// CommitStagedChunk promotes a verified tmp object and registers it inside
// the caller's transaction. drive_chunk_upload_require rechecks authority and
// locks the space row, freezing the classification-derived scope until commit;
// the advisory lock serializes this canonical key against GC and inventory.
// Callers MUST commit or roll back this same tx only after this function
// returns. A reducer failure can leave canonical bytes without a row; the
// canonical orphan inventory owns that safe, delayed cleanup.
func CommitStagedChunk(ctx context.Context, tx pgx.Tx, store ChunkPromoter, bucket string, userID, spaceID int64, staged *StagedChunk) error {
	var scope string
	if err := tx.QueryRow(ctx, `SELECT drive_chunk_upload_require($1, $2)`, userID, spaceID).Scan(&scope); err != nil {
		return err
	}
	if err := lockChunkTx(ctx, tx, scope, staged.sha256); err != nil {
		return err
	}
	if err := promoteStagedChunk(ctx, store, bucket, scope, staged); err != nil {
		return &chunkStorageError{err: err}
	}
	_, err := tx.Exec(ctx, `SELECT drive_chunk_register($1, $2, $3, $4)`, userID, spaceID, staged.sha256, staged.size)
	return err
}

func authorizeBoundUpload(ctx context.Context, tx pgx.Tx, userID, spaceID, targetID, epoch int64) (string, error) {
	var scope string
	err := tx.QueryRow(ctx, `SELECT CASE WHEN s.classification='regular' THEN 'g' ELSE 's'||s.id END
		FROM drive_nodes n JOIN drive_spaces s ON s.id=n.space_id
		JOIN drive_acl_generations g ON g.space_id=s.id
		WHERE n.id=$3 AND n.space_id=$2 AND s.acl_mode='acl' AND g.epoch=$4
		  AND drive_runtime_has_node_capability($1,n.id,
		      CASE WHEN n.kind='folder' THEN 'create_child' ELSE 'modify_content' END)`,
		userID, spaceID, targetID, epoch).Scan(&scope)
	return scope, err
}

func CommitStagedChunkBound(ctx context.Context, tx pgx.Tx, store ChunkPromoter, bucket string,
	userID, spaceID, targetID, epoch int64, staged *StagedChunk) error {
	scope, err := authorizeBoundUpload(ctx, tx, userID, spaceID, targetID, epoch)
	if err != nil {
		return err
	}
	if err := lockChunkTx(ctx, tx, scope, staged.sha256); err != nil {
		return err
	}
	if err := promoteStagedChunk(ctx, store, bucket, scope, staged); err != nil {
		return &chunkStorageError{err: err}
	}
	_, err = tx.Exec(ctx, `SELECT drive_chunk_register_bound($1,$2,$3,$4,$5,$6)`,
		userID, spaceID, targetID, epoch, staged.sha256, staged.size)
	return err
}

func promoteStagedChunk(ctx context.Context, store ChunkPromoter, bucket, scope string, staged *StagedChunk) error {
	destKey := "drive/" + scope + "/" + staged.sha256
	src := minio.CopySrcOptions{Bucket: bucket, Object: staged.tempKey}
	dst := minio.CopyDestOptions{Bucket: bucket, Object: destKey}
	_, err := store.CopyObject(ctx, dst, src)
	return err
}
