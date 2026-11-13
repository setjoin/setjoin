package mailrecovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/minio/minio-go/v7"
)

type objectStore interface {
	Put(context.Context, string, io.Reader, int64, string) error
	Get(context.Context, string) (io.ReadCloser, error)
	Remove(context.Context, string) error
}

type minioStore struct {
	client *minio.Client
	bucket string
}

func (store minioStore) Put(ctx context.Context, key string, reader io.Reader, size int64, contentType string) error {
	_, err := store.client.PutObject(ctx, store.bucket, key, reader, size, minio.PutObjectOptions{ContentType: contentType})
	return err
}

func (store minioStore) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	return store.client.GetObject(ctx, store.bucket, key, minio.GetObjectOptions{})
}

func (store minioStore) Remove(ctx context.Context, key string) error {
	return store.client.RemoveObject(ctx, store.bucket, key, minio.RemoveObjectOptions{})
}

type reducerFailure struct{ err error }

func (failure reducerFailure) Error() string { return failure.err.Error() }
func (failure reducerFailure) Unwrap() error { return failure.err }

func parseContentRange(value string) (start, end, total int64, err error) {
	if !strings.HasPrefix(value, "bytes ") || strings.ContainsAny(value, "\r\n") {
		return 0, 0, 0, errors.New("invalid Content-Range")
	}
	rangeAndTotal := strings.Split(strings.TrimPrefix(value, "bytes "), "/")
	if len(rangeAndTotal) != 2 {
		return 0, 0, 0, errors.New("invalid Content-Range")
	}
	bounds := strings.Split(rangeAndTotal[0], "-")
	if len(bounds) != 2 {
		return 0, 0, 0, errors.New("invalid Content-Range")
	}
	start, err = strconv.ParseInt(bounds[0], 10, 64)
	if err != nil || start < 0 || strconv.FormatInt(start, 10) != bounds[0] {
		return 0, 0, 0, errors.New("invalid Content-Range start")
	}
	end, err = strconv.ParseInt(bounds[1], 10, 64)
	if err != nil || end < start || strconv.FormatInt(end, 10) != bounds[1] {
		return 0, 0, 0, errors.New("invalid Content-Range end")
	}
	total, err = strconv.ParseInt(rangeAndTotal[1], 10, 64)
	if err != nil || total <= end || strconv.FormatInt(total, 10) != rangeAndTotal[1] {
		return 0, 0, 0, errors.New("invalid Content-Range total")
	}
	return start, end, total, nil
}

func readBounded(reader io.Reader, maximum int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, errors.New("recovery payload exceeds limit")
	}
	return data, nil
}

func (h *Handler) putChunk(ctx context.Context, userID int64, sessionID uuid.UUID, itemID, contentRange string, body io.Reader) error {
	if itemID == "" || len(itemID) > 256 || strings.ContainsAny(itemID, "/\x00\r\n") {
		return errors.New("invalid recovery item id")
	}
	start, end, total, err := parseContentRange(contentRange)
	if err != nil || end-start+1 > maxChunkBytes {
		return errors.New("invalid or oversized recovery chunk range")
	}
	chunk, err := readBounded(body, maxChunkBytes)
	if err != nil || int64(len(chunk)) != end-start+1 {
		return errors.New("recovery chunk body does not match Content-Range")
	}
	chunkDigest := sha256.Sum256(chunk)
	chunkHex := hex.EncodeToString(chunkDigest[:])

	var incidentID uuid.UUID
	var nextOffset, declaredSize int64
	var itemStatus, sessionStatus string
	var expiresAt time.Time
	err = h.db.QueryRow(ctx, `
		SELECT session.incident_id,item.next_offset,item.declared_size,item.status,session.status,session.expires_at
		  FROM mail_recovery_upload_sessions session
		  JOIN mail_recovery_upload_items item ON item.session_id=session.id
		 WHERE session.id=$1 AND session.uploading_user_id=$2 AND item.item_id=$3`,
		sessionID, userID, itemID).Scan(&incidentID, &nextOffset, &declaredSize, &itemStatus, &sessionStatus, &expiresAt)
	if err != nil {
		return err
	}
	if total != declaredSize || sessionStatus != "uploading" || itemStatus != "uploading" || !expiresAt.After(h.now()) {
		return errors.New("recovery upload item is unavailable")
	}
	var existingSize int
	var existingDigest, existingKey string
	existingErr := h.db.QueryRow(ctx, `
		SELECT size_bytes,encode(sha256,'hex'),object_key
		  FROM mail_recovery_upload_chunks
		 WHERE session_id=$1 AND item_id=$2 AND start_offset=$3`, sessionID, itemID, start).
		Scan(&existingSize, &existingDigest, &existingKey)
	if existingErr == nil {
		if existingSize == len(chunk) && existingDigest == chunkHex {
			return nil
		}
		return errors.New("recovery chunk replay differs")
	}
	if !errors.Is(existingErr, pgx.ErrNoRows) {
		return existingErr
	}
	if start != nextOffset {
		return errors.New("recovery chunk is out of order")
	}
	itemHash := sha256.Sum256([]byte(itemID))
	objectKey := fmt.Sprintf("recovery-quarantine/%s/%s/%s/%d-%s", incidentID, sessionID,
		hex.EncodeToString(itemHash[:]), start, chunkHex)
	if err := h.store.Put(ctx, objectKey, bytes.NewReader(chunk), int64(len(chunk)), "application/octet-stream"); err != nil {
		return err
	}
	var raw json.RawMessage
	err = h.db.QueryRow(ctx, `SELECT mail_recovery_upload_chunk_record($1,$2,$3,$4,$5,$6,$7)`,
		userID, sessionID, itemID, start, len(chunk), chunkHex, objectKey).Scan(&raw)
	if err != nil {
		// shared-object-delete-on-raced-record: the compensating Remove must
		// fire only when NO row was committed. The object key is
		// content-addressed, so a concurrent identical upload can commit a
		// record bound to this same key; deleting blindly would wedge that
		// committed record. Re-select the chunk row: a committed row (ours or
		// a raced twin's) keeps the object; a provably absent row means the
		// object is a pure orphan of this failed call and is safe to remove.
		// On a probe error the object is KEPT — deletion is the dangerous
		// direction, and residue reaping owns true orphans.
		var probeKey string
		probeErr := h.db.QueryRow(ctx, `
			SELECT object_key FROM mail_recovery_upload_chunks
			 WHERE session_id=$1 AND item_id=$2 AND start_offset=$3`,
			sessionID, itemID, start).Scan(&probeKey)
		if errors.Is(probeErr, pgx.ErrNoRows) {
			_ = h.store.Remove(ctx, objectKey)
		}
		return reducerFailure{err: err}
	}
	return nil
}

type uploadChunk struct {
	start  int64
	size   int64
	digest string
	key    string
}

func (h *Handler) commitItem(ctx context.Context, userID int64, sessionID uuid.UUID, itemID string) (map[string]any, error) {
	if itemID == "" || len(itemID) > 256 || strings.ContainsAny(itemID, "/\x00\r\n") {
		return nil, errors.New("invalid recovery item id")
	}
	var expectedDigest, role, status, objectRef string
	var declaredSize int64
	err := h.db.QueryRow(ctx, `
		SELECT encode(item.sha256,'hex'),item.declared_size,item.role,item.status,COALESCE(item.object_ref,'')
		  FROM mail_recovery_upload_sessions session
		  JOIN mail_recovery_upload_items item ON item.session_id=session.id
		 WHERE session.id=$1 AND session.uploading_user_id=$2 AND item.item_id=$3
		   AND session.status IN ('uploading','quarantined')`, sessionID, userID, itemID).
		Scan(&expectedDigest, &declaredSize, &role, &status, &objectRef)
	if err != nil {
		return nil, err
	}
	if status == "verified" {
		return map[string]any{"itemId": itemID, "status": "verified", "objectRef": objectRef, "replayed": true}, nil
	}
	rows, err := h.db.Query(ctx, `
		SELECT start_offset,size_bytes,encode(sha256,'hex'),object_key
		  FROM mail_recovery_upload_chunks
		 WHERE session_id=$1 AND item_id=$2 ORDER BY start_offset`, sessionID, itemID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	chunks := make([]uploadChunk, 0, int(declaredSize/int64(maxChunkBytes))+1)
	for rows.Next() {
		var chunk uploadChunk
		if err := rows.Scan(&chunk.start, &chunk.size, &chunk.digest, &chunk.key); err != nil {
			return nil, err
		}
		chunks = append(chunks, chunk)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	temporary, err := os.CreateTemp("", "setjoin-recovery-item-*")
	if err != nil {
		return nil, err
	}
	temporaryName := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryName)
	}()
	_ = temporary.Chmod(0o600)
	fullHash := sha256.New()
	var expectedOffset int64
	for _, chunk := range chunks {
		if chunk.start != expectedOffset || chunk.size <= 0 || chunk.size > maxChunkBytes {
			return nil, errors.New("recovery chunk manifest is not contiguous")
		}
		object, err := h.store.Get(ctx, chunk.key)
		if err != nil {
			return nil, err
		}
		chunkHash := sha256.New()
		written, copyErr := io.Copy(io.MultiWriter(temporary, fullHash, chunkHash), io.LimitReader(object, chunk.size+1))
		closeErr := object.Close()
		if copyErr != nil || closeErr != nil || written != chunk.size || hex.EncodeToString(chunkHash.Sum(nil)) != chunk.digest {
			return nil, errors.New("recovery quarantine chunk verification failed")
		}
		expectedOffset += chunk.size
	}
	if expectedOffset != declaredSize || hex.EncodeToString(fullHash.Sum(nil)) != expectedDigest {
		return nil, errors.New("assembled recovery item digest or size differs")
	}
	if _, err := temporary.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	contentType := "application/octet-stream"
	if role == "raw" {
		contentType = "message/rfc822"
	}
	if err := h.store.Put(ctx, expectedDigest, temporary, declaredSize, contentType); err != nil {
		return nil, err
	}
	var resultJSON json.RawMessage
	if err := h.db.QueryRow(ctx, `SELECT mail_recovery_upload_item_verify($1,$2,$3,$4)`,
		userID, sessionID, itemID, expectedDigest).Scan(&resultJSON); err != nil {
		return nil, reducerFailure{err: err}
	}
	for _, chunk := range chunks {
		if err := h.store.Remove(ctx, chunk.key); err != nil {
			h.logger.Warn("recovery chunk cleanup deferred", "key", chunk.key, "error", err)
		}
	}
	var result map[string]any
	_ = json.Unmarshal(resultJSON, &result)
	result["objectRef"] = expectedDigest
	return result, nil
}

func (h *Handler) finalize(ctx context.Context, userID int64, sessionID uuid.UUID) (map[string]any, error) {
	var rawRef, eligibility, status string
	var rawSize int64
	err := h.db.QueryRow(ctx, `
		SELECT item.object_ref,item.declared_size,session.eligibility,session.status
		  FROM mail_recovery_upload_sessions session
		  JOIN mail_recovery_upload_items item ON item.session_id=session.id AND item.role='raw'
		 WHERE session.id=$1 AND session.uploading_user_id=$2`, sessionID, userID).
		Scan(&rawRef, &rawSize, &eligibility, &status)
	if err != nil {
		return nil, err
	}
	if status == "quarantined" || status == "deduplicated" || status == "rejected" {
		var id uuid.UUID
		var artifactStatus string
		if err := h.db.QueryRow(ctx, `
			SELECT artifact.id,artifact.status
			  FROM mail_recovery_quarantine_artifacts artifact
			 WHERE artifact.session_id=$1
			 UNION ALL
			SELECT ledger.quarantine_id,
			       CASE WHEN session.status='deduplicated' THEN 'deduplicated' ELSE ledger.outcome END
			  FROM mail_recovery_upload_sessions session
			  JOIN mail_recovery_ledger ledger ON ledger.artifact_identity=session.artifact_identity
			 WHERE session.id=$1 AND session.status='deduplicated'
			 LIMIT 1`, sessionID).
			Scan(&id, &artifactStatus); err == nil {
			return map[string]any{"id": id.String(), "status": artifactStatus, "replayed": true}, nil
		}
	}
	if rawRef == "" || rawSize <= 0 || rawSize > maxRawMIMEBytes {
		return nil, errors.New("verified raw MIME item is unavailable")
	}
	object, err := h.store.Get(ctx, rawRef)
	if err != nil {
		return nil, err
	}
	raw, readErr := readBounded(object, rawSize)
	closeErr := object.Close()
	if readErr != nil || closeErr != nil || int64(len(raw)) != rawSize {
		return nil, errors.New("raw MIME quarantine object is incomplete")
	}
	if h.scanner == nil {
		return nil, errors.New("malware scanner is required before recovery quarantine")
	}
	virus, err := h.scanner.Scan(raw)
	if err != nil {
		return nil, fmt.Errorf("malware scan failed closed: %w", err)
	}
	malwareStatus := "clean"
	rejectionReason := ""
	if virus != "" {
		malwareStatus = "infected"
		rejectionReason = "malware_detected"
	}
	parsed, parseErr := parseRecoveredMessage(raw, eligibility, h.now())
	if parseErr != nil {
		rejectionReason = "malformed_message"
		parsed = parsedMessage{Eligibility: eligibility}
	}
	parsedJSON, _ := json.Marshal(parsed)
	quarantineID := uuid.New()
	var resultJSON json.RawMessage
	if err := h.db.QueryRow(ctx, `SELECT mail_recovery_artifact_quarantine($1,$2,$3,$4::jsonb,$5,$6)`,
		userID, sessionID, quarantineID, parsedJSON, malwareStatus, nullableString(rejectionReason)).Scan(&resultJSON); err != nil {
		return nil, reducerFailure{err: err}
	}
	var result map[string]any
	_ = json.Unmarshal(resultJSON, &result)
	return result, nil
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}
