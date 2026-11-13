package jmap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/minio/minio-go/v7"
)

// assembleAttachmentSubmission, for a draft that carries attachments, loads the draft
// body + its message_attachments, streams each blob from MinIO, assembles the
// multipart/mixed wire message, stores it under its content hash, and returns the new
// blob key for the EmailSubmission processedRefs swap seam.
//
// Returns ("", nil) when there is nothing to assemble (no emailId, draft not found, or
// no attachments). A real failure (blob missing, store error) returns an error so the
// caller drops the creation into notCreated — never send a message missing its
// attachments. R1-scoped by accountID on the BYPASSRLS worker pool (mirrors
// signOneSubmission), so the inline mailbox_id predicate survives the FORCE-RLS flip.
func (h *JMAPHandler) assembleAttachmentSubmission(ctx context.Context, accountID int64, emailID string) (string, error) {
	if emailID == "" {
		return "", nil
	}

	var rawRef string
	var receivedAt time.Time
	var hasAttach bool
	err := h.workerPool.QueryRow(ctx,
		`SELECT raw_ref, received_at, has_attachments FROM messages WHERE id = $1 AND mailbox_id = $2`,
		emailID, accountID,
	).Scan(&rawRef, &receivedAt, &hasAttach)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil // reducer will emit notFound if required
	}
	if err != nil {
		return "", fmt.Errorf("load draft: %w", err)
	}
	if !hasAttach {
		return "", nil
	}

	parts, err := h.loadDraftAttachmentParts(ctx, emailID, receivedAt)
	if err != nil {
		return "", err
	}
	if len(parts) == 0 {
		return "", nil
	}

	wire, err := assembleMixedMIME(rawRef, parts)
	if err != nil {
		return "", fmt.Errorf("assemble mime: %w", err)
	}
	// Store under the content hash (the raw_ref-IS-the-sha256-hex convention the swap
	// seam + outbound worker expect; bare hex, like signOneSubmission).
	sum := sha256.Sum256([]byte(wire))
	key := hex.EncodeToString(sum[:])
	if _, err := h.minio.PutObject(ctx, h.bucket, key,
		strings.NewReader(wire), int64(len(wire)),
		minio.PutObjectOptions{ContentType: "message/rfc822"}); err != nil {
		return "", fmt.Errorf("store assembled message: %w", err)
	}
	return key, nil
}

// loadDraftAttachmentParts loads a draft's message_attachments rows and fetches
// each blob's bytes from MinIO, returning the parts in id order (nil when none).
// Shared by the plain-attachment assembler above and the S/MIME sign/encrypt
// paths (W0/#4 assemble-then-sign): whoever builds the wire, the parts are
// loaded identically. Ownership was already established by the caller's
// R1-scoped draft-row load; the rows here are keyed by that draft's identity.
func (h *JMAPHandler) loadDraftAttachmentParts(ctx context.Context, emailID string, receivedAt time.Time) ([]attachmentPart, error) {
	rows, err := h.workerPool.Query(ctx,
		`SELECT blob_sha256,
		        COALESCE(filename, 'attachment'),
		        COALESCE(content_type, 'application/octet-stream'),
		        COALESCE(disposition, 'attachment'),
		        content_id
		 FROM message_attachments
		 WHERE message_id = $1 AND received_at = $2
		 ORDER BY id`,
		emailID, receivedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("load attachments: %w", err)
	}
	defer rows.Close()

	var parts []attachmentPart
	for rows.Next() {
		var sha, filename, ct, disp string
		var cid *string
		if err := rows.Scan(&sha, &filename, &ct, &disp, &cid); err != nil {
			return nil, err
		}
		obj, err := h.minio.GetObject(ctx, h.bucket, sha, minio.GetObjectOptions{})
		if err != nil {
			return nil, fmt.Errorf("open blob %s: %w", sha, err)
		}
		data, err := io.ReadAll(obj)
		obj.Close()
		if err != nil {
			return nil, fmt.Errorf("read blob %s: %w", sha, err)
		}
		p := attachmentPart{Filename: filename, ContentType: ct, Disposition: disp, Data: data}
		if cid != nil {
			p.ContentID = *cid
		}
		parts = append(parts, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return parts, nil
}
