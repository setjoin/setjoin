package jmap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/minio/minio-go/v7"
	"setjoin.com/mailserver/internal/auth"
	sharedcontinuity "setjoin.com/shared/continuity"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/identity"
)

const maxRecoveryReceiptIDs = 64

type recoveryReceiptArgs struct {
	AccountID string   `json:"accountId"`
	IDs       []string `json:"ids"`
}

type recoveryReceiptAttachment struct {
	BlobID string `json:"blobId"`
	SHA256 string `json:"sha256"`
	Size   string `json:"size"`
	Role   string `json:"role"`
}

type recoveryReceiptRow struct {
	ID          string                      `json:"id"`
	RawRef      string                      `json:"rawRef"`
	ReceivedAt  string                      `json:"receivedAt"`
	Eligibility string                      `json:"eligibility"`
	Attachments []recoveryReceiptAttachment `json:"attachments"`
}

type recoveryReceiptContextResult struct {
	Context continuityContext    `json:"context"`
	List    []recoveryReceiptRow `json:"list"`
}

func decodeStrictJSON(raw json.RawMessage, target any) error {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}

func (h *JMAPHandler) recoveryReceiptContexts(ctx context.Context, mailboxID int64, ids []int64) (recoveryReceiptContextResult, error) {
	raw, err := h.caller.CallScoped(ctx, mailboxID, "continuity_recovery_receipt_context", ids, h.continuity.BootEpoch)
	if err != nil {
		return recoveryReceiptContextResult{}, err
	}
	var result recoveryReceiptContextResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return recoveryReceiptContextResult{}, err
	}
	return result, nil
}

func (h *JMAPHandler) digestObject(ctx context.Context, key string, declaredSize int64) (string, int64, error) {
	if h.minio == nil || key == "" || declaredSize <= 0 {
		return "", 0, fmt.Errorf("recovery object unavailable")
	}
	limit := int64(h.maxUploadSize)
	if limit <= 0 || limit > maxSignSize {
		limit = maxSignSize
	}
	if declaredSize > limit {
		return "", 0, fmt.Errorf("recovery object exceeds limit")
	}
	object, err := h.minio.GetObject(ctx, h.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return "", 0, err
	}
	defer object.Close()
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(object, limit+1))
	if err != nil || written != declaredSize {
		return "", 0, fmt.Errorf("recovery object size mismatch")
	}
	return hex.EncodeToString(hash.Sum(nil)), written, nil
}

func (h *JMAPHandler) emailRecoveryReceipt(ctx context.Context, user *auth.Claims, raw json.RawMessage) (string, json.RawMessage) {
	if !h.continuityEnabled() {
		return marshalResponse("error", Error{Type: "forbidden", Description: "client recovery receipts are disabled"})
	}
	var args recoveryReceiptArgs
	if err := decodeStrictJSON(raw, &args); err != nil || len(args.IDs) == 0 || len(args.IDs) > maxRecoveryReceiptIDs {
		return marshalResponse("error", Error{Type: "invalidArguments", Description: "invalid recovery receipt request"})
	}
	mailboxID, methodErr := h.parseAccountID(ctx, args.AccountID, user.UserID)
	if methodErr != nil {
		return "error", methodErr
	}
	ids := make([]int64, 0, len(args.IDs))
	for _, id := range args.IDs {
		parsed, err := strconv.ParseInt(id, 10, 64)
		if err != nil || parsed <= 0 {
			return marshalResponse("error", Error{Type: "invalidArguments", Description: "invalid recovery message id"})
		}
		ids = append(ids, parsed)
	}
	contexts, err := h.recoveryReceiptContexts(ctx, mailboxID, ids)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "Email/recoveryReceipt")
	}
	found := make(map[string]bool, len(contexts.List))
	list := make([]map[string]any, 0, len(contexts.List))
	for _, row := range contexts.List {
		found[row.ID] = true
		rawBytes, err := h.rawFromRef(ctx, row.RawRef)
		if err != nil || len(rawBytes) == 0 || len(rawBytes) > maxSignSize {
			return marshalResponse("error", Error{Type: "serverFail", Description: "raw MIME is unavailable for recovery"})
		}
		rawDigest := sha256.Sum256(rawBytes)
		blobDigests := make([]sharedcontinuity.BlobDigest, 0, len(row.Attachments))
		for _, attachment := range row.Attachments {
			size, parseErr := strconv.ParseInt(attachment.Size, 10, 64)
			if parseErr != nil || size <= 0 {
				return marshalResponse("error", Error{Type: "serverFail", Description: "attachment metadata is invalid"})
			}
			digest, actualSize, digestErr := h.digestObject(ctx, attachment.BlobID, size)
			if digestErr != nil || digest != attachment.SHA256 || actualSize != size {
				return marshalResponse("error", Error{Type: "serverFail", Description: "attachment bytes failed recovery verification"})
			}
			blobDigests = append(blobDigests, sharedcontinuity.BlobDigest{
				BlobID: attachment.BlobID, SHA256: digest, Size: strconv.FormatInt(actualSize, 10),
			})
		}
		claims := sharedcontinuity.ReceiptClaims{
			InstallationID: contexts.Context.InstallationID,
			AccountID:      args.AccountID, OriginalMessageID: row.ID, Eligibility: row.Eligibility,
			RawMIMESHA256: hex.EncodeToString(rawDigest[:]), RawMIMESize: strconv.Itoa(len(rawBytes)),
			Blobs: blobDigests, TimelineGeneration: contexts.Context.TimelineGeneration,
			StateWatermark: contexts.Context.StateWatermark,
		}
		signed, signErr := h.continuity.SignReceipt(claims)
		if signErr != nil {
			return marshalResponse("error", Error{Type: "serverFail", Description: "recovery receipt signing failed"})
		}
		identity, identityErr := sharedcontinuity.ArtifactIdentity(signed.Claims)
		if identityErr != nil {
			return marshalResponse("error", Error{Type: "serverFail", Description: "recovery identity failed"})
		}
		list = append(list, map[string]any{
			"id": row.ID, "eligibility": row.Eligibility, "receivedAt": row.ReceivedAt,
			"artifactIdentity": identity, "receipt": signed,
			"raw": map[string]any{
				"sha256": signed.Claims.RawMIMESHA256, "size": signed.Claims.RawMIMESize,
				"url": fmt.Sprintf("/jmap/recovery-raw/%s/%s", args.AccountID, row.ID),
			},
			"blobs": row.Attachments,
		})
	}
	notFound := make([]string, 0)
	for _, id := range args.IDs {
		if !found[id] {
			notFound = append(notFound, id)
		}
	}
	return marshalResponse("Email/recoveryReceipt", map[string]any{
		"accountId": args.AccountID, "list": list, "notFound": notFound,
	})
}

func (h *JMAPHandler) authorizeRecoveryAccount(ctx context.Context, accountID int64, userID int64) bool {
	own, grants, err := identity.ValidateAccountID(ctx, h.pool, accountID, userID, h.delegateGrants)
	return err == nil && (own || gateRead.allows(grants))
}

// RecoveryRaw streams exact eligible RFC 5322 bytes only while the receipt
// feature is enabled. It re-authorizes account scope on every request.
func (h *JMAPHandler) RecoveryRaw(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		httputil.WriteProblem(w, r, httputil.NewUnauthorizedProblem("authentication required"))
		return
	}
	if !h.continuityEnabled() {
		WriteProblem(w, http.StatusNotFound, "notFound", "recovery raw endpoint is disabled")
		return
	}
	accountID, accountErr := strconv.ParseInt(r.PathValue("accountId"), 10, 64)
	messageID, messageErr := strconv.ParseInt(r.PathValue("messageId"), 10, 64)
	if accountErr != nil || messageErr != nil || accountID <= 0 || messageID <= 0 ||
		!h.authorizeRecoveryAccount(r.Context(), accountID, user.UserID) {
		WriteProblem(w, http.StatusForbidden, "forbidden", "recovery account access denied")
		return
	}
	contexts, err := h.recoveryReceiptContexts(r.Context(), accountID, []int64{messageID})
	if err != nil || len(contexts.List) != 1 {
		WriteProblem(w, http.StatusNotFound, "emailNotFound", "recoverable message not found")
		return
	}
	raw, err := h.rawFromRef(r.Context(), contexts.List[0].RawRef)
	if err != nil || len(raw) == 0 || len(raw) > maxSignSize {
		WriteProblem(w, http.StatusServiceUnavailable, "serverUnavailable", "raw MIME unavailable")
		return
	}
	w.Header().Set("Content-Type", "message/rfc822")
	w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="recovery-%d.eml"`, messageID))
	httputil.SetUntrustedBlobHeaders(w)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}
