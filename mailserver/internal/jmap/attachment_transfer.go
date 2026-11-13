package jmap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/identity"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/toggle"
)

const (
	attachmentTokenBodyMaxBytes = 4 << 10
	maxNativeAttachmentBytes    = int64(8) << 30
)

type attachmentTokenRequest struct {
	AccountID string `json:"accountId"`
	SHA256    string `json:"sha256"`
}

type attachmentTokenResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expiresAt"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	Size      string `json:"size"`
	ETag      string `json:"etag"`
}

type effectiveTransferPolicy struct {
	Allowed bool `json:"allowed"`
	SyncQoS struct {
		Mode      string `json:"mode"`
		Effective struct {
			AutomaticNetwork string `json:"automaticNetwork"`
		} `json:"effective"`
	} `json:"syncQoS"`
}

func attachmentPolicyModeHidden(policy effectiveTransferPolicy) bool {
	return policy.SyncQoS.Mode == "off"
}

func decodeAttachmentTokenRequest(w http.ResponseWriter, r *http.Request) (attachmentTokenRequest, error) {
	var req attachmentTokenRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, attachmentTokenBodyMaxBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return req, err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return req, errors.New("request must contain one JSON object")
	}
	if !validBlobSHA256(req.SHA256) {
		return req, errors.New("sha256 must be lowercase 64-hex")
	}
	accountID, err := strconv.ParseInt(req.AccountID, 10, 64)
	if err != nil || accountID <= 0 || strconv.FormatInt(accountID, 10) != req.AccountID {
		return req, errors.New("accountId must be a canonical positive decimal string")
	}
	return req, nil
}

func validBlobSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func (h *JMAPHandler) attachmentFeatureEnabled() bool {
	return h != nil && h.toggles != nil &&
		h.toggles.IsEnabled(toggle.FeatureOfflineMail) &&
		h.toggles.IsEnabled(toggle.FeatureConnectivityAwareSync)
}

func (h *JMAPHandler) transferPolicy(ctx context.Context, mailboxID, deviceID int64) (effectiveTransferPolicy, string, bool) {
	var policy effectiveTransferPolicy
	if h == nil || h.workerPool == nil {
		return policy, "", false
	}
	raw, err := h.workerCaller.Call(ctx, "offline_effective_policy_snapshot", mailboxID, deviceID)
	if err != nil || json.Unmarshal(raw, &policy) != nil {
		return policy, "", false
	}
	digest := sha256.Sum256(raw)
	generation := hex.EncodeToString(digest[:])
	allowed := policy.Allowed && policy.SyncQoS.Mode == "execute" &&
		policy.SyncQoS.Effective.AutomaticNetwork != "never"
	return policy, generation, allowed
}

func (h *JMAPHandler) transferDeviceID(ctx context.Context, userID int64, fingerprint, platform string) (int64, bool) {
	if h == nil || h.workerPool == nil || fingerprint == "" {
		return 0, false
	}
	if platform != "desktop" && platform != "ios" && platform != "android" {
		return 0, false
	}
	var id int64
	err := h.workerPool.QueryRow(ctx,
		`SELECT id FROM user_devices
		  WHERE user_id=$1 AND fingerprint_hash=sha256($2::bytea)
		    AND platform=$3 AND NOT wipe_requested
		  ORDER BY id ASC LIMIT 1`,
		userID, fingerprint, platform).Scan(&id)
	return id, err == nil && id > 0
}

func (h *JMAPHandler) attachmentBlobMetadata(ctx context.Context, sha string) (int64, string, bool) {
	if h == nil || h.workerPool == nil {
		return 0, "", false
	}
	var size int64
	var contentType string
	err := h.workerPool.QueryRow(ctx,
		`SELECT size_bytes, COALESCE(content_type,'application/octet-stream')
		   FROM blobs WHERE sha256=$1 AND size_bytes BETWEEN 0 AND $2`,
		sha, maxNativeAttachmentBytes).Scan(&size, &contentType)
	return size, contentType, err == nil
}

// MintAttachmentTransfer handles POST /api/mail/attachment-transfer-token. Only a normal
// access session may mint; a derived scoped token cannot renew itself.
func (h *JMAPHandler) MintAttachmentTransfer(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.attachmentFeatureEnabled() {
		http.NotFound(w, r)
		return
	}
	if claims.Scp != "" || claims.Attachment != nil || claims.Device == nil || claims.IsGuest() {
		httputil.WriteProblemStatus(w, http.StatusForbidden, "normal native access session required")
		return
	}
	if h.jwt == nil {
		httputil.WriteProblemStatus(w, http.StatusServiceUnavailable, "attachment transfer unavailable")
		return
	}
	req, err := decodeAttachmentTokenRequest(w, r)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid attachment transfer request")
		return
	}
	accountID, _ := strconv.ParseInt(req.AccountID, 10, 64)
	mailboxID, err := identity.ResolvePrimaryMailbox(r.Context(), h.pool, claims.UserID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	deviceID, ok := h.transferDeviceID(r.Context(), claims.UserID, claims.Device.ID, claims.Device.Platform)
	if !ok {
		httputil.WriteProblemStatus(w, http.StatusForbidden, "approved native device required")
		return
	}
	policy, generation, allowed := h.transferPolicy(r.Context(), mailboxID, deviceID)
	if attachmentPolicyModeHidden(policy) {
		http.NotFound(w, r)
		return
	}
	if !allowed {
		httputil.WriteProblemStatus(w, http.StatusForbidden, "attachment transfer is not allowed by current policy")
		return
	}
	if !h.blobDownloadAuthorized(r.Context(), req.AccountID, req.SHA256, claims.UserID) {
		http.NotFound(w, r)
		return
	}
	size, _, ok := h.attachmentBlobMetadata(r.Context(), req.SHA256)
	if !ok {
		http.NotFound(w, r)
		return
	}
	token, expiresAt, err := h.jwt.IssueMailAttachmentToken(claims, jwtutil.AttachmentTransferClaim{
		SHA256:            req.SHA256,
		AccountID:         accountID,
		MailboxID:         mailboxID,
		DeviceID:          deviceID,
		DeviceFingerprint: claims.Device.ID,
		PolicyGeneration:  generation,
	})
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "session cannot mint attachment transfer")
		return
	}
	w.Header().Set("Pragma", "no-cache")
	httputil.WriteJSON(w, http.StatusOK, attachmentTokenResponse{
		Token: token, ExpiresAt: expiresAt.UTC().Format(time.RFC3339),
		Path: "/mail-attachment/" + req.SHA256, SHA256: req.SHA256,
		Size: strconv.FormatInt(size, 10), ETag: `"` + req.SHA256 + `"`,
	})
}

func (h *JMAPHandler) originSessionActive(ctx context.Context, claims *auth.Claims) bool {
	if h == nil || h.workerPool == nil || claims == nil || claims.Attachment == nil ||
		claims.Attachment.OriginJTI == "" || claims.Attachment.OriginIssuedAt <= 0 {
		return false
	}
	var revoked bool
	err := h.workerPool.QueryRow(ctx,
		`SELECT EXISTS(
		   SELECT 1 FROM session_revocations
		    WHERE user_id=$1 AND expires_at>now() AND (
		      (scope='all' AND not_before>=to_timestamp($2)) OR
		      (scope='jti' AND jti=$3) OR
		      (scope='family' AND family_id=$4 AND $4<>'')
		    ))`,
		claims.UserID, claims.Attachment.OriginIssuedAt,
		claims.Attachment.OriginJTI, claims.FamilyID).Scan(&revoked)
	return err == nil && !revoked
}

func (h *JMAPHandler) liveAttachmentBinding(ctx context.Context, claims *auth.Claims) (int64, string, int) {
	if claims == nil || claims.Scp != "mail-attachment" || claims.Attachment == nil ||
		claims.Device == nil || claims.Device.ID != claims.Attachment.DeviceFingerprint ||
		!validBlobSHA256(claims.Attachment.SHA256) || claims.Attachment.AccountID <= 0 ||
		claims.Attachment.MailboxID <= 0 || claims.Attachment.DeviceID <= 0 {
		return 0, "", http.StatusUnauthorized
	}
	if !h.attachmentFeatureEnabled() {
		return 0, "", http.StatusNotFound
	}
	if !h.originSessionActive(ctx, claims) {
		return 0, "", http.StatusUnauthorized
	}
	deviceID, ok := h.transferDeviceID(ctx, claims.UserID, claims.Device.ID, claims.Device.Platform)
	if !ok || deviceID != claims.Attachment.DeviceID {
		return 0, "", http.StatusForbidden
	}
	policy, generation, allowed := h.transferPolicy(ctx, claims.Attachment.MailboxID, deviceID)
	if attachmentPolicyModeHidden(policy) {
		return 0, "", http.StatusNotFound
	}
	if !allowed || generation != claims.Attachment.PolicyGeneration {
		return 0, "", http.StatusConflict
	}
	accountID := strconv.FormatInt(claims.Attachment.AccountID, 10)
	if !h.blobDownloadAuthorized(ctx, accountID, claims.Attachment.SHA256, claims.UserID) {
		return 0, "", http.StatusNotFound
	}
	size, contentType, ok := h.attachmentBlobMetadata(ctx, claims.Attachment.SHA256)
	if !ok {
		return 0, "", http.StatusNotFound
	}
	return size, contentType, 0
}

// DownloadAttachmentTransfer handles the exact one-blob bearer route. Every
// request, including every Range continuation, repeats live session, device,
// policy-generation, ownership, and feature checks before opening object data.
func (h *JMAPHandler) DownloadAttachmentTransfer(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	sha := r.PathValue("sha256")
	if claims == nil || claims.Attachment == nil || sha != claims.Attachment.SHA256 {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "invalid attachment transfer token")
		return
	}
	size, contentType, status := h.liveAttachmentBinding(r.Context(), claims)
	if status != 0 {
		httputil.WriteProblemStatus(w, status, http.StatusText(status))
		return
	}
	if h.minio == nil {
		httputil.WriteProblemStatus(w, http.StatusServiceUnavailable, "attachment storage unavailable")
		return
	}
	obj, err := h.minio.GetObject(r.Context(), h.bucket, sha, minio.GetObjectOptions{})
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer obj.Close()
	info, err := obj.Stat()
	if err != nil || info.Size != size {
		http.NotFound(w, r)
		return
	}
	serveImmutableBlob(w, r, obj, sha, contentType, "attachment", sha)
}
