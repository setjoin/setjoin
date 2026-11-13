package admin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/reducererr"
)

const maxMailboxLifecycleBody = 64 << 10

type mailboxLifecycleCommand struct {
	Action             string `json:"action"`
	ExpectedGeneration string `json:"expectedGeneration"`
	IdempotencyKey     string `json:"idempotencyKey"`
	Reason             string `json:"reason"`
	TargetUserID       string `json:"targetUserId,omitempty"`
	EvidenceKind       string `json:"evidenceKind,omitempty"`
	IdentityLinkID     string `json:"identityLinkId,omitempty"`
	LinkGeneration     string `json:"linkGeneration,omitempty"`
	SourceKeyDigest    string `json:"sourceKeyDigest,omitempty"`
	Delivery           string `json:"delivery,omitempty"`
	RedirectAddress    string `json:"redirectAddress,omitempty"`
}

type mailboxPurgeScheduleCommand struct {
	ExpectedGeneration string `json:"expectedGeneration"`
	PreviewDigest      string `json:"previewDigest"`
	IdempotencyKey     string `json:"idempotencyKey"`
	Reason             string `json:"reason"`
	ApproverUserID     string `json:"approverUserId"`
}

func decodeMailboxLifecycleJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxMailboxLifecycleBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid mailbox lifecycle request")
		return false
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "mailbox lifecycle request must contain one JSON object")
		return false
	}
	return true
}

func mailboxLifecycleReason(w http.ResponseWriter, r *http.Request, reason string) bool {
	if len(reason) < 8 || len(reason) > 1024 || strings.ContainsAny(reason, "\r\n\x00") ||
		strings.TrimSpace(r.Header.Get("X-Audit-Reason")) != reason {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "body reason must exactly match X-Audit-Reason and contain 8-1024 safe characters")
		return false
	}
	return true
}

func mailboxLifecycleKey(w http.ResponseWriter, r *http.Request, bodyKey string) (uuid.UUID, bool) {
	headerKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if headerKey == "" || bodyKey != headerKey {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "body idempotencyKey must exactly match Idempotency-Key")
		return uuid.Nil, false
	}
	key, err := uuid.Parse(headerKey)
	if err != nil || key == uuid.Nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid Idempotency-Key")
		return uuid.Nil, false
	}
	return key, true
}

func mailboxLifecycleID(w http.ResponseWriter, r *http.Request, name string) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	if err != nil || id <= 0 {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid mailbox lifecycle identifier")
		return 0, false
	}
	return id, true
}

func mailboxLifecycleDigest(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func writeMailboxLifecycleRaw(w http.ResponseWriter, raw json.RawMessage) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func (h *UsersHandler) MailboxLifecyclePreview(w http.ResponseWriter, r *http.Request) {
	mailboxID, ok := mailboxLifecycleID(w, r, "id")
	if !ok {
		return
	}
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	var raw json.RawMessage
	if err := h.workerPool.QueryRow(r.Context(), `SELECT mailbox_lifecycle_preview($1,$2)`, claims.UserID, mailboxID).Scan(&raw); err != nil {
		if !reducererr.WriteClassified(w, r, err) {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError, "mailbox lifecycle preview failed")
		}
		return
	}
	writeMailboxLifecycleRaw(w, raw)
}

func (h *UsersHandler) RetainedMailboxes(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	var raw json.RawMessage
	err := h.workerPool.QueryRow(r.Context(), `SELECT mailbox_retained_list($1,$2,$3)`,
		claims.UserID, middleware.DomainScopeFromContext(r.Context()), 200).Scan(&raw)
	if err != nil {
		if reducererr.WriteClassified(w, r, err) {
			return
		}
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "retained mailbox list failed")
		return
	}
	writeMailboxLifecycleRaw(w, raw)
}

func (h *UsersHandler) MailboxLifecycleParity(w http.ResponseWriter, r *http.Request) {
	var raw json.RawMessage
	if err := h.workerPool.QueryRow(r.Context(), `SELECT mailbox_lifecycle_parity_report()`).Scan(&raw); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "mailbox lifecycle parity report failed")
		return
	}
	writeMailboxLifecycleRaw(w, raw)
}

func (h *UsersHandler) MailboxLifecycleTransition(w http.ResponseWriter, r *http.Request) {
	mailboxID, ok := mailboxLifecycleID(w, r, "id")
	if !ok {
		return
	}
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	var req mailboxLifecycleCommand
	if !decodeMailboxLifecycleJSON(w, r, &req) || !mailboxLifecycleReason(w, r, req.Reason) {
		return
	}
	key, ok := mailboxLifecycleKey(w, r, req.IdempotencyKey)
	if !ok {
		return
	}
	generation, err := strconv.ParseInt(req.ExpectedGeneration, 10, 64)
	if err != nil || generation <= 0 {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid expectedGeneration")
		return
	}
	if req.Action != "suspend" && req.Action != "resume" && req.Action != "detach_retain" && req.Action != "reconnect" {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid mailbox lifecycle action")
		return
	}
	parseOptional := func(raw string) (*int64, bool) {
		if raw == "" {
			return nil, true
		}
		value, parseErr := strconv.ParseInt(raw, 10, 64)
		if parseErr != nil || value <= 0 {
			return nil, false
		}
		return &value, true
	}
	target, targetOK := parseOptional(req.TargetUserID)
	linkID, linkOK := parseOptional(req.IdentityLinkID)
	linkGeneration, linkGenerationOK := parseOptional(req.LinkGeneration)
	if !targetOK || !linkOK || !linkGenerationOK {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid reconnect evidence")
		return
	}
	if req.Delivery != "" && req.Delivery != "accepting" && req.Delivery != "rejecting" {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid delivery mode")
		return
	}
	if req.RedirectAddress != "" {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "redirect delivery is not available")
		return
	}
	var authTime *time.Time
	if claims.SessionAuthTime != nil {
		value := time.Unix(*claims.SessionAuthTime, 0).UTC()
		authTime = &value
	}
	var raw json.RawMessage
	err = h.workerPool.QueryRow(r.Context(), `SELECT mailbox_lifecycle_transition(
		$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		claims.UserID, mailboxID, key, req.Action, generation, mailboxLifecycleDigest(req), req.Reason,
		target, emptyStringNil(req.EvidenceKind), linkID, linkGeneration, emptyStringNil(req.SourceKeyDigest),
		authTime, emptyStringNil(req.Delivery), emptyStringNil(req.RedirectAddress)).Scan(&raw)
	if err != nil {
		if !reducererr.WriteClassified(w, r, err) {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError, "mailbox lifecycle transition failed")
		}
		return
	}
	writeMailboxLifecycleRaw(w, raw)
}

func emptyStringNil(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func (h *UsersHandler) MailboxPurgeSchedule(w http.ResponseWriter, r *http.Request) {
	mailboxID, ok := mailboxLifecycleID(w, r, "id")
	if !ok {
		return
	}
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	var req mailboxPurgeScheduleCommand
	if !decodeMailboxLifecycleJSON(w, r, &req) || !mailboxLifecycleReason(w, r, req.Reason) {
		return
	}
	key, ok := mailboxLifecycleKey(w, r, req.IdempotencyKey)
	if !ok {
		return
	}
	generation, genErr := strconv.ParseInt(req.ExpectedGeneration, 10, 64)
	approver, approverErr := strconv.ParseInt(req.ApproverUserID, 10, 64)
	if genErr != nil || generation <= 0 || approverErr != nil || approver <= 0 || len(req.PreviewDigest) != 64 {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid purge schedule request")
		return
	}
	var raw json.RawMessage
	err := h.workerPool.QueryRow(r.Context(), `SELECT mailbox_purge_schedule($1,$2,$3,$4,$5,$6,$7,$8)`,
		claims.UserID, mailboxID, key, generation, strings.ToLower(req.PreviewDigest), mailboxLifecycleDigest(req), req.Reason, approver).Scan(&raw)
	if err != nil {
		if !reducererr.WriteClassified(w, r, err) {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError, "mailbox purge scheduling failed")
		}
		return
	}
	writeMailboxLifecycleRaw(w, raw)
}

func (h *UsersHandler) MailboxPurgeApproval(w http.ResponseWriter, r *http.Request) {
	requestID, ok := mailboxLifecycleID(w, r, "id")
	if !ok {
		return
	}
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	var req struct {
		Decision string `json:"decision"`
		Comment  string `json:"comment"`
	}
	if !decodeMailboxLifecycleJSON(w, r, &req) || (req.Decision != "approve" && req.Decision != "deny") || len(req.Comment) > 1024 {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid purge approval decision")
		return
	}
	var raw json.RawMessage
	if err := h.workerPool.QueryRow(r.Context(), `SELECT mailbox_purge_approval_apply($1,$2,$3,$4)`,
		requestID, claims.UserID, req.Decision, req.Comment).Scan(&raw); err != nil {
		if !reducererr.WriteClassified(w, r, err) {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError, "mailbox purge approval failed")
		}
		return
	}
	writeMailboxLifecycleRaw(w, raw)
}

func (h *UsersHandler) MailboxPurgeExecute(w http.ResponseWriter, r *http.Request) {
	purgeID, err := uuid.Parse(r.PathValue("id"))
	if err != nil || purgeID == uuid.Nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid purge request id")
		return
	}
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	var req struct {
		IdempotencyKey string `json:"idempotencyKey"`
		Reason         string `json:"reason"`
	}
	if !decodeMailboxLifecycleJSON(w, r, &req) || !mailboxLifecycleReason(w, r, req.Reason) {
		return
	}
	key, ok := mailboxLifecycleKey(w, r, req.IdempotencyKey)
	if !ok {
		return
	}
	var raw json.RawMessage
	if err := h.workerPool.QueryRow(r.Context(), `SELECT mailbox_purge_execute($1,$2,$3,$4)`,
		claims.UserID, purgeID, key, mailboxLifecycleDigest(req)).Scan(&raw); err != nil {
		if !reducererr.WriteClassified(w, r, err) {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError, "mailbox purge execution failed")
		}
		return
	}
	writeMailboxLifecycleRaw(w, raw)
}

func (h *UsersHandler) MailboxPurgeCancel(w http.ResponseWriter, r *http.Request) {
	purgeID, err := uuid.Parse(r.PathValue("id"))
	if err != nil || purgeID == uuid.Nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid purge request id")
		return
	}
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	var req struct {
		IdempotencyKey string `json:"idempotencyKey"`
		Reason         string `json:"reason"`
	}
	if !decodeMailboxLifecycleJSON(w, r, &req) || !mailboxLifecycleReason(w, r, req.Reason) {
		return
	}
	key, ok := mailboxLifecycleKey(w, r, req.IdempotencyKey)
	if !ok {
		return
	}
	var raw json.RawMessage
	if err := h.workerPool.QueryRow(r.Context(), `SELECT mailbox_purge_cancel($1,$2,$3,$4,$5)`,
		claims.UserID, purgeID, key, mailboxLifecycleDigest(req), req.Reason).Scan(&raw); err != nil {
		if !reducererr.WriteClassified(w, r, err) {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError, "mailbox purge cancellation failed")
		}
		return
	}
	writeMailboxLifecycleRaw(w, raw)
}
