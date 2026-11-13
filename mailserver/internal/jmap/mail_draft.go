package jmap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"time"

	"github.com/google/uuid"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/toggle"
)

func (h *JMAPHandler) mailDraftEnabled() bool {
	return h.toggles != nil && h.toggles.IsEnabled(toggle.FeatureSharedMailDrafts)
}

func mailDraftDisabled() (string, json.RawMessage) {
	return methodError("serverUnavailable", "shared mail drafts are not enabled")
}

func mailDraftDigest(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func parseMailDraftID(raw, name string) (int64, *Error) {
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		return 0, &Error{Type: "invalidArguments", Description: name + " must be a positive decimal string"}
	}
	return value, nil
}

func (h *JMAPHandler) mailDraftGet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	if !h.mailDraftEnabled() {
		return mailDraftDisabled()
	}
	var req struct {
		AccountID string   `json:"accountId"`
		IDs       []string `json:"ids,omitempty"`
	}
	if err := json.Unmarshal(args, &req); err != nil || len(req.IDs) > 256 {
		return methodError("invalidArguments", "invalid shared draft query")
	}
	ids := make([]uuid.UUID, 0, len(req.IDs))
	for _, raw := range req.IDs {
		id, err := uuid.Parse(raw)
		if err != nil || id == uuid.Nil {
			return methodError("invalidArguments", "ids must contain non-zero UUIDs")
		}
		ids = append(ids, id)
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	var idArg any
	if req.IDs != nil {
		idArg = ids
	}
	result, err := h.caller.CallScoped(ctx, accountID, "mail_draft_get", user.UserID, idArg)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "mailDraftGet")
	}
	return "MailDraft/get", result
}

func (h *JMAPHandler) mailDraftOpen(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	if !h.mailDraftEnabled() {
		return mailDraftDisabled()
	}
	var req struct {
		AccountID   string `json:"accountId"`
		OperationID string `json:"operationId"`
		MessageID   string `json:"messageId"`
		ReceivedAt  string `json:"receivedAt"`
		FinalSender string `json:"finalSenderAddress"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	op, err := uuid.Parse(req.OperationID)
	messageID, idErr := parseMailDraftID(req.MessageID, "messageId")
	receivedAt, timeErr := time.Parse(time.RFC3339Nano, req.ReceivedAt)
	if err != nil || op == uuid.Nil || idErr != nil || timeErr != nil {
		return methodError("invalidArguments", "operationId, messageId and receivedAt are required")
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	result, callErr := h.caller.CallScoped(ctx, accountID, "mail_draft_session_open", user.UserID,
		op, messageID, receivedAt, req.FinalSender, mailDraftDigest(req))
	if callErr != nil {
		return "error", mapReducerErr(callErr, h.logger, "mailDraftOpen")
	}
	return "MailDraft/open", result
}

func (h *JMAPHandler) mailDraftLease(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	if !h.mailDraftEnabled() {
		return mailDraftDisabled()
	}
	var req struct {
		AccountID     string  `json:"accountId"`
		OperationID   string  `json:"operationId"`
		ID            string  `json:"id"`
		Action        string  `json:"action"`
		ExpectedEpoch string  `json:"expectedEpoch"`
		TargetUserID  *string `json:"targetUserId,omitempty"`
		Reason        string  `json:"reason"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	op, opErr := uuid.Parse(req.OperationID)
	id, idErr := uuid.Parse(req.ID)
	epoch, epochErr := strconv.ParseInt(req.ExpectedEpoch, 10, 64)
	if opErr != nil || op == uuid.Nil || idErr != nil || id == uuid.Nil || epochErr != nil || epoch < 1 {
		return methodError("invalidArguments", "invalid shared draft lease tuple")
	}
	var target any
	if req.TargetUserID != nil {
		value, parseErr := parseMailDraftID(*req.TargetUserID, "targetUserId")
		if parseErr != nil {
			return methodError(parseErr.Type, parseErr.Description)
		}
		target = value
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	result, callErr := h.caller.CallScoped(ctx, accountID, "mail_draft_lease_action", user.UserID,
		op, id, req.Action, epoch, target, req.Reason, mailDraftDigest(req))
	if callErr != nil {
		return "error", mapReducerErr(callErr, h.logger, "mailDraftLease")
	}
	return "MailDraft/lease", result
}

func (h *JMAPHandler) mailDraftSave(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	if !h.mailDraftEnabled() {
		return mailDraftDisabled()
	}
	var req struct {
		AccountID        string `json:"accountId"`
		OperationID      string `json:"operationId"`
		ID               string `json:"id"`
		ExpectedEpoch    string `json:"expectedEpoch"`
		BaseRevision     string `json:"baseRevision"`
		MessageID        string `json:"messageId"`
		ReceivedAt       string `json:"receivedAt"`
		ContentDigest    string `json:"contentDigest"`
		AttachmentDigest string `json:"attachmentDigest"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	op, opErr := uuid.Parse(req.OperationID)
	id, idErr := uuid.Parse(req.ID)
	epoch, epochErr := strconv.ParseInt(req.ExpectedEpoch, 10, 64)
	revision, revisionErr := strconv.ParseInt(req.BaseRevision, 10, 64)
	messageID, messageErr := strconv.ParseInt(req.MessageID, 10, 64)
	receivedAt, timeErr := time.Parse(time.RFC3339Nano, req.ReceivedAt)
	if opErr != nil || op == uuid.Nil || idErr != nil || id == uuid.Nil || epochErr != nil || epoch < 1 ||
		revisionErr != nil || revision < 1 || messageErr != nil || messageID <= 0 || timeErr != nil ||
		len(req.ContentDigest) != 64 || len(req.AttachmentDigest) != 64 {
		return methodError("invalidArguments", "invalid shared draft revision tuple")
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	result, callErr := h.caller.CallScoped(ctx, accountID, "mail_draft_revision_accept", user.UserID,
		op, id, epoch, revision, messageID, receivedAt, req.ContentDigest, req.AttachmentDigest, mailDraftDigest(req))
	if callErr != nil {
		return "error", mapReducerErr(callErr, h.logger, "mailDraftSave")
	}
	return "MailDraft/save", result
}

func (h *JMAPHandler) mailDraftReplace(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	if !h.mailDraftEnabled() {
		return mailDraftDisabled()
	}
	var req struct {
		AccountID     string          `json:"accountId"`
		OperationID   string          `json:"operationId"`
		ID            string          `json:"id"`
		ExpectedEpoch string          `json:"expectedEpoch"`
		BaseRevision  string          `json:"baseRevision"`
		Draft         json.RawMessage `json:"draft"`
	}
	if err := json.Unmarshal(args, &req); err != nil || len(req.Draft) == 0 || len(req.Draft) > 1<<20 {
		return methodError("invalidArguments", "invalid shared draft replacement")
	}
	op, opErr := uuid.Parse(req.OperationID)
	id, idErr := uuid.Parse(req.ID)
	epoch, epochErr := strconv.ParseInt(req.ExpectedEpoch, 10, 64)
	revision, revisionErr := strconv.ParseInt(req.BaseRevision, 10, 64)
	if opErr != nil || op == uuid.Nil || idErr != nil || id == uuid.Nil || epochErr != nil || epoch < 1 ||
		revisionErr != nil || revision < 1 {
		return methodError("invalidArguments", "invalid shared draft replacement tuple")
	}
	var draft map[string]any
	if err := json.Unmarshal(req.Draft, &draft); err != nil || draft == nil {
		return methodError("invalidArguments", "draft must be an object")
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	result, callErr := h.caller.CallScoped(ctx, accountID, "mail_draft_replace", user.UserID,
		op, id, epoch, revision, req.Draft, mailDraftDigest(req))
	if callErr != nil {
		return "error", mapReducerErr(callErr, h.logger, "mailDraftReplace")
	}
	return "MailDraft/replace", result
}
