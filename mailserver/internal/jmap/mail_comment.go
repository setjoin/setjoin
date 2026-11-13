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

func (h *JMAPHandler) mailCommentsEnabled() bool {
	return h.toggles != nil && h.toggles.IsEnabled(toggle.FeatureSharedMailComments)
}

func mailCommentsDisabled() (string, json.RawMessage) {
	return methodError("serverUnavailable", "shared mail comments are not enabled")
}

func (h *JMAPHandler) mailCommentGet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	if !h.mailCommentsEnabled() {
		return mailCommentsDisabled()
	}
	var req struct {
		AccountID string  `json:"accountId"`
		ThreadID  string  `json:"threadId"`
		Before    *string `json:"before,omitempty"`
		Limit     int     `json:"limit,omitempty"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	if req.Limit == 0 {
		req.Limit = 100
	}
	if req.Limit < 1 || req.Limit > 100 {
		return methodError("invalidArguments", "limit must be 1..100")
	}
	var before any
	if req.Before != nil {
		v, err := time.Parse(time.RFC3339, *req.Before)
		if err != nil {
			return methodError("invalidArguments", "before must be RFC3339")
		}
		before = v
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	result, err := h.caller.CallScoped(ctx, accountID, "mail_comment_get", user.UserID, req.ThreadID, before, req.Limit)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "mailCommentGet")
	}
	return "MailComment/get", result
}

func (h *JMAPHandler) mailCommentSet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	if !h.mailCommentsEnabled() {
		return mailCommentsDisabled()
	}
	var req struct {
		AccountID          string   `json:"accountId"`
		ThreadID           string   `json:"threadId"`
		OperationID        string   `json:"operationId"`
		ExpectedGeneration string   `json:"expectedGeneration"`
		Body               string   `json:"body"`
		MentionUserIDs     []string `json:"mentionUserIds,omitempty"`
		ReplacesCommentID  *string  `json:"replacesCommentId,omitempty"`
		HandoffUserID      *string  `json:"handoffUserId,omitempty"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	operationID, err := uuid.Parse(req.OperationID)
	if err != nil || operationID == uuid.Nil {
		return methodError("invalidArguments", "operationId must be a non-zero UUID")
	}
	expected, err := strconv.ParseInt(req.ExpectedGeneration, 10, 64)
	if err != nil || expected < 0 {
		return methodError("invalidArguments", "expectedGeneration must be a non-negative decimal string")
	}
	if len(req.MentionUserIDs) > 50 {
		return methodError("requestTooLarge", "too many mentions")
	}
	mentions := make([]int64, 0, len(req.MentionUserIDs))
	for _, raw := range req.MentionUserIDs {
		id, parseErr := strconv.ParseInt(raw, 10, 64)
		if parseErr != nil || id <= 0 {
			return methodError("invalidArguments", "mention user ids must be positive decimal strings")
		}
		mentions = append(mentions, id)
	}
	var replaces any
	if req.ReplacesCommentID != nil {
		id, parseErr := uuid.Parse(*req.ReplacesCommentID)
		if parseErr != nil || id == uuid.Nil {
			return methodError("invalidArguments", "replacesCommentId must be a non-zero UUID")
		}
		replaces = id
	}
	var handoff any
	if req.HandoffUserID != nil {
		id, parseErr := strconv.ParseInt(*req.HandoffUserID, 10, 64)
		if parseErr != nil || id <= 0 {
			return methodError("invalidArguments", "handoffUserId must be a positive decimal string")
		}
		handoff = id
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	canonical, _ := json.Marshal(req)
	digestBytes := sha256.Sum256(canonical)
	digest := hex.EncodeToString(digestBytes[:])
	result, err := h.caller.CallScoped(ctx, accountID, "mail_comment_set", user.UserID,
		req.ThreadID, operationID, expected, req.Body, mentions, replaces, handoff, digest)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "mailCommentSet")
	}
	return "MailComment/set", result
}
