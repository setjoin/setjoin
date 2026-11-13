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

func (h *JMAPHandler) mailWorkEnabled() bool {
	return h.toggles != nil && h.toggles.IsEnabled(toggle.FeatureSharedMailWork)
}

func (h *JMAPHandler) mailWorkNotificationsEnabled() bool {
	return h.mailWorkEnabled() && h.toggles.IsEnabled(toggle.FeatureSharedMailNotifications)
}

func (h *JMAPHandler) mailWorkAnalyticsEnabled() bool {
	return h.mailWorkEnabled() && h.toggles.IsEnabled(toggle.FeatureSharedMailAnalytics)
}

func (h *JMAPHandler) mailWorkIntegrationsEnabled() bool {
	return h.mailWorkEnabled() && h.toggles.IsEnabled(toggle.FeatureSharedMailIntegrations)
}

func mailWorkDisabled() (string, json.RawMessage) {
	return methodError("serverUnavailable", "shared mail work is not enabled")
}

func (h *JMAPHandler) mailWorkGet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	if !h.mailWorkEnabled() {
		return mailWorkDisabled()
	}
	var req struct {
		AccountID string   `json:"accountId"`
		IDs       []string `json:"ids,omitempty"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	if len(req.IDs) > 256 {
		return methodError("requestTooLarge", "too many ids requested")
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	var ids any
	if req.IDs != nil {
		ids = req.IDs
	}
	result, err := h.caller.CallScoped(ctx, accountID, "mail_work_get", user.UserID, ids)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "mailWorkGet")
	}
	return "MailWork/get", result
}

func (h *JMAPHandler) mailWorkChanges(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	if !h.mailWorkEnabled() {
		return mailWorkDisabled()
	}
	var req struct {
		AccountID  string `json:"accountId"`
		SinceState string `json:"sinceState"`
		MaxChanges int    `json:"maxChanges,omitempty"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	if errResp := sinceStateError(req.SinceState); errResp != nil {
		return "error", errResp
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	result, err := h.caller.CallScoped(ctx, accountID, "mail_work_changes", user.UserID, req.SinceState, nullIfZero(req.MaxChanges))
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "mailWorkChanges")
	}
	return "MailWork/changes", result
}

func (h *JMAPHandler) mailWorkSet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	if !h.mailWorkEnabled() {
		return mailWorkDisabled()
	}
	var req struct {
		AccountID          string  `json:"accountId"`
		ThreadID           string  `json:"threadId"`
		OperationID        string  `json:"operationId"`
		Action             string  `json:"action"`
		ExpectedGeneration string  `json:"expectedGeneration"`
		AssigneeUserID     *string `json:"assigneeUserId,omitempty"`
		Status             *string `json:"status,omitempty"`
		DueAt              *string `json:"dueAt,omitempty"`
		Reason             string  `json:"reason"`
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
	var assignee any
	if req.AssigneeUserID != nil {
		v, parseErr := strconv.ParseInt(*req.AssigneeUserID, 10, 64)
		if parseErr != nil || v <= 0 {
			return methodError("invalidArguments", "assigneeUserId must be a positive decimal string")
		}
		assignee = v
	}
	var due any
	if req.DueAt != nil {
		v, parseErr := time.Parse(time.RFC3339, *req.DueAt)
		if parseErr != nil {
			return methodError("invalidArguments", "dueAt must be RFC3339")
		}
		due = v
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	canonical, _ := json.Marshal(req)
	digestBytes := sha256.Sum256(canonical)
	digest := hex.EncodeToString(digestBytes[:])
	result, err := h.caller.CallScoped(ctx, accountID, "mail_work_set", user.UserID,
		req.ThreadID, operationID, req.Action, expected, assignee, req.Status, due, req.Reason, digest)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "mailWorkSet")
	}
	return "MailWork/set", result
}

func (h *JMAPHandler) mailWorkAction(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	if !h.mailWorkIntegrationsEnabled() {
		return mailWorkDisabled()
	}
	var req struct {
		AccountID          string  `json:"accountId"`
		ThreadID           string  `json:"threadId"`
		OperationID        string  `json:"operationId"`
		ExpectedGeneration string  `json:"expectedGeneration"`
		ActionKind         string  `json:"actionKind"`
		TargetID           *string `json:"targetId,omitempty"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	operationID, err := uuid.Parse(req.OperationID)
	if err != nil || operationID == uuid.Nil {
		return methodError("invalidArguments", "operationId must be a non-zero UUID")
	}
	expected, err := strconv.ParseInt(req.ExpectedGeneration, 10, 64)
	if err != nil || expected < 1 {
		return methodError("invalidArguments", "expectedGeneration must be a positive decimal string")
	}
	if req.ActionKind != "task" && req.ActionKind != "chat" && req.ActionKind != "drive" {
		return methodError("invalidArguments", "actionKind must be task, chat, or drive")
	}
	var target any
	if req.TargetID != nil {
		value, parseErr := strconv.ParseInt(*req.TargetID, 10, 64)
		if parseErr != nil || value <= 0 {
			return methodError("invalidArguments", "targetId must be a positive decimal string")
		}
		target = value
	}
	if (req.ActionKind == "task" && target != nil) || (req.ActionKind != "task" && target == nil) {
		return methodError("invalidArguments", "targetId is required only for chat and drive")
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	canonical, _ := json.Marshal(req)
	digestBytes := sha256.Sum256(canonical)
	result, callErr := h.caller.CallScoped(ctx, accountID, "mail_work_action_enqueue", user.UserID,
		req.ThreadID, operationID, expected, req.ActionKind, target, hex.EncodeToString(digestBytes[:]))
	if callErr != nil {
		return "error", mapReducerErr(callErr, h.logger, "mailWorkAction")
	}
	return "MailWork/action", result
}

func (h *JMAPHandler) mailWorkCollaboratorsGet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	if !h.mailWorkEnabled() {
		return mailWorkDisabled()
	}
	var req struct {
		AccountID string `json:"accountId"`
		Query     string `json:"query,omitempty"`
		Limit     int    `json:"limit,omitempty"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	if len(req.Query) > 128 {
		return methodError("invalidArguments", "query is too long")
	}
	if req.Limit == 0 {
		req.Limit = 20
	}
	if req.Limit < 1 || req.Limit > 50 {
		return methodError("invalidArguments", "limit must be between 1 and 50")
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	result, err := h.caller.CallScoped(ctx, accountID, "mail_work_collaborators_get", user.UserID, req.Query, req.Limit)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "mailWorkCollaboratorsGet")
	}
	return "MailWorkCollaborators/get", result
}

func (h *JMAPHandler) mailWorkPolicyGet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	if !h.mailWorkEnabled() {
		return mailWorkDisabled()
	}
	var req struct {
		AccountID string `json:"accountId"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	result, err := h.caller.CallScoped(ctx, accountID, "mail_work_sla_policy_get", user.UserID)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "mailWorkPolicyGet")
	}
	return "MailWorkPolicy/get", result
}

func (h *JMAPHandler) mailWorkPolicySet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	if !h.mailWorkEnabled() {
		return mailWorkDisabled()
	}
	var req struct {
		AccountID          string   `json:"accountId"`
		OperationID        string   `json:"operationId"`
		ExpectedGeneration string   `json:"expectedGeneration"`
		Timezone           string   `json:"timezone"`
		WeekdayMask        int      `json:"weekdayMask"`
		WorkdayStart       string   `json:"workdayStart"`
		WorkdayEnd         string   `json:"workdayEnd"`
		Holidays           []string `json:"holidays"`
		SLAMinutes         int      `json:"slaMinutes"`
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
	if _, err = time.LoadLocation(req.Timezone); err != nil || req.WeekdayMask < 1 || req.WeekdayMask > 127 ||
		req.SLAMinutes < 1 || req.SLAMinutes > 525600 || len(req.Holidays) > 366 {
		return methodError("invalidArguments", "invalid SLA policy bounds")
	}
	start, startErr := time.Parse("15:04", req.WorkdayStart)
	end, endErr := time.Parse("15:04", req.WorkdayEnd)
	if startErr != nil || endErr != nil || !start.Before(end) {
		return methodError("invalidArguments", "workdayStart and workdayEnd must be HH:MM with start before end")
	}
	seen := make(map[string]struct{}, len(req.Holidays))
	for _, holiday := range req.Holidays {
		if _, parseErr := time.Parse("2006-01-02", holiday); parseErr != nil {
			return methodError("invalidArguments", "holidays must contain unique YYYY-MM-DD values")
		}
		if _, duplicate := seen[holiday]; duplicate {
			return methodError("invalidArguments", "holidays must contain unique YYYY-MM-DD values")
		}
		seen[holiday] = struct{}{}
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	canonical, _ := json.Marshal(req)
	digestBytes := sha256.Sum256(canonical)
	result, callErr := h.caller.CallScoped(ctx, accountID, "mail_work_sla_policy_set", user.UserID,
		operationID, expected, req.Timezone, req.WeekdayMask, req.WorkdayStart, req.WorkdayEnd,
		req.Holidays, req.SLAMinutes, hex.EncodeToString(digestBytes[:]))
	if callErr != nil {
		return "error", mapReducerErr(callErr, h.logger, "mailWorkPolicySet")
	}
	return "MailWorkPolicy/set", result
}

func (h *JMAPHandler) mailWorkNotificationPreferencesGet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	if !h.mailWorkNotificationsEnabled() {
		return mailWorkDisabled()
	}
	var req struct {
		AccountID string `json:"accountId"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	result, err := h.caller.CallScoped(ctx, accountID, "mail_work_notification_preferences_get", user.UserID)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "mailWorkNotificationPreferencesGet")
	}
	return "MailWorkNotificationPreferences/get", result
}

func (h *JMAPHandler) mailWorkNotificationPreferencesSet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	if !h.mailWorkNotificationsEnabled() {
		return mailWorkDisabled()
	}
	var req struct {
		AccountID          string `json:"accountId"`
		OperationID        string `json:"operationId"`
		Category           string `json:"category"`
		Delivery           string `json:"delivery"`
		Timezone           string `json:"timezone"`
		DigestHour         int    `json:"digestHour"`
		ExpectedGeneration string `json:"expectedGeneration"`
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
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	canonical, _ := json.Marshal(req)
	digestBytes := sha256.Sum256(canonical)
	result, err := h.caller.CallScoped(ctx, accountID, "mail_work_notification_preferences_set", user.UserID,
		operationID, req.Category, req.Delivery, req.Timezone, req.DigestHour, expected,
		hex.EncodeToString(digestBytes[:]))
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "mailWorkNotificationPreferencesSet")
	}
	return "MailWorkNotificationPreferences/set", result
}

func (h *JMAPHandler) mailWorkMetricsGet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	if !h.mailWorkAnalyticsEnabled() {
		return mailWorkDisabled()
	}
	var req struct {
		AccountID     string `json:"accountId"`
		From          string `json:"from"`
		To            string `json:"to"`
		PolicyVersion int    `json:"policyVersion,omitempty"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	from, err := time.Parse("2006-01-02", req.From)
	if err != nil {
		return methodError("invalidArguments", "from must be YYYY-MM-DD")
	}
	to, err := time.Parse("2006-01-02", req.To)
	if err != nil || to.Before(from) || to.Sub(from) > 366*24*time.Hour {
		return methodError("invalidArguments", "to must be YYYY-MM-DD, on or after from, within 366 days")
	}
	if req.PolicyVersion == 0 {
		req.PolicyVersion = 1
	}
	if req.PolicyVersion < 1 {
		return methodError("invalidArguments", "policyVersion must be positive")
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	result, callErr := h.caller.CallScoped(ctx, accountID, "mail_work_metrics_get", user.UserID,
		from.Format("2006-01-02"), to.Format("2006-01-02"), req.PolicyVersion)
	if callErr != nil {
		return "error", mapReducerErr(callErr, h.logger, "mailWorkMetricsGet")
	}
	return "MailWorkMetrics/get", result
}
