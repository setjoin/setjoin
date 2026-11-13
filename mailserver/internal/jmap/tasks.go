package jmap

import (
	"context"
	"encoding/json"
	"strconv"

	"setjoin.com/mailserver/internal/auth"
)

// tasks.go — JMAP Task family handlers: Task/get, Task/query, Task/changes,
// Task/set. Registered in registerMethods() (handler.go).
// See mailserver/internal/AGENTS.md.

// --- JMAP Task method implementations ---

func (h *JMAPHandler) taskGet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID  string   `json:"accountId"`
		Ids        []string `json:"ids"`
		Properties []string `json:"properties,omitempty"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}

	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	ids, badIDs := parseIDList(req.Ids)

	var result json.RawMessage
	result, err := h.caller.CallScoped(ctx, accountID, "jmap_task_get", ids)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "taskGet")
	}
	return "Task/get", addNotFound(result, badIDs)
}

func (h *JMAPHandler) taskQuery(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID string          `json:"accountId"`
		Filter    json.RawMessage `json:"filter,omitempty"`
		Sort      json.RawMessage `json:"sort,omitempty"`
		Position  int             `json:"position,omitempty"`
		Limit     int             `json:"limit,omitempty"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	if req.Limit <= 0 || req.Limit > 256 {
		req.Limit = 50
	}

	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	var result json.RawMessage
	result, err := h.caller.CallScoped(ctx, accountID, "jmap_task_query", req.Filter, req.Sort, req.Position, req.Limit)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "taskQuery")
	}
	return "Task/query", result
}

func (h *JMAPHandler) taskChanges(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID  string `json:"accountId"`
		SinceState string `json:"sinceState"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}

	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	if errResp := sinceStateError(req.SinceState); errResp != nil {
		return "error", errResp
	}
	var result json.RawMessage
	result, err := h.caller.CallScoped(ctx, accountID, "jmap_task_changes", req.SinceState)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "taskChanges")
	}
	return "Task/changes", result
}

func (h *JMAPHandler) taskSet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req SetRequest
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	r, err := h.dispatchSet(ctx, accountID, &req, "jmap_task")
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "taskSet")
	}
	return "Task/set", r
}

// --- TaskComment/* — the QoL #17 activity-feed extension (non-core) ---

// taskCommentCreate (TaskComment/set) — append a user comment to a task's
// activity feed. mentionedEmails resolve to internal users server-side (the
// reducer owns the @mention notification); ownership is enforced there (R1).
func (h *JMAPHandler) taskCommentCreate(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID       string          `json:"accountId"`
		TaskID          string          `json:"taskId"`
		Body            string          `json:"body"`
		MentionedEmails json.RawMessage `json:"mentionedEmails,omitempty"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	taskID, err := strconv.ParseInt(req.TaskID, 10, 64)
	if err != nil || taskID <= 0 {
		return methodError("invalidArguments", "invalid taskId")
	}
	mentions := req.MentionedEmails
	if len(mentions) == 0 {
		mentions = json.RawMessage("[]")
	}
	result, err := h.caller.CallScoped(ctx, accountID, "task_comment_create", taskID, req.Body, mentions)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "taskCommentCreate")
	}
	return "TaskComment/set", result
}

// taskActivityGet (TaskComment/get) — the ownership-checked activity feed
// (comments + system change entries) for one task.
func (h *JMAPHandler) taskActivityGet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID string `json:"accountId"`
		TaskID    string `json:"taskId"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	taskID, err := strconv.ParseInt(req.TaskID, 10, 64)
	if err != nil || taskID <= 0 {
		return methodError("invalidArguments", "invalid taskId")
	}
	result, err := h.caller.CallScoped(ctx, accountID, "task_activity_list", taskID)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "taskActivityGet")
	}
	return "TaskComment/get", result
}
