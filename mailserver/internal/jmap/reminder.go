package jmap

import (
	"context"
	"encoding/json"

	"setjoin.com/mailserver/internal/auth"
)

// Reminder reducer errors route through the shared mapReducerErr (c6):
// BZ038 → notFound "reminder not found", BZ039 → invalidArguments "snooze time
// must be in the future" — the per-code wording lives in reducererr's Detail
// fixed table now (the former reducerError switch).

// reminderGet — Reminder/get: returns the account's active reminders (fired, not
// dismissed, not currently snoozed). Account id comes from auth (never req.*).
func (h *JMAPHandler) reminderGet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID string `json:"accountId"`
		Limit     int    `json:"limit,omitempty"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	if req.Limit <= 0 || req.Limit > 500 {
		req.Limit = 100
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	if h.pool == nil {
		empty, _ := json.Marshal(map[string]any{"accountId": req.AccountID, "list": []any{}, "state": encodeStateToken(0)})
		return "Reminder/get", empty
	}
	var raw json.RawMessage
	raw, err := h.caller.CallScoped(ctx, accountID, "reminders_get", req.Limit)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "Reminder/get")
	}
	return "Reminder/get", raw
}

// reminderDismiss — Reminder/dismiss: dismisses one reminder (or all when no id is
// given). Ownership enforced in the reducer (BZ038 on a foreign/missing reminder).
func (h *JMAPHandler) reminderDismiss(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID  string `json:"accountId"`
		ReminderID string `json:"reminderId,omitempty"`
		All        bool   `json:"all,omitempty"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	var raw json.RawMessage
	var err error
	if req.All || req.ReminderID == "" {
		raw, err = h.caller.CallScoped(ctx, accountID, "reminder_dismiss_all")
	} else {
		rid, errJSON := parseArg(req.ReminderID, "reminderId")
		if errJSON != nil {
			return "error", errJSON
		}
		raw, err = h.caller.CallScoped(ctx, accountID, "reminder_dismiss", rid)
	}
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "Reminder/dismiss")
	}
	return "Reminder/dismiss", raw
}

// reminderSnooze — Reminder/snooze: re-arms a reminder for a later time. Rejects a
// past time (BZ039) and a foreign/missing reminder (BZ038), surfaced as JMAP errors.
func (h *JMAPHandler) reminderSnooze(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID  string `json:"accountId"`
		ReminderID string `json:"reminderId"`
		Until      string `json:"until"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	rid, errJSON := parseArg(req.ReminderID, "reminderId")
	if errJSON != nil {
		return "error", errJSON
	}
	var raw json.RawMessage
	err := h.pool.QueryRow(ctx, `SELECT reminder_snooze($1, $2, $3::timestamptz)`, accountID, rid, req.Until).Scan(&raw)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "Reminder/snooze")
	}
	return "Reminder/snooze", raw
}
