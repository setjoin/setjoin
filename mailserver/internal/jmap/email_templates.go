package jmap

import (
	"context"
	"encoding/json"
	"strconv"

	"setjoin.com/mailserver/internal/auth"
)

// Email-template reducer errors route through the shared mapReducerErr (c6):
// BZ040 → invalidArguments with the reducer message passed through (the
// reducererr Detail allowlist owns that — the former emailTemplateError branch).

// emailTemplateList — EmailTemplate/list: list the account's compose templates.
// The mailbox id is resolved from auth (parseAccountID), never taken from the
// request (R2).
func (h *JMAPHandler) emailTemplateList(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
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
	if h.pool == nil {
		empty, _ := json.Marshal(map[string]any{"accountId": req.AccountID, "list": []any{}})
		return "EmailTemplate/list", empty
	}
	list, err := h.caller.CallScoped(ctx, accountID, "email_template_list")
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "EmailTemplate/list")
	}
	out, _ := json.Marshal(map[string]any{
		"accountId": strconv.FormatInt(accountID, 10),
		"list":      list,
	})
	return "EmailTemplate/list", out
}

// emailTemplateSet — EmailTemplate/set: create or (upsert-by-name) update a
// compose template. body_html is stored verbatim by the reducer; validation +
// mailbox scoping live in the reducer, the handler only resolves the account id
// from auth (R2).
func (h *JMAPHandler) emailTemplateSet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID string `json:"accountId"`
		Name      string `json:"name"`
		Subject   string `json:"subject"`
		BodyHTML  string `json:"bodyHtml"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	if h.pool == nil {
		ok, _ := json.Marshal(map[string]any{"accountId": req.AccountID})
		return "EmailTemplate/set", ok
	}
	created, err := h.caller.CallScoped(ctx, accountID, "email_template_set", req.Name, req.Subject, req.BodyHTML)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "EmailTemplate/set")
	}
	out, _ := json.Marshal(map[string]any{
		"accountId": strconv.FormatInt(accountID, 10),
		"created":   created,
	})
	return "EmailTemplate/set", out
}

// emailTemplateDelete — EmailTemplate/delete: delete one of the account's compose
// templates. The reducer's WHERE carries the ownership predicate (R3), so a
// foreign id is a no-op.
func (h *JMAPHandler) emailTemplateDelete(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID string `json:"accountId"`
		ID        string `json:"id"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	id, errJSON := parseArg(req.ID, "id")
	if errJSON != nil {
		return "error", errJSON
	}
	if h.pool == nil {
		ok, _ := json.Marshal(map[string]any{"accountId": req.AccountID, "deleted": req.ID})
		return "EmailTemplate/delete", ok
	}
	res, err := h.caller.CallScoped(ctx, accountID, "email_template_delete", id)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "EmailTemplate/delete")
	}
	out, _ := json.Marshal(map[string]any{
		"accountId": strconv.FormatInt(accountID, 10),
		"result":    res,
	})
	return "EmailTemplate/delete", out
}
