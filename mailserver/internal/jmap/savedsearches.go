package jmap

import (
	"context"
	"encoding/json"
	"strconv"

	"setjoin.com/mailserver/internal/auth"
)

// Saved-search reducer errors route through the shared mapReducerErr (c6):
// BZ040 → invalidArguments with the reducer message passed through (the
// reducererr Detail allowlist owns that — the former savedSearchError branch).

// savedSearchList — SavedSearch/list: list the account's saved searches. The
// mailbox id is resolved from auth (parseAccountID), never taken from the
// request (R2).
func (h *JMAPHandler) savedSearchList(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
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
		return "SavedSearch/list", empty
	}
	list, err := h.caller.CallScoped(ctx, accountID, "saved_search_list")
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "SavedSearch/list")
	}
	out, _ := json.Marshal(map[string]any{
		"accountId": strconv.FormatInt(accountID, 10),
		"list":      list,
	})
	return "SavedSearch/list", out
}

// savedSearchSet — SavedSearch/set: create a named saved search from a raw query
// string (stored verbatim). Ownership/validation live in the reducer; the handler
// only resolves the account id from auth (R2).
func (h *JMAPHandler) savedSearchSet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID string `json:"accountId"`
		Name      string `json:"name"`
		Query     string `json:"query"`
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
		return "SavedSearch/set", ok
	}
	created, err := h.caller.CallScoped(ctx, accountID, "saved_search_set", req.Name, req.Query)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "SavedSearch/set")
	}
	out, _ := json.Marshal(map[string]any{
		"accountId": strconv.FormatInt(accountID, 10),
		"created":   created,
	})
	return "SavedSearch/set", out
}

// savedSearchDelete — SavedSearch/delete: delete one of the account's saved
// searches. The reducer's WHERE carries the ownership predicate (R3), so a
// foreign id is a no-op.
func (h *JMAPHandler) savedSearchDelete(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
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
		return "SavedSearch/delete", ok
	}
	res, err := h.caller.CallScoped(ctx, accountID, "saved_search_delete", id)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "SavedSearch/delete")
	}
	out, _ := json.Marshal(map[string]any{
		"accountId": strconv.FormatInt(accountID, 10),
		"result":    res,
	})
	return "SavedSearch/delete", out
}
