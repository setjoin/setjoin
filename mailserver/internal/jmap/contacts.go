package jmap

import (
	"context"
	"encoding/json"

	"setjoin.com/mailserver/internal/auth"
)

// contacts.go — JMAP Contacts family handlers: AddressBook/*, ContactCard/*
// (get/query/changes/set/galSearch), and the directory browse surface
// (directoryTree/directoryMembers/directorySearch). ContactGroup/* lives in
// contact_group.go; methods here are registered in registerMethods() (handler.go).
// See mailserver/internal/AGENTS.md.

// --- JMAP Contact method implementations ---

func (h *JMAPHandler) addressBookGet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
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
	var idsArray interface{}
	if ids != nil { // nil only when req.Ids was absent/empty → NULL → get-all
		idsArray = ids
	}

	var result json.RawMessage
	result, err := h.caller.CallScoped(ctx, accountID, "jmap_addressbook_get", idsArray)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "addressBookGet")
	}
	return "AddressBook/get", addNotFound(result, badIDs)
}

func (h *JMAPHandler) addressBookChanges(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
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
	result, err := h.caller.CallScoped(ctx, accountID, "jmap_addressbook_changes", req.SinceState)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "addressBookChanges")
	}
	return "AddressBook/changes", result
}

func (h *JMAPHandler) addressBookSet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req SetRequest
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	r, err := h.dispatchSet(ctx, accountID, &req, "jmap_addressbook")
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "addressBookSet")
	}
	return "AddressBook/set", r
}

func (h *JMAPHandler) contactCardGet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
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
	result, err := h.caller.CallScoped(ctx, accountID, "jmap_contact_get", ids)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "contactCardGet")
	}
	return "ContactCard/get", addNotFound(result, badIDs)
}

func (h *JMAPHandler) contactCardQuery(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
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
	result, err := h.caller.CallScoped(ctx, accountID, "jmap_contact_query", req.Filter, req.Sort, req.Position, req.Limit)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "contactCardQuery")
	}
	return "ContactCard/query", result
}

func (h *JMAPHandler) contactCardChanges(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
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
	result, err := h.caller.CallScoped(ctx, accountID, "jmap_contact_changes", req.SinceState)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "contactCardChanges")
	}
	return "ContactCard/changes", result
}

func (h *JMAPHandler) contactCardSet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req SetRequest
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	r, err := h.dispatchSet(ctx, accountID, &req, "jmap_contactcard")
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "contactCardSet")
	}
	return "ContactCard/set", r
}

// contactCardFindDuplicates groups the caller's contacts by lower(email address)
// and returns clusters with ≥2 members ([{email, contactIds}, …]) via the
// contact_find_duplicates reducer. CallScoped sets app.current_mailbox_id (RLS).
func (h *JMAPHandler) contactCardFindDuplicates(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
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
	var result json.RawMessage
	result, err := h.caller.CallScoped(ctx, accountID, "contact_find_duplicates")
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "contactCardFindDuplicates")
	}
	return "ContactCard/findDuplicates", result
}

// contactCardMerge merges the duplicate contact dropId INTO keepId (field union,
// group-membership re-point, atomic) via the contact_merge reducer. Ownership is
// enforced in the reducer's WHERE (R3); a foreign/missing id → BZ112 → notFound.
func (h *JMAPHandler) contactCardMerge(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID string `json:"accountId"`
		KeepID    string `json:"keepId"`
		DropID    string `json:"dropId"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	keepID, errJSON := parseArg(req.KeepID, "keepId")
	if errJSON != nil {
		return "error", errJSON
	}
	dropID, errJSON := parseArg(req.DropID, "dropId")
	if errJSON != nil {
		return "error", errJSON
	}
	result, err := h.caller.CallScoped(ctx, accountID, "contact_merge", keepID, dropID)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "contactCardMerge")
	}
	return "ContactCard/merge", result
}

func (h *JMAPHandler) contactCardGalSearch(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID string `json:"accountId"`
		Text      string `json:"text,omitempty"`
		Limit     int    `json:"limit,omitempty"`
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
	result, err := h.caller.Call(ctx, "gal_search", accountID, req.Text, req.Limit)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "contactCardGalSearch")
	}
	return "ContactCard/galSearch", result
}

func (h *JMAPHandler) contactCardDirectoryTree(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
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
	var result json.RawMessage
	result, err := h.caller.Call(ctx, "directory_tree", accountID)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "contactCardDirectoryTree")
	}
	return "ContactCard/directoryTree", result
}

func (h *JMAPHandler) contactCardDirectoryMembers(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID    string `json:"accountId"`
		DepartmentID int64  `json:"departmentId"`
		Offset       int    `json:"offset,omitempty"`
		Limit        int    `json:"limit,omitempty"`
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
	result, err := h.caller.Call(ctx, "directory_members", accountID, req.DepartmentID, req.Offset, req.Limit)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "contactCardDirectoryMembers")
	}
	return "ContactCard/directoryMembers", result
}

func (h *JMAPHandler) contactCardDirectorySearch(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID string `json:"accountId"`
		Query     string `json:"query"`
		Limit     int    `json:"limit,omitempty"`
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
	result, err := h.caller.Call(ctx, "directory_search", accountID, req.Query, req.Limit)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "contactCardDirectorySearch")
	}
	return "ContactCard/directorySearch", result
}
