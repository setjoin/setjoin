package jmap

import (
	"context"
	"encoding/json"
	"strconv"

	"setjoin.com/mailserver/internal/auth"
)

// A4 — personal contact groups (user-created distribution lists). Thin JMAP
// translators over the jmap_contact_group_* reducers + expand_contact_group.
// Gated under the contacts capability/app (see appForMethod / capabilityForMethod).

// membersPatch is the embedded patch carried on a ContactGroup/set request to
// add/remove members of a single group ({"members":{groupId,add,remove}}). It is
// handled by the contact_group_members_set reducer, separately from the standard
// create/update/destroy CRUD, keeping the gateway a thin translator.
type membersPatch struct {
	GroupID string            `json:"groupId"`
	Add     []json.RawMessage `json:"add"`
	Remove  []json.RawMessage `json:"remove"`
}

// parseMembersPatch decodes a members patch; ok=false when groupId is absent.
func parseMembersPatch(raw json.RawMessage) (membersPatch, bool) {
	var p membersPatch
	if err := json.Unmarshal(raw, &p); err != nil {
		return membersPatch{}, false
	}
	if p.GroupID == "" {
		return membersPatch{}, false
	}
	return p, true
}

func (h *JMAPHandler) contactGroupGet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID string   `json:"accountId"`
		Ids       []string `json:"ids"`
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
	result, err := h.caller.CallScoped(ctx, accountID, "jmap_contact_group_get", ids)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "contactGroupGet")
	}
	return "ContactGroup/get", addNotFound(result, badIDs)
}

func (h *JMAPHandler) contactGroupQuery(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID string          `json:"accountId"`
		Filter    json.RawMessage `json:"filter,omitempty"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	var result json.RawMessage
	result, err := h.caller.CallScoped(ctx, accountID, "jmap_contact_group_query", req.Filter)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "contactGroupQuery")
	}
	return "ContactGroup/query", result
}

// contactGroupSet handles create/update/destroy via the shared dispatchSet, and a
// {"members":{groupId,add,remove}} patch via contact_group_members_set.
func (h *JMAPHandler) contactGroupSet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		SetRequest
		Members json.RawMessage `json:"members,omitempty"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}

	r, err := h.dispatchSet(ctx, accountID, &req.SetRequest, "jmap_contact_group")
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "contactGroupSet")
	}

	// Optional members patch: route to contact_group_members_set. Ownership +
	// member validity are enforced in the reducer (BZ045 on a foreign group).
	if len(req.Members) > 0 && string(req.Members) != "null" {
		if patch, ok := parseMembersPatch(req.Members); ok {
			// A malformed groupId used to silently SKIP the whole members
			// patch (c4 defect) — now it rejects, naming the property.
			groupID, errJSON := parseArg(patch.GroupID, "members.groupId")
			if errJSON != nil {
				return "error", errJSON
			}
			add := rawListToJSON(patch.Add)
			remove := rawListToJSON(patch.Remove)
			var mres json.RawMessage
			mres, merr := h.caller.CallScoped(ctx, accountID, "contact_group_members_set", groupID, add, remove)
			if merr != nil {
				// BZ045 (foreign group) surfaces as forbidden / "contact
				// group not owned by caller" via the shared classification +
				// Detail fixed table; the generic helper also maps the rest
				// (BZ002/BZ006/unknown) and keeps the log.
				return "error", mapReducerErr(merr, h.logger, "contactGroupSet members")
			}
			// Splice the members result onto the set response.
			r = mergeMembersResult(r, mres)
		}
	}
	return "ContactGroup/set", r
}

func (h *JMAPHandler) contactGroupExpand(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID string `json:"accountId"`
		GroupID   string `json:"groupId"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	groupID, errJSON := parseArg(req.GroupID, "groupId")
	if errJSON != nil {
		return "error", errJSON
	}
	list, err := h.caller.CallScoped(ctx, accountID, "expand_contact_group", groupID)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "contactGroupExpand")
	}
	out, _ := json.Marshal(map[string]json.RawMessage{
		"accountId": json.RawMessage(strconv.Quote(req.AccountID)),
		"list":      list,
	})
	return "ContactGroup/expand", out
}

// rawListToJSON marshals a slice of raw member objects back into a JSON array
// for the reducer ([] when empty).
func rawListToJSON(items []json.RawMessage) json.RawMessage {
	if len(items) == 0 {
		return json.RawMessage("[]")
	}
	out, err := json.Marshal(items)
	if err != nil {
		return json.RawMessage("[]")
	}
	return out
}

// mergeMembersResult attaches the members-set outcome onto the /set response
// under a "members" key so the client sees the new memberCount.
func mergeMembersResult(setResult, membersResult json.RawMessage) json.RawMessage {
	merged := make(map[string]json.RawMessage)
	if len(setResult) > 0 {
		_ = json.Unmarshal(setResult, &merged)
	}
	merged["members"] = membersResult
	out, _ := json.Marshal(merged)
	return out
}
