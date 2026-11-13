package jmap

import (
	"context"
	"encoding/json"
	"time"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/reducererr"
)

// calendar_a3.go — A3 calendar Outlook-parity JMAP handlers: ACL-aware shared reads,
// sharing CRUD, occurrence-vs-series edit, delegate listing, resource list, send update.
//
// SECURITY: the shared-read handlers derive the VIEWER from user.UserID (the
// authenticated user's id) — never from any viewerId in the request body — and pass an
// owner *email* the reducer resolves server-side. parseAccountID's same-mailbox guard is
// untouched: a viewer can never pass another user's accountId to read their calendar.

// calendarA3Error maps a calendar reducer BZ code onto a JMAP error type.
// BZ001 (not authorized for this calendar) → forbidden; everything else
// (including BZ002 forbidden / BZ006 accountNotFound) defers to the shared
// mapReducerErr — the single source of truth for the generic map + the log.
//
// BZ001 is dual-use (storage over_quota in mail reducers; forbidden/notFound
// slugs in calendar reducers). The calendar meaning is CALL-SITE-CONTEXTUAL —
// reducererr deliberately classifies the non-over_quota slugs as ClassUnknown —
// so this stays a semantic IsCode branch, not a projection (see the contract
// matrix row for BZ001/acl_forbidden).
func calendarA3Error(err error, h *JMAPHandler, method string) json.RawMessage {
	if reducererr.IsCode(err, "BZ001") {
		j, _ := json.Marshal(Error{Type: "forbidden", Description: "not authorized for this calendar"})
		return j
	}
	return mapReducerErr(err, h.logger, method)
}

// calendarGetShared — Calendar/getShared: another user's calendars the viewer may see.
func (h *JMAPHandler) calendarGetShared(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID  string `json:"accountId"`
		OwnerEmail string `json:"ownerEmail"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	// Validate the request accountId is the viewer's own (guard stays intact). The viewer
	// passed to the reducer is always user.UserID, never anything from the body.
	if _, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID); errResp != nil {
		return "error", errResp
	}
	if req.OwnerEmail == "" {
		return methodError("invalidArguments", "ownerEmail is required")
	}
	if h.pool == nil {
		empty, _ := json.Marshal(map[string]any{"accountId": req.AccountID, "ownerEmail": req.OwnerEmail, "list": []any{}})
		return "Calendar/getShared", empty
	}
	var result json.RawMessage
	result, err := h.caller.Call(ctx, "jmap_calendar_get_shared", user.UserID, req.OwnerEmail)
	if err != nil {
		return "error", calendarA3Error(err, h, "Calendar/getShared")
	}
	return "Calendar/getShared", result
}

// calendarEventGetShared — CalendarEvent/getShared: events on a shared calendar within a
// time window. freebusy grants are redacted to Busy blocks by the reducer.
func (h *JMAPHandler) calendarEventGetShared(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID  string `json:"accountId"`
		OwnerEmail string `json:"ownerEmail"`
		After      string `json:"after,omitempty"`
		Before     string `json:"before,omitempty"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	if _, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID); errResp != nil {
		return "error", errResp
	}
	if req.OwnerEmail == "" {
		return methodError("invalidArguments", "ownerEmail is required")
	}
	if h.pool == nil {
		empty, _ := json.Marshal(map[string]any{"accountId": req.AccountID, "ownerEmail": req.OwnerEmail, "list": []any{}})
		return "CalendarEvent/getShared", empty
	}
	var after, before any
	if req.After != "" {
		after = req.After
	}
	if req.Before != "" {
		before = req.Before
	}
	var result json.RawMessage
	if err := h.pool.QueryRow(ctx,
		`SELECT jmap_calendar_event_get_shared($1, $2, $3::timestamptz, $4::timestamptz)`,
		user.UserID, req.OwnerEmail, after, before,
	).Scan(&result); err != nil {
		return "error", calendarA3Error(err, h, "CalendarEvent/getShared")
	}
	return "CalendarEvent/getShared", result
}

// calendarShareGet — Calendar/shareGet: list the grants on a calendar the account owns.
func (h *JMAPHandler) calendarShareGet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID  string `json:"accountId"`
		CalendarID string `json:"calendarId"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	calID, errJSON := parseArg(req.CalendarID, "calendarId")
	if errJSON != nil {
		return "error", errJSON
	}
	if h.pool == nil {
		empty, _ := json.Marshal(map[string]any{"accountId": req.AccountID, "calendarId": req.CalendarID, "list": []any{}})
		return "Calendar/shareGet", empty
	}
	var result json.RawMessage
	result, err := h.caller.CallScoped(ctx, accountID, "jmap_calendar_share_get", calID)
	if err != nil {
		return "error", calendarA3Error(err, h, "Calendar/shareGet")
	}
	return "Calendar/shareGet", result
}

// calendarShareSet — Calendar/shareSet: grant/revoke calendar_acls (owner/admin only).
func (h *JMAPHandler) calendarShareSet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID  string          `json:"accountId"`
		CalendarID string          `json:"calendarId"`
		Grants     json.RawMessage `json:"grants,omitempty"`
		Revokes    json.RawMessage `json:"revokes,omitempty"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	calID, errJSON := parseArg(req.CalendarID, "calendarId")
	if errJSON != nil {
		return "error", errJSON
	}
	grants := req.Grants
	if len(grants) == 0 {
		grants = json.RawMessage(`[]`)
	}
	revokes := req.Revokes
	if len(revokes) == 0 {
		revokes = json.RawMessage(`[]`)
	}
	if h.pool == nil {
		ok, _ := json.Marshal(map[string]any{"accountId": req.AccountID, "calendarId": req.CalendarID})
		return "Calendar/shareSet", ok
	}
	var result json.RawMessage
	if err := h.pool.QueryRow(ctx,
		`SELECT jmap_calendar_share_set($1, $2, $3::jsonb, $4::jsonb)`,
		accountID, calID, string(grants), string(revokes),
	).Scan(&result); err != nil {
		return "error", calendarA3Error(err, h, "Calendar/shareSet")
	}
	return "Calendar/shareSet", result
}

// calendarDelegateList — Calendar/delegateList: the managers the viewer may act for
// (mailbox_delegates grants that authorize calendar respond). Read-only.
func (h *JMAPHandler) calendarDelegateList(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID string `json:"accountId"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	if _, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID); errResp != nil {
		return "error", errResp
	}
	if h.workerPool == nil {
		empty, _ := json.Marshal(map[string]any{"accountId": req.AccountID, "list": []any{}})
		return "Calendar/delegateList", empty
	}
	// Resolve which mailboxes the authenticated user may respond for: a full_access or
	// manage_calendar delegate grant. Project the owner email + display name.
	// On h.workerPool (BYPASSRLS): a delegate-side read is cross-mailbox-for-one-user
	// (rows live on the MANAGERS' mailboxes, naming the viewer — native-RLS V090);
	// R1 by d.user_id = the authenticated user.
	rows, err := h.workerPool.Query(ctx,
		`SELECT mb.email, COALESCE(u.display_name, mb.email) AS name, d.permission
		   FROM mailbox_delegates d
		   JOIN mailboxes mb ON mb.id = d.mailbox_id
		   LEFT JOIN users u ON u.id = mb.user_id
		  WHERE d.user_id = $1
		    AND d.permission IN ('full_access','manage_calendar')
		  ORDER BY name`,
		user.UserID,
	)
	if err != nil {
		return "error", calendarA3Error(err, h, "Calendar/delegateList")
	}
	defer rows.Close()
	list := make([]map[string]any, 0)
	for rows.Next() {
		var email, name, perm string
		if err := rows.Scan(&email, &name, &perm); err != nil {
			return "error", calendarA3Error(err, h, "Calendar/delegateList")
		}
		list = append(list, map[string]any{"email": email, "name": name, "permission": perm})
	}
	if err := rows.Err(); err != nil {
		return "error", calendarA3Error(err, h, "Calendar/delegateList")
	}
	out, _ := json.Marshal(map[string]any{
		"accountId": h.GetAccountID(ctx, user.UserID),
		"list":      list,
	})
	return "Calendar/delegateList", out
}

// calendarEventSetOccurrence — CalendarEvent/setOccurrence: occurrence/following/series.
func (h *JMAPHandler) calendarEventSetOccurrence(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID    string          `json:"accountId"`
		MasterID     string          `json:"masterId"`
		RecurrenceID string          `json:"recurrenceId"`
		Scope        string          `json:"scope"`
		Patch        json.RawMessage `json:"patch,omitempty"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	masterID, errJSON := parseArg(req.MasterID, "masterId")
	if errJSON != nil {
		return "error", errJSON
	}
	if req.Scope != "this" && req.Scope != "following" && req.Scope != "series" {
		return methodError("invalidArguments", "scope must be this, following, or series")
	}
	patch := req.Patch
	if len(patch) == 0 {
		patch = json.RawMessage(`{}`)
	}
	if h.pool == nil {
		ok, _ := json.Marshal(map[string]any{"accountId": req.AccountID, "ok": true, "scope": req.Scope})
		return "CalendarEvent/setOccurrence", ok
	}
	var result json.RawMessage
	if err := h.pool.QueryRow(ctx,
		`SELECT jmap_calendar_event_set_occurrence($1, $2, $3::timestamptz, $4, $5::jsonb)`,
		accountID, masterID, req.RecurrenceID, req.Scope, string(patch),
	).Scan(&result); err != nil {
		return "error", calendarA3Error(err, h, "CalendarEvent/setOccurrence")
	}
	// Occurrence-scoped iTIP outbound (Task 9): a scope='this' edit/delete of a
	// meeting occurrence nests a calendar_send_invite-shaped payload under
	// "invitePayload" (REQUEST for an edit, CANCEL for excluded:true), reusing
	// the exact sendUpdateInvite→serializeAndEnqueueInvite egress path
	// CalendarEvent/sendUpdate already uses — same queue, same worker.
	if payload, ok := extractInvitePayload(result); ok {
		h.sendUpdateInvite(ctx, accountID, payload)
	}
	return "CalendarEvent/setOccurrence", result
}

// calendarEventResourceList — CalendarEvent/resourceList: bookable rooms/equipment.
func (h *JMAPHandler) calendarEventResourceList(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
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
		return "CalendarEvent/resourceList", empty
	}
	var result json.RawMessage
	result, err := h.caller.CallScoped(ctx, accountID, "jmap_calendar_resource_list")
	if err != nil {
		return "error", calendarA3Error(err, h, "CalendarEvent/resourceList")
	}
	return "CalendarEvent/resourceList", result
}

// calendarEventSendUpdate — CalendarEvent/sendUpdate: bump SEQUENCE + re-issue REQUEST.
func (h *JMAPHandler) calendarEventSendUpdate(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID string `json:"accountId"`
		EventID   string `json:"eventId"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	eventID, errJSON := parseArg(req.EventID, "eventId")
	if errJSON != nil {
		return "error", errJSON
	}
	if h.pool == nil {
		ok, _ := json.Marshal(map[string]any{"accountId": req.AccountID, "eventId": req.EventID})
		return "CalendarEvent/sendUpdate", ok
	}
	var result json.RawMessage
	result, err := h.caller.CallScoped(ctx, accountID, "jmap_calendar_event_send_update", eventID)
	if err != nil {
		return "error", calendarA3Error(err, h, "CalendarEvent/sendUpdate")
	}
	// Re-issue the iMIP REQUEST for the bumped meeting (best-effort, async), reusing the
	// invite egress path. The reducer already bumped SEQUENCE + state.
	h.sendUpdateInvite(ctx, accountID, result)
	return "CalendarEvent/sendUpdate", result
}

// sendUpdateInvite enqueues an iMIP REQUEST from a send-update payload (the
// calendar_send_invite shape). Skipped when the payload is an error shape (notMeeting /
// noRecipients) or when MinIO is not configured (unit tests). Best-effort; never blocks
// the JMAP response. The MIME build + blob + enqueue is the shared serializeAndEnqueueInvite
// worker (same one the CalendarEvent/set create path uses — one helper, two callers).
func (h *JMAPHandler) sendUpdateInvite(ctx context.Context, accountID int64, payload json.RawMessage) {
	if h.minio == nil || h.pool == nil {
		return
	}
	var p struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return
	}
	if p.Type != "" { // error shape (notMeeting / noRecipients / notFound)
		return
	}
	// Detach from the request lifecycle exactly like the create path (calendar.go):
	// the HTTP request ctx is cancelled the moment this handler returns, which would
	// cancel the background blob PutObject + outbound_queue INSERT mid-flight ("context
	// canceled") — leaving the SEQUENCE bumped but the updated REQUEST never enqueued.
	bgCtx, bgCancel := context.WithTimeout(context.Background(), 5*time.Minute)
	go func() {
		defer func() {
			if r := recover(); r != nil && h.logger != nil {
				h.logger.Error("sendUpdateInvite panic", "panic", r)
			}
		}()
		defer bgCancel()
		h.serializeAndEnqueueInvite(bgCtx, payload)
	}()
}
