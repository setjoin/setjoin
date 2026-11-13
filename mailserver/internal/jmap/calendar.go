package jmap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/caldav"
)

// calendar.go — JMAP Calendar family core handlers: Calendar/* and
// CalendarEvent/* (get/query/changes/set/freeBusy/queryFreeSlots/rsvp), plus
// the iMIP invite serialization + resource-booking side-effect helpers that
// only the calendar create path uses. A3 parity handlers live in calendar_a3.go;
// methods here are registered in registerMethods() (handler.go).
// See mailserver/internal/AGENTS.md.

// --- JMAP Calendar method implementations ---

func (h *JMAPHandler) calendarGet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
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
	result, err := h.caller.CallScoped(ctx, accountID, "jmap_calendar_get", idsArray)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "calendarGet")
	}
	return "Calendar/get", addNotFound(result, badIDs)
}

func (h *JMAPHandler) calendarChanges(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
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
	result, err := h.caller.CallScoped(ctx, accountID, "jmap_calendar_changes", req.SinceState)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "calendarChanges")
	}
	return "Calendar/changes", result
}

func (h *JMAPHandler) calendarSet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID string          `json:"accountId"`
		Update    json.RawMessage `json:"update,omitempty"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}

	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	var result json.RawMessage
	if len(req.Update) > 0 && string(req.Update) != "null" && jsonIsObject(req.Update) {
		res, err := h.caller.CallScoped(ctx, accountID, "jmap_calendar_set_update", req.Update)
		if err != nil {
			return "error", mapReducerErr(err, h.logger, "calendarSet")
		}
		result = res
	}
	return "Calendar/set", result
}

func (h *JMAPHandler) calendarEventGet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
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
	result, err := h.caller.CallScoped(ctx, accountID, "jmap_calendar_event_get", ids)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "calendarEventGet")
	}
	return "CalendarEvent/get", addNotFound(result, badIDs)
}

func (h *JMAPHandler) calendarEventQuery(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
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
	result, err := h.caller.CallScoped(ctx, accountID, "jmap_calendar_event_query", req.Filter, req.Sort, req.Position, req.Limit)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "calendarEventQuery")
	}
	return "CalendarEvent/query", result
}

func (h *JMAPHandler) calendarEventChanges(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
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
	result, err := h.caller.CallScoped(ctx, accountID, "jmap_calendar_event_changes", req.SinceState)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "calendarEventChanges")
	}
	return "CalendarEvent/changes", result
}

func (h *JMAPHandler) calendarEventSet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID string          `json:"accountId"`
		Create    json.RawMessage `json:"create,omitempty"`
		Update    json.RawMessage `json:"update,omitempty"`
		Destroy   []string        `json:"destroy,omitempty"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}

	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	var updateResult, destroyResult, createResult json.RawMessage

	if len(req.Create) > 0 && string(req.Create) != "null" && jsonIsObject(req.Create) {
		res, err := h.caller.CallScoped(ctx, accountID, "jmap_calendar_event_set_create", user.UserID, user.Email, req.Create)
		if err != nil {
			return "error", mapReducerErr(err, h.logger, "calendarEventSet create")
		}
		createResult = res
		orgEmail := user.Email
		orgName := ""
		if d := extractDelegatedFrom(req.Create); d != "" {
			orgEmail = d
			orgName = ""
		}

		// The created map is createKey -> new event id (string). Everything below keys off
		// the freshly-created event ids; the reducers own the decisions (who to invite,
		// which room to book), the gateway only serializes + enqueues.
		eventIDs, keyByEventID := createdEventIDs(createResult)

		// A3: book any room/equipment resources invited on the created events. The
		// resolution (resource email -> room calendar) and the per-resource
		// calendar_book_resource fan-out now run inside calendar_finalize_create_bookings;
		// the booker is the caller's users.id (account_scope), not the mailbox id (ADR-003).
		// Synchronous, like the old inline booking. The reducer keys outcomes by event id;
		// remap to the client create-keys so the resourceBookings wire shape is unchanged.
		if len(eventIDs) > 0 {
			if bookings := h.bookResourcesForCreatedEvents(ctx, accountID, eventIDs, keyByEventID); bookings != nil {
				createResult = mergeResourceBookings(createResult, bookings)
			}
		}

		// Invites: the reducer DECIDES the per-event iMIP REQUEST payloads (recipient set +
		// organizer, read from the stored rows). Done synchronously (cheap). The
		// byte-serialization + egress (BuildIMip -> blob -> outbound_queue) stays in a
		// background goroutine — best-effort, 5-min timeout, panic recovery — so a
		// serialization failure never fails the create, exactly as before.
		if len(eventIDs) > 0 {
			payloads := h.finalizeCreateInvitePayloads(ctx, accountID, eventIDs, orgEmail, orgName)
			if len(payloads) > 0 {
				bgCtx, bgCancel := context.WithTimeout(context.Background(), 5*time.Minute)
				go func() {
					defer func() {
						if r := recover(); r != nil {
							h.logger.Error("serializeAndEnqueueInvite panic", "panic", r)
						}
					}()
					defer bgCancel()
					for _, payload := range payloads {
						h.serializeAndEnqueueInvite(bgCtx, payload)
					}
				}()
			}
		}
	}

	if len(req.Update) > 0 && string(req.Update) != "null" && jsonIsObject(req.Update) {
		res, err := h.caller.CallScoped(ctx, accountID, "jmap_calendar_event_set_update", req.Update)
		if err != nil {
			return "error", mapReducerErr(err, h.logger, "calendarEventSet update")
		}
		updateResult = res
	}

	if len(req.Destroy) > 0 {
		ids, badIDs := parseIDList(req.Destroy)
		res, err := h.caller.CallScoped(ctx, accountID, "jmap_calendar_event_set_destroy", ids)
		if err != nil {
			return "error", mapReducerErr(err, h.logger, "calendarEventSet destroy")
		}
		destroyResult = addSetErrors(res, "notDestroyed", badIDs)
	}

	result := mergeSetResults(createResult, updateResult, destroyResult)
	return "CalendarEvent/set", result
}

func extractDelegatedFrom(createsJSON json.RawMessage) string {
	var creates map[string]struct {
		DelegatedFrom string `json:"delegatedFrom"`
	}
	if err := json.Unmarshal(createsJSON, &creates); err != nil {
		return ""
	}
	for _, ev := range creates {
		if ev.DelegatedFrom != "" {
			return ev.DelegatedFrom
		}
	}
	return ""
}

// createdEventIDs reads the `created` map (createKey -> new event-id string) off a
// CalendarEvent/set create result and returns the parsed event ids plus the inverse
// map (event id -> createKey) the gateway uses to re-key reducer outputs back to the
// client's create keys for the wire response.
func createdEventIDs(createResult json.RawMessage) ([]int64, map[int64]string) {
	var createWrap struct {
		Created map[string]string `json:"created"`
	}
	if err := json.Unmarshal(createResult, &createWrap); err != nil || len(createWrap.Created) == 0 {
		return nil, nil
	}
	ids := make([]int64, 0, len(createWrap.Created))
	keyByEventID := make(map[int64]string, len(createWrap.Created))
	for key, idStr := range createWrap.Created {
		id, perr := strconv.ParseInt(idStr, 10, 64)
		if perr != nil {
			continue
		}
		ids = append(ids, id)
		keyByEventID[id] = key
	}
	return ids, keyByEventID
}

// invitePayload is the per-event iMIP REQUEST payload the calendar_finalize_create_invites
// reducer produces (and the calendar_send_invite reducer's shape for the sendUpdate path).
// The gateway only serializes it — the recipient/organizer decision is the reducer's.
type invitePayload struct {
	UID            string            `json:"uid"`
	Title          string            `json:"title"`
	Description    string            `json:"description"`
	Location       string            `json:"location"`
	Start          string            `json:"start"`
	End            string            `json:"end"`
	AllDay         bool              `json:"allDay"`
	Timezone       string            `json:"timezone"`
	Status         string            `json:"status"`
	Sequence       int               `json:"sequence"`
	RRULE          string            `json:"rrule"`
	OrganizerEmail string            `json:"organizerEmail"`
	OrganizerName  string            `json:"organizerName"`
	Attendees      []caldav.Attendee `json:"attendees"`
	// RecurrenceID/Method (Task 9 — occurrence-scoped iTIP): set only by
	// jmap_calendar_event_set_occurrence's invitePayload for a scope='this'
	// edit/delete of a meeting occurrence. Absent (zero value) for every other
	// caller (create, sendUpdate) — Method then defaults to REQUEST below.
	RecurrenceID string `json:"recurrenceId,omitempty"`
	Method       string `json:"method,omitempty"`
}

// extractInvitePayload pulls the nested "invitePayload" sub-object out of
// jmap_calendar_event_set_occurrence's result (Task 9) — that reducer's
// top-level shape is {ok, eventId, scope, newState, invitePayload}, but
// sendUpdateInvite/serializeAndEnqueueInvite expect the calendar_send_invite
// shape directly (the same one create/sendUpdate already produce at the top
// level). ok=false when the key is absent OR present-but-null (a non-meeting,
// a scope other than 'this', or no non-organizer attendees — nothing to send).
func extractInvitePayload(result json.RawMessage) (json.RawMessage, bool) {
	var wrapper struct {
		InvitePayload json.RawMessage `json:"invitePayload"`
	}
	if err := json.Unmarshal(result, &wrapper); err != nil {
		return nil, false
	}
	if len(wrapper.InvitePayload) == 0 || string(wrapper.InvitePayload) == "null" {
		return nil, false
	}
	return wrapper.InvitePayload, true
}

// finalizeCreateInvitePayloads asks calendar_finalize_create_invites for the per-event
// iMIP payloads (the recipient/organizer DECISION, read from the stored rows) for the
// freshly-created events. Returns the raw payloads for the worker to serialize; an empty
// slice when nothing is to be sent (no eligible event / no recipients). Best-effort: a DB
// error logs and yields no payloads (the create already committed; invites are async).
func (h *JMAPHandler) finalizeCreateInvitePayloads(ctx context.Context, accountID int64, eventIDs []int64, organizerEmail, organizerName string) []json.RawMessage {
	if h.pool == nil || len(eventIDs) == 0 {
		return nil
	}
	rows, err := h.pool.Query(ctx,
		`SELECT calendar_finalize_create_invites($1, $2, $3, $4)`,
		accountID, eventIDs, organizerEmail, organizerName,
	)
	if err != nil {
		h.logger.Error("imip: finalize-invites decision failed", "error", err)
		return nil
	}
	defer rows.Close()
	var payloads []json.RawMessage
	for rows.Next() {
		var p json.RawMessage
		if err := rows.Scan(&p); err != nil {
			h.logger.Error("imip: finalize-invites scan failed", "error", err)
			return payloads
		}
		payloads = append(payloads, p)
	}
	return payloads
}

// EnqueueInvite is the exported invite-egress seam: build iMIP MIME, store the
// blob, enqueue outbound_queue. Used by internal/booking for booking-confirm
// invites — identical path to CalendarEvent/set create and sendUpdate.
func (h *JMAPHandler) EnqueueInvite(ctx context.Context, payload json.RawMessage) {
	h.serializeAndEnqueueInvite(ctx, payload)
}

// serializeAndEnqueueInvite is the byte-serialization + egress worker, shared by the
// CalendarEvent/set create path and CalendarEvent/sendUpdate. It takes a reducer-produced
// iMIP payload (it no longer parses raw client JSON or makes any decision), builds the iMIP
// MIME via caldav.BuildIMip, stores it as a content-addressed blob, and enqueues the
// outbound_queue row. Best-effort by contract: any failure logs and returns (the caller
// loops per payload, so one bad payload does not block the others).
func (h *JMAPHandler) serializeAndEnqueueInvite(ctx context.Context, payload json.RawMessage) {
	if h.minio == nil || h.pool == nil {
		return
	}
	mime, key, recipients, p, err := buildInviteMIME(payload)
	if err != nil {
		if p.UID == "" {
			h.logger.Error("imip: invite payload parse failed", "error", err)
		} else {
			h.logger.Warn("imip: invite serialize skipped", "uid", p.UID, "error", err)
		}
		return
	}
	if mime == "" { // nothing to send (no attendees) — not an error
		return
	}

	// Store the iMIP MIME message as a MinIO blob.
	if _, err := h.minio.PutObject(ctx, h.bucket, key,
		strings.NewReader(mime), int64(len(mime)),
		minio.PutObjectOptions{ContentType: "message/rfc822"}); err != nil {
		h.logger.Error("imip: failed to store blob", "error", err)
		return
	}

	if _, err := h.pool.Exec(ctx,
		`INSERT INTO outbound_queue (message_id, from_addr, rcpt_addrs, raw_ref, status)
		 VALUES ($1, $2, $3, $4, 'pending')`,
		p.UID, p.OrganizerEmail, recipients, key); err != nil {
		h.logger.Error("imip: failed to enqueue", "error", err)
		return
	}

	h.logger.Info("imip: invitation queued for delivery",
		"uid", p.UID, "recipients", len(recipients))
}

// buildInviteMIME is the pure (no I/O) half of serializeAndEnqueueInvite: it parses a
// reducer-produced iMIP payload, builds the iMIP REQUEST MIME via caldav.BuildIMip, and
// derives the content-addressed blob key + the recipient envelope (attendees minus the
// organizer). It makes NO decision — the recipient set and organizer are already on the
// payload. Returns ("", "", nil, p, nil) when the payload has no attendees (nothing to
// send). Split out so the byte-shape is unit-testable without MinIO / a DB pool.
func buildInviteMIME(payload json.RawMessage) (mime, blobKey string, recipients []string, p invitePayload, err error) {
	if err = json.Unmarshal(payload, &p); err != nil {
		return "", "", nil, p, err
	}
	if len(p.Attendees) == 0 {
		return "", "", nil, p, nil
	}

	start, perr := time.Parse(time.RFC3339, p.Start)
	if perr != nil {
		return "", "", nil, p, fmt.Errorf("parse start: %w", perr)
	}
	end, perr := time.Parse(time.RFC3339, p.End)
	if perr != nil {
		return "", "", nil, p, fmt.Errorf("parse end: %w", perr)
	}

	event := caldav.CalendarEvent{
		UID:          p.UID,
		Title:        p.Title,
		Description:  p.Description,
		Location:     p.Location,
		Start:        start,
		End:          end,
		AllDay:       p.AllDay,
		Timezone:     p.Timezone,
		Status:       p.Status,
		Sequence:     p.Sequence,
		RRULE:        p.RRULE,
		RecurrenceID: p.RecurrenceID,
		Organizer:    caldav.Attendee{Email: p.OrganizerEmail, Name: p.OrganizerName, Role: "organizer"},
		Attendees:    p.Attendees,
	}

	// Method defaults to REQUEST (every pre-Task-9 caller — create, sendUpdate —
	// has no "method" key); an occurrence payload sets CANCEL for a delete.
	method := caldav.MethodRequest
	if p.Method == string(caldav.MethodCancel) {
		method = caldav.MethodCancel
	}
	mime, _, err = caldav.BuildIMip(method, event, p.OrganizerEmail, p.OrganizerName)
	if err != nil {
		return "", "", nil, p, err
	}

	hash := sha256.Sum256([]byte(mime))
	blobKey = "imip/" + hex.EncodeToString(hash[:]) + ".eml"

	recipients = make([]string, 0, len(p.Attendees))
	for _, a := range p.Attendees {
		if a.Email != p.OrganizerEmail {
			recipients = append(recipients, a.Email)
		}
	}
	return mime, blobKey, recipients, p, nil
}

// bookResourcesForCreatedEvents resolves + books the room/equipment resources invited on
// the freshly-created events by calling calendar_finalize_create_bookings (the reducer that
// owns the email->room resolution + per-resource calendar_book_resource fan-out, with the
// booker = the caller's users.id via account_scope — ADR-003). The reducer returns outcomes
// keyed by EVENT id; this remaps them to the client create-keys (via keyByEventID) so the
// `resourceBookings` wire shape mergeResourceBookings emits is byte-identical to before.
// Returns nil when there is nothing to book.
func (h *JMAPHandler) bookResourcesForCreatedEvents(ctx context.Context, accountID int64, eventIDs []int64, keyByEventID map[int64]string) map[string]map[string]json.RawMessage {
	if h.pool == nil || len(eventIDs) == 0 {
		return nil
	}
	var byEventID map[string]map[string]json.RawMessage
	if err := h.pool.QueryRow(ctx,
		`SELECT calendar_finalize_create_bookings($1, $2)`,
		accountID, eventIDs,
	).Scan(&byEventID); err != nil {
		h.logger.Warn("resource booking failed", "error", err)
		return nil
	}
	if len(byEventID) == 0 {
		return nil
	}
	// Re-key event-id -> createKey for the wire response.
	outcomes := make(map[string]map[string]json.RawMessage, len(byEventID))
	for eventIDStr, rooms := range byEventID {
		eventID, perr := strconv.ParseInt(eventIDStr, 10, 64)
		if perr != nil {
			continue
		}
		key, ok := keyByEventID[eventID]
		if !ok {
			continue
		}
		outcomes[key] = rooms
	}
	if len(outcomes) == 0 {
		return nil
	}
	return outcomes
}

// mergeResourceBookings attaches a "resourceBookings" object onto the CalendarEvent/set
// create result so clients can read per-event booking outcomes alongside `created`.
func mergeResourceBookings(createResult json.RawMessage, bookings map[string]map[string]json.RawMessage) json.RawMessage {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(createResult, &obj); err != nil {
		return createResult
	}
	b, err := json.Marshal(bookings)
	if err != nil {
		return createResult
	}
	obj["resourceBookings"] = b
	merged, err := json.Marshal(obj)
	if err != nil {
		return createResult
	}
	return merged
}

// --- JMAP Calendar free/busy & rsvp ---

func (h *JMAPHandler) calendarEventFreeBusy(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID string   `json:"accountId"`
		UserIds   []string `json:"userIds"`
		Start     string   `json:"start"`
		End       string   `json:"end"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}

	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	// A malformed userId rejects (position-aware) instead of silently
	// computing availability for a subset of the requested people (c4).
	var userIDs []int64
	for i, id := range req.UserIds {
		v, ok := parseID(id)
		if !ok {
			return methodError("invalidArguments", fmt.Sprintf("invalid userIds[%d]", i))
		}
		userIDs = append(userIDs, v)
	}

	var result json.RawMessage
	err := h.pool.QueryRow(ctx,
		`SELECT calendar_free_busy($1, $2, $3::timestamptz, $4::timestamptz)`,
		accountID, userIDs, req.Start, req.End,
	).Scan(&result)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "calendarEventFreeBusy")
	}
	return "CalendarEvent/freeBusy", result
}

func (h *JMAPHandler) calendarEventQueryFreeSlots(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID        string   `json:"accountId"`
		UserIds          []string `json:"userIds"`
		Start            string   `json:"start"`
		End              string   `json:"end"`
		DurationMinutes  int      `json:"durationMinutes"`
		SlotIntervalMin  int      `json:"slotIntervalMinutes"`
		WorkingStartTime string   `json:"workingStartTime"`
		WorkingEndTime   string   `json:"workingEndTime"`
		MaxSlots         int      `json:"maxSlots"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}

	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	// Position-aware reject, as in calendarEventFreeBusy (c4).
	var userIDs []int64
	for i, id := range req.UserIds {
		v, ok := parseID(id)
		if !ok {
			return methodError("invalidArguments", fmt.Sprintf("invalid userIds[%d]", i))
		}
		userIDs = append(userIDs, v)
	}
	if len(userIDs) == 0 {
		return methodError("invalidArguments", "at least one userId is required")
	}

	durationMins := 30
	if req.DurationMinutes > 0 {
		durationMins = req.DurationMinutes
	}
	slotInterval := 15
	if req.SlotIntervalMin > 0 {
		slotInterval = req.SlotIntervalMin
	}
	workStart := "09:00"
	if req.WorkingStartTime != "" {
		workStart = req.WorkingStartTime
	}
	workEnd := "17:00"
	if req.WorkingEndTime != "" {
		workEnd = req.WorkingEndTime
	}
	maxSlots := 20
	if req.MaxSlots > 0 && req.MaxSlots <= 100 {
		maxSlots = req.MaxSlots
	}

	var result json.RawMessage
	err := h.pool.QueryRow(ctx,
		`SELECT calendar_find_free_slots($1, $2, $3::timestamptz, $4::timestamptz, $5, $6, $7::time, $8::time, $9)`,
		accountID, userIDs, req.Start, req.End,
		durationMins, slotInterval, workStart, workEnd, maxSlots,
	).Scan(&result)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "calendarEventQueryFreeSlots")
	}
	return "CalendarEvent/queryFreeSlots", result
}

func (h *JMAPHandler) calendarEventRsvp(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID string `json:"accountId"`
		EventId   string `json:"eventId"`
		Status    string `json:"status"`
		// OnBehalfOf, when set, is the email of the manager/owner the authenticated user
		// is responding for as a delegate. The viewer's accountId guard is NOT relaxed:
		// the manager's mailbox is resolved server-side and the reducer verifies the
		// authenticated user holds a mailbox_delegates grant on it (full_access /
		// manage_calendar). When empty, the normal self-RSVP path runs.
		OnBehalfOf string `json:"onBehalfOf,omitempty"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}

	if req.Status != "accepted" && req.Status != "tentative" && req.Status != "declined" {
		return methodError("invalidArguments", "status must be accepted, tentative, or declined")
	}
	eventID, _ := strconv.ParseInt(req.EventId, 10, 64)

	// Self-RSVP: account is the authenticated user's own mailbox (guard enforced).
	if req.OnBehalfOf == "" {
		accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
		if errResp != nil {
			return "error", errResp
		}
		var result json.RawMessage
		err := h.pool.QueryRow(ctx,
			`SELECT jmap_calendar_event_rsvp($1, $2, $3, $4, NULL)`,
			accountID, eventID, user.Email, req.Status,
		).Scan(&result)
		if err != nil {
			return "error", mapReducerErr(err, h.logger, "calendarEventRsvp")
		}
		return "CalendarEvent/rsvp", result
	}

	// Delegate respond: resolve the manager's primary mailbox + attendee email
	// server-side from OnBehalfOf (never trusted from accountId), pass the
	// authenticated user as p_on_behalf_of so the reducer gates on the delegate grant.
	if h.pool == nil {
		ok, _ := json.Marshal(map[string]any{"accountId": req.AccountID, "onBehalfOf": req.OnBehalfOf})
		return "CalendarEvent/rsvp", ok
	}
	var mgrMailbox int64
	if err := h.pool.QueryRow(ctx,
		`SELECT id FROM mailboxes WHERE email = $1 AND is_primary = TRUE LIMIT 1`,
		req.OnBehalfOf,
	).Scan(&mgrMailbox); err != nil {
		return methodError("notFound", "manager mailbox not found")
	}
	var result json.RawMessage
	result, err := h.caller.CallScoped(ctx, mgrMailbox, "jmap_calendar_event_rsvp", eventID, req.OnBehalfOf, req.Status, user.UserID)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "calendarEventRsvp (delegate)")
	}
	return "CalendarEvent/rsvp", result
}

// calendarEventCounter is the outbound iTIP COUNTER: the authenticated invitee proposes
// new times to the organizer. The reply-direction twin of the invite path — the reducer
// gates ownership + attendee membership and returns a NON-MUTATING proposal payload; the
// gateway then serializes it as a COUNTER iMIP (attendee→organizer) best-effort/async,
// exactly like serializeAndEnqueueInvite.
func (h *JMAPHandler) calendarEventCounter(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID string `json:"accountId"`
		EventId   string `json:"eventId"`
		Start     string `json:"start"`
		End       string `json:"end"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	if req.Start == "" || req.End == "" {
		return methodError("invalidArguments", "start and end are required")
	}

	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	eventID, _ := strconv.ParseInt(req.EventId, 10, 64)

	var payload json.RawMessage
	err := h.pool.QueryRow(ctx,
		`SELECT jmap_calendar_event_counter($1, $2, $3::timestamptz, $4::timestamptz, $5, $6)`,
		accountID, eventID, req.Start, req.End, user.Email, "",
	).Scan(&payload)
	if err != nil {
		return "error", calendarA3Error(err, h, "CalendarEvent/counter")
	}

	// Egress: serialize + enqueue the COUNTER iMIP in the background, best-effort (same
	// pattern as the create-invite path). A serialization/enqueue failure never fails the
	// call — the reducer already returned the proposal to the client.
	if h.minio != nil && h.pool != nil && len(payload) > 0 {
		bgCtx, bgCancel := context.WithTimeout(context.Background(), 5*time.Minute)
		p := payload
		go func() {
			defer func() {
				if r := recover(); r != nil {
					h.logger.Error("serializeAndEnqueueCounter panic", "panic", r)
				}
			}()
			defer bgCancel()
			h.serializeAndEnqueueCounter(bgCtx, p)
		}()
	}
	return "CalendarEvent/counter", payload
}

// counterPayload is the iMIP COUNTER payload jmap_calendar_event_counter emits. It is the
// reply-direction twin of invitePayload: a SINGLE attendee (the invitee) proposing new
// times to the organizer. Start/End are the PROPOSED times; UID + Sequence are unchanged.
type counterPayload struct {
	UID            string `json:"uid"`
	Title          string `json:"title"`
	Description    string `json:"description"`
	Location       string `json:"location"`
	Start          string `json:"start"`
	End            string `json:"end"`
	AllDay         bool   `json:"allDay"`
	Timezone       string `json:"timezone"`
	Sequence       int    `json:"sequence"`
	OrganizerEmail string `json:"organizerEmail"`
	OrganizerName  string `json:"organizerName"`
	AttendeeEmail  string `json:"attendeeEmail"`
	AttendeeName   string `json:"attendeeName"`
}

// serializeAndEnqueueCounter is the byte-serialization + egress worker for the COUNTER
// path, the inversion of serializeAndEnqueueInvite: from_addr = the countering attendee,
// envelope recipient = the organizer. Best-effort by contract — any failure logs + returns.
func (h *JMAPHandler) serializeAndEnqueueCounter(ctx context.Context, payload json.RawMessage) {
	if h.minio == nil || h.pool == nil {
		return
	}
	mime, key, recipients, p, err := buildCounterMIME(payload)
	if err != nil {
		if p.UID == "" {
			h.logger.Error("imip: counter payload parse failed", "error", err)
		} else {
			h.logger.Warn("imip: counter serialize skipped", "uid", p.UID, "error", err)
		}
		return
	}
	if mime == "" {
		return
	}

	if _, err := h.minio.PutObject(ctx, h.bucket, key,
		strings.NewReader(mime), int64(len(mime)),
		minio.PutObjectOptions{ContentType: "message/rfc822"}); err != nil {
		h.logger.Error("imip: failed to store counter blob", "error", err)
		return
	}

	if _, err := h.pool.Exec(ctx,
		`INSERT INTO outbound_queue (message_id, from_addr, rcpt_addrs, raw_ref, status)
		 VALUES ($1, $2, $3, $4, 'pending')`,
		p.UID, p.AttendeeEmail, recipients, key); err != nil {
		h.logger.Error("imip: failed to enqueue counter", "error", err)
		return
	}

	h.logger.Info("imip: counter proposal queued for delivery",
		"uid", p.UID, "organizer", p.OrganizerEmail)
}

// buildCounterMIME is the pure (no I/O) half of serializeAndEnqueueCounter — the INVERSION
// of buildInviteMIME. A COUNTER travels attendee→organizer, so BuildIMip is called with
// fromEmail = the attendee (→ From: = attendee, To: = the organizer, the only non-attendee
// party recipientList emits when the attendee is excluded). We do NOT reuse BuildIMip's
// returned recipient set (it excludes the From attendee → empty for a counter); the envelope
// is the organizer, set explicitly. DTSTART/DTEND carry the PROPOSED times; UID + SEQUENCE
// are unchanged (a counter does not bump the invitee's copy). Split out so the byte-shape is
// unit-testable without MinIO / a DB pool.
func buildCounterMIME(payload json.RawMessage) (mime, blobKey string, recipients []string, p counterPayload, err error) {
	if err = json.Unmarshal(payload, &p); err != nil {
		return "", "", nil, p, err
	}
	if p.OrganizerEmail == "" || p.AttendeeEmail == "" {
		return "", "", nil, p, fmt.Errorf("counter payload missing organizer or attendee")
	}

	start, perr := time.Parse(time.RFC3339, p.Start)
	if perr != nil {
		return "", "", nil, p, fmt.Errorf("parse start: %w", perr)
	}
	end, perr := time.Parse(time.RFC3339, p.End)
	if perr != nil {
		return "", "", nil, p, fmt.Errorf("parse end: %w", perr)
	}

	event := caldav.CalendarEvent{
		UID:         p.UID,
		Title:       p.Title,
		Description: p.Description,
		Location:    p.Location,
		Start:       start, // proposed
		End:         end,   // proposed
		AllDay:      p.AllDay,
		Timezone:    p.Timezone,
		Sequence:    p.Sequence, // unchanged
		Organizer:   caldav.Attendee{Email: p.OrganizerEmail, Name: p.OrganizerName, Role: "organizer"},
		Attendees:   []caldav.Attendee{{Email: p.AttendeeEmail, Name: p.AttendeeName, Role: "attendee"}},
	}

	mime, _, err = caldav.BuildIMip(caldav.MethodCounter, event, p.AttendeeEmail, p.AttendeeName)
	if err != nil {
		return "", "", nil, p, err
	}

	hash := sha256.Sum256([]byte(mime))
	blobKey = "imip/" + hex.EncodeToString(hash[:]) + ".eml"
	recipients = []string{p.OrganizerEmail}
	return mime, blobKey, recipients, p, nil
}
