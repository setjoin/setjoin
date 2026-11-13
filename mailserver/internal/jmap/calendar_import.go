package jmap

import (
	"context"
	"encoding/json"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/migration"
)

// calendar_import.go — JMAP CalendarEvent/import: bulk-import an uploaded .ics
// file into ONE calendar the caller owns. The gateway parses the raw iCal bytes
// with the caldav parser (via migration.SplitAndParseICS — the PURE split+parse,
// never the raw-INSERT migration path) and hands the events to the
// calendar_import_ics reducer, which verifies calendar ownership and routes each
// event through jmap_calendar_event_set_create (RLS + state + notify come free).
// Registered in registerMethods() (handler.go); gated by the calendars capability.

// maxImportICSBytes bounds the uploaded .ics before parsing (DoS guard).
const maxImportICSBytes = 1 << 20 // 1 MiB

// maxImportEvents bounds the number of parsed components before the reducer call.
const maxImportEvents = 1000

func (h *JMAPHandler) calendarEventImport(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID  string `json:"accountId"`
		CalendarID string `json:"calendarId"`
		ICS        string `json:"ics"`
		Strategy   string `json:"strategy"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}

	// DoS guard: bound the payload BEFORE parsing.
	if len(req.ICS) == 0 {
		return methodError("invalidArguments", "ics is required")
	}
	if len(req.ICS) > maxImportICSBytes {
		return methodError("invalidArguments", "ics file too large")
	}

	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	calendarID, errJSON := parseArg(req.CalendarID, "calendarId")
	if errJSON != nil {
		return "error", errJSON
	}

	// Parse the uploaded iCal with the shared caldav parser (pure split+parse).
	events, _, parseErrs := migration.SplitAndParseICS(req.ICS)
	if len(events) > maxImportEvents {
		return methodError("invalidArguments", "too many events in ics file")
	}

	// Build the create-shaped JSON array the reducer consumes (shared with the
	// webcal-subscribe worker — see migration.EventsToJSON's doc for why this is
	// ONE mapping, not a per-caller copy). Only the fields
	// jmap_calendar_event_set_create reads are mapped; attendees/valarm are left
	// out (importing a personal calendar copy must not email attendees, and iCal
	// relative-trigger VALARMs are deferred — see the reducer/AGENTS notes).
	eventsJSON, err := migration.EventsToJSON(events)
	if err != nil {
		return methodError("serverFail", "could not encode events")
	}

	strategy := req.Strategy
	if strategy == "" {
		strategy = "skip"
	}

	// Route through the ownership-checked reducer (never a raw INSERT).
	result, err := h.caller.CallScoped(ctx, accountID, "calendar_import_ics",
		user.UserID, user.Email, calendarID, json.RawMessage(eventsJSON), strategy)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "calendarEventImport")
	}

	// Surface parse errors alongside the reducer result (best-effort; the import
	// itself already succeeded for the events that parsed).
	if len(parseErrs) > 0 {
		var obj map[string]json.RawMessage
		if json.Unmarshal(result, &obj) == nil {
			if pe, mErr := json.Marshal(parseErrs); mErr == nil {
				obj["parseErrors"] = pe
				if merged, mErr := json.Marshal(obj); mErr == nil {
					result = merged
				}
			}
		}
	}
	return "CalendarEvent/import", result
}
