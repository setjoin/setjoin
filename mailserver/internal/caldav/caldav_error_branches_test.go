package caldav

// Free/busy-query error-path acceptance tests: every admission failure in
// handleFreeBusyQuery must fail closed with an EMPTY multistatus — never a
// 500, never another principal's busy data. Complements
// freebusy_identity_test.go, which owns the canonical-identity happy path and
// the poisoned-echo case.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
)

// fbBranchScratch builds the users/mailboxes/calendars shape for the error
// branches: user 601 with primary mailbox 301 (calendar 401), user 602 with
// ONLY a non-primary mailbox 302 (calendar 402), and calendar 403 dangling on
// a mailbox id that does not exist.
func fbBranchScratch(t *testing.T) *pgxpool.Pool {
	t.Helper()
	const schema = "caldav_fbbranches"
	pool := itipGapScratchSchema(t, schema, []string{
		`CREATE TABLE ` + schema + `.users (id bigint PRIMARY KEY, email text NOT NULL)`,
		`CREATE TABLE ` + schema + `.mailboxes (id bigint PRIMARY KEY, user_id bigint, is_primary boolean NOT NULL DEFAULT false)`,
		`CREATE TABLE ` + schema + `.calendars (id bigint PRIMARY KEY, mailbox_id bigint NOT NULL,` +
			` name text NOT NULL DEFAULT '', color text, description text, timezone text NOT NULL DEFAULT 'UTC',` +
			` is_default boolean NOT NULL DEFAULT false, is_shared boolean NOT NULL DEFAULT false)`,
		`INSERT INTO ` + schema + `.users VALUES (601, 'owner@fb.test')`,
		`INSERT INTO ` + schema + `.mailboxes VALUES (301, 601, true), (302, 602, false)`,
		`INSERT INTO ` + schema + `.calendars VALUES (401, 301), (402, 302), (403, 999)`,
	})
	return pool
}

func fbBranchRequest(t *testing.T, h *Handler, userID int64, path string, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rec := httptest.NewRecorder()
	h.handleFreeBusyQuery(rec, req, []byte(body))
	return rec
}

const fbBranchBody = `<C:free-busy-query xmlns:C="urn:ietf:params:xml:ns:caldav">` +
	`<C:time-range start="20260101T000000Z" end="20260301T000000Z"/>` +
	`</C:free-busy-query>`

// TestFreeBusyQuery_ErrorBranchesFailClosed: missing calendar, dangling
// calendar mailbox, unresolvable caller primary mailbox, unparsable time
// range, and reducer failure all produce an empty (but well-formed)
// multistatus with no VFREEBUSY content.
func TestFreeBusyQuery_ErrorBranchesFailClosed(t *testing.T) {
	pool := fbBranchScratch(t)

	cases := []struct {
		name   string
		userID int64
		cal    string
		body   string
		stub   *fbStubCaller
	}{
		{
			name:   "missing calendar",
			userID: 601,
			cal:    "/424242/",
			body:   fbBranchBody,
			stub:   &fbStubCaller{},
		},
		{
			name:   "calendar mailbox dangling",
			userID: 601,
			cal:    "/403/",
			body:   fbBranchBody,
			stub:   &fbStubCaller{},
		},
		{
			name:   "caller has no primary mailbox",
			userID: 602,
			cal:    "/402/",
			body:   fbBranchBody,
			stub:   &fbStubCaller{},
		},
		{
			name:   "unparsable time range",
			userID: 601,
			cal:    "/401/",
			body: `<C:free-busy-query xmlns:C="urn:ietf:params:xml:ns:caldav">` +
				`<C:time-range start="not-a-time" end="20260301T000000Z"/>` +
				`</C:free-busy-query>`,
			stub: &fbStubCaller{},
		},
		{
			name:   "reducer call fails",
			userID: 601,
			cal:    "/401/",
			body:   fbBranchBody,
			stub:   &fbStubCaller{err: context.DeadlineExceeded},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handler{pool: pool, caller: tc.stub, logger: noopLogger()}
			rec := fbBranchRequest(t, h, tc.userID, tc.cal, tc.body)
			if rec.Code != http.StatusMultiStatus {
				t.Fatalf("want 207 fail-closed multistatus, got %d:\n%s", rec.Code, rec.Body.String())
			}
			body := rec.Body.String()
			if strings.Contains(body, "FREEBUSY") || strings.Contains(body, "mailto:") {
				t.Errorf("error path must fail closed without free/busy content:\n%s", body)
			}
		})
	}
}

// TestFreeBusyQuery_OwnerEmailUnresolvableDropsResponse: a matching reducer
// echo for an owner whose users row is gone (dangling mailbox.user_id) drops
// the response instead of rendering an empty or wrong principal.
func TestFreeBusyQuery_OwnerEmailUnresolvableDropsResponse(t *testing.T) {
	const schema = "caldav_fbdangling"
	pool := itipGapScratchSchema(t, schema, []string{
		`CREATE TABLE ` + schema + `.users (id bigint PRIMARY KEY, email text NOT NULL)`,
		`CREATE TABLE ` + schema + `.mailboxes (id bigint PRIMARY KEY, user_id bigint, is_primary boolean NOT NULL DEFAULT false)`,
		`CREATE TABLE ` + schema + `.calendars (id bigint PRIMARY KEY, mailbox_id bigint NOT NULL,` +
			` name text NOT NULL DEFAULT '', color text, description text, timezone text NOT NULL DEFAULT 'UTC',` +
			` is_default boolean NOT NULL DEFAULT false, is_shared boolean NOT NULL DEFAULT false)`,
		// Deliberately NO users row: mailbox 701 dangles on user 701.
		`INSERT INTO ` + schema + `.mailboxes VALUES (701, 701, true)`,
		`INSERT INTO ` + schema + `.calendars VALUES (801, 701)`,
	})
	stub := &fbStubCaller{
		raw: json.RawMessage(`[{"userId":"701","intervals":[{"start":"2026-01-05T09:00:00Z","end":"2026-01-05T10:00:00Z","status":"busy"}]}]`),
	}
	h := &Handler{pool: pool, caller: stub, logger: noopLogger()}

	rec := fbBranchRequest(t, h, 701, "/801/", fbBranchBody)

	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("want 207, got %d:\n%s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); strings.Contains(body, "mailto:") {
		t.Errorf("unresolvable owner email must drop the response:\n%s", body)
	}
}

// TestEventRowToCalendarEvent_TranspAndCompleted: nullable DB columns map
// through only when present; a completed VTODO emits its COMPLETED instant.
func TestEventRowToCalendarEvent_TranspAndCompleted(t *testing.T) {
	transp := "OPAQUE"
	ce := eventRowToCalendarEvent(&eventRow{
		UID:           "todo-1",
		ComponentType: "VTODO",
		Title:         "Filing",
		Status:        "completed",
		Transp:        &transp,
		CompletedAt:   timePtr(time.Date(2026, 6, 15, 9, 30, 0, 0, time.UTC)),
		StartAt:       time.Date(2026, 6, 15, 9, 0, 0, 0, time.UTC),
		EndAt:         time.Date(2026, 6, 15, 9, 30, 0, 0, time.UTC),
	})
	if ce.Transp != "OPAQUE" {
		t.Errorf("Transp = %q, want OPAQUE", ce.Transp)
	}

	ics := componentToICalTodo(ce)
	if strings.Contains(ics, "TRANSP:") {
		t.Errorf("VTODO wire carries no TRANSP position:\n%s", ics)
	}
	if !strings.Contains(ics, "COMPLETED:20260615T093000Z") {
		t.Errorf("completed VTODO must emit its COMPLETED instant:\n%s", ics)
	}
	if !strings.Contains(ics, "STATUS:COMPLETED") {
		t.Errorf("completed VTODO must emit STATUS:COMPLETED:\n%s", ics)
	}

	vevent := eventToICal(ce)
	if !strings.Contains(vevent, "TRANSP:OPAQUE") {
		t.Errorf("VEVENT wire must carry TRANSP through eventRowToCalendarEvent:\n%s", vevent)
	}

	nilTransp := eventRowToCalendarEvent(&eventRow{UID: "todo-2", ComponentType: "VTODO", Title: "t"})
	if nilTransp.Transp != "" {
		t.Errorf("NULL transp must stay empty, got %q", nilTransp.Transp)
	}
}

// TestEventToICalWithOverrides_AllDayRecurrenceIDDateForm: an exception to an
// all-day series carries RECURRENCE-ID;VALUE=DATE with the wall date in the
// series timezone — never a timed UTC form.
func TestEventToICalWithOverrides_AllDayRecurrenceIDDateForm(t *testing.T) {
	h := &Handler{}
	master := &eventRow{
		UID:           "allday-1",
		ComponentType: "VEVENT",
		Title:         "Offsite",
		AllDay:        true,
		RRULE:         strPtr("FREQ=DAILY"),
		Timezone:      strPtr("UTC"),
		StartAt:       time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
		EndAt:         time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC),
		ETag:          "m1",
	}
	ovr := &eventRow{
		UID:                "allday-1",
		ComponentType:      "VEVENT",
		Title:              "Offsite (moved)",
		AllDay:             true,
		RecurrenceOverride: timePtr(time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)),
		StartAt:            time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC),
		EndAt:              time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC),
		ETag:               "o1",
	}

	ics := h.eventToICalWithOverrides(master, []*eventRow{ovr})

	if !strings.Contains(ics, "RECURRENCE-ID;VALUE=DATE:20260803") {
		t.Errorf("all-day override must carry the DATE-valued RECURRENCE-ID:\n%s", ics)
	}
	if strings.Contains(ics, "RECURRENCE-ID:20260803") {
		t.Errorf("all-day override must not carry a timed RECURRENCE-ID:\n%s", ics)
	}
}
