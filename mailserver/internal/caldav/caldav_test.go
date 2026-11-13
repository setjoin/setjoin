package caldav

import (
	"encoding/xml"
	"strings"
	"testing"
	"time"

	"setjoin.com/mailserver/internal/webdav"
)

// TestEventToICalWithOverrides: a recurring master with one detached override
// must serialize as ONE VCALENDAR containing TWO VEVENTs sharing the master's
// UID — the exception rides inside the master resource (RFC 4791 §4.1), not as
// a second resource. The override VEVENT carries RECURRENCE-ID; the master
// VEVENT still carries its own EXDATE (a separately-excluded occurrence).
func TestEventToICalWithOverrides(t *testing.T) {
	h := &Handler{}
	loc := time.UTC
	master := &eventRow{
		UID:           "s1",
		ComponentType: "VEVENT",
		Title:         "Standup",
		Status:        "confirmed",
		RRULE:         strPtr("FREQ=DAILY"),
		EXDATE:        []time.Time{time.Date(2026, 8, 10, 10, 0, 0, 0, loc)},
		StartAt:       time.Date(2026, 8, 1, 10, 0, 0, 0, loc),
		EndAt:         time.Date(2026, 8, 1, 10, 30, 0, 0, loc),
		ETag:          "m1",
	}
	ovr := &eventRow{
		UID:                "s1",
		ComponentType:      "VEVENT",
		Title:              "Standup (moved)",
		Status:             "confirmed",
		RecurrenceOverride: timePtr(time.Date(2026, 8, 3, 10, 0, 0, 0, loc)),
		StartAt:            time.Date(2026, 8, 3, 14, 0, 0, 0, loc),
		EndAt:              time.Date(2026, 8, 3, 14, 30, 0, 0, loc),
		ETag:               "o1",
	}

	ics := h.eventToICalWithOverrides(master, []*eventRow{ovr})

	if got := strings.Count(ics, "BEGIN:VCALENDAR"); got != 1 {
		t.Fatalf("expected exactly 1 VCALENDAR envelope, got %d:\n%s", got, ics)
	}
	if got := strings.Count(ics, "BEGIN:VEVENT"); got != 2 {
		t.Fatalf("expected exactly 2 VEVENTs (master + override), got %d:\n%s", got, ics)
	}
	if !strings.Contains(ics, "RECURRENCE-ID:20260803T100000Z") {
		t.Errorf("override VEVENT must carry RECURRENCE-ID for the ORIGINAL occurrence instant:\n%s", ics)
	}
	if !strings.Contains(ics, "EXDATE:20260810T100000Z") {
		t.Errorf("master VEVENT must still carry its own EXDATE:\n%s", ics)
	}
	if got := strings.Count(ics, "UID:s1"); got != 2 {
		t.Errorf("both VEVENTs must share the master UID (RFC 4791 %%4.1), got %d:\n%s", got, ics)
	}
}

func strPtr(s string) *string        { return &s }
func timePtr(t time.Time) *time.Time { return &t }

// appleICS mimics an Apple Calendar PUT for a recurring event with one
// exception: EXDATE;TZID=... on the master, plus a second VEVENT carrying
// RECURRENCE-ID;TZID=... for the moved occurrence.
const appleICS = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\n" +
	"BEGIN:VEVENT\r\nUID:apple-1\r\nSUMMARY:Standup\r\n" +
	"DTSTART;TZID=America/New_York:20260801T100000\r\n" +
	"DTEND;TZID=America/New_York:20260801T103000\r\n" +
	"RRULE:FREQ=WEEKLY\r\n" +
	"EXDATE;TZID=America/New_York:20260810T100000\r\n" +
	"END:VEVENT\r\n" +
	"BEGIN:VEVENT\r\nUID:apple-1\r\nSUMMARY:Standup (moved)\r\n" +
	"RECURRENCE-ID;TZID=America/New_York:20260803T100000\r\n" +
	"DTSTART;TZID=America/New_York:20260803T140000\r\n" +
	"DTEND;TZID=America/New_York:20260803T143000\r\n" +
	"END:VEVENT\r\n" +
	"END:VCALENDAR\r\n"

// TestParseICalObjectsAppleException: parseICal (single-object) silently merges
// two VEVENTs by field-overwrite, losing the exception. ParseICalObjects must
// split them into two independent CalendarEvents, with Apple's
// TZID-parameterized EXDATE/RECURRENCE-ID resolved to the correct UTC instant
// (America/New_York is UTC-4 in August 2026, EDT).
func TestParseICalObjectsAppleException(t *testing.T) {
	objs, err := ParseICalObjects(appleICS)
	if err != nil {
		t.Fatalf("ParseICalObjects: %v", err)
	}
	if len(objs) != 2 {
		t.Fatalf("expected 2 objects (master + exception), got %d", len(objs))
	}
	if objs[0].RecurrenceID != "" {
		t.Errorf("master must not carry RECURRENCE-ID, got %q", objs[0].RecurrenceID)
	}
	if len(objs[0].EXDATE) != 1 {
		t.Fatalf("expected 1 EXDATE on the master, got %d", len(objs[0].EXDATE))
	}
	wantExdate := time.Date(2026, 8, 10, 14, 0, 0, 0, time.UTC) // 10:00 EDT → 14:00 UTC
	if !objs[0].EXDATE[0].Equal(wantExdate) {
		t.Errorf("EXDATE;TZID= not resolved to UTC instant: got %v, want %v", objs[0].EXDATE[0], wantExdate)
	}
	wantRecID := time.Date(2026, 8, 3, 14, 0, 0, 0, time.UTC) // 10:00 EDT → 14:00 UTC
	if !objs[1].RecurrenceIDTime.Equal(wantRecID) {
		t.Errorf("RECURRENCE-ID;TZID= not resolved to a typed UTC instant: got %v, want %v", objs[1].RecurrenceIDTime, wantRecID)
	}
	if objs[1].Title != "Standup (moved)" {
		t.Errorf("exception VEVENT title: got %q", objs[1].Title)
	}
}

// TestParseICalObjectsGoogleShape: Google emits plain UTC-Z EXDATE/RECURRENCE-ID
// (no TZID) — must land on the identical instant as the Apple TZID form above.
func TestParseICalObjectsGoogleShape(t *testing.T) {
	googleICS := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\n" +
		"BEGIN:VEVENT\r\nUID:google-1\r\nSUMMARY:Standup\r\n" +
		"DTSTART:20260801T140000Z\r\nDTEND:20260801T143000Z\r\n" +
		"RRULE:FREQ=WEEKLY\r\n" +
		"EXDATE:20260810T140000Z\r\n" +
		"END:VEVENT\r\n" +
		"BEGIN:VEVENT\r\nUID:google-1\r\nSUMMARY:Standup (moved)\r\n" +
		"RECURRENCE-ID:20260803T140000Z\r\n" +
		"DTSTART:20260803T180000Z\r\nDTEND:20260803T183000Z\r\n" +
		"END:VEVENT\r\nEND:VCALENDAR\r\n"

	objs, err := ParseICalObjects(googleICS)
	if err != nil {
		t.Fatalf("ParseICalObjects: %v", err)
	}
	if len(objs) != 2 {
		t.Fatalf("expected 2 objects, got %d", len(objs))
	}
	want := time.Date(2026, 8, 10, 14, 0, 0, 0, time.UTC)
	if !objs[0].EXDATE[0].Equal(want) {
		t.Errorf("google EXDATE: got %v, want %v", objs[0].EXDATE[0], want)
	}
	wantRecID := time.Date(2026, 8, 3, 14, 0, 0, 0, time.UTC)
	if !objs[1].RecurrenceIDTime.Equal(wantRecID) {
		t.Errorf("google RECURRENCE-ID: got %v, want %v", objs[1].RecurrenceIDTime, wantRecID)
	}
}

// TestParseICalObjectsSingleEventUnchanged: a plain single-VEVENT payload
// (the common case — every existing caller) still parses via the one-object
// wrapper parseICal, unaffected by the multi-object split.
func TestParseICalObjectsSingleEventUnchanged(t *testing.T) {
	ics := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:single-1\r\nSUMMARY:Solo\r\n" +
		"DTSTART:20260801T140000Z\r\nDTEND:20260801T143000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	ev, err := parseICal(ics)
	if err != nil {
		t.Fatalf("parseICal: %v", err)
	}
	if ev.UID != "single-1" || ev.Title != "Solo" {
		t.Errorf("single-event parse regressed: %+v", ev)
	}
}

// TestParseICalObjectsEXDATE_ValueDate: EXDATE;VALUE=DATE: form (whole-day
// exclusion) parses as a date-only instant.
func TestParseICalObjectsEXDATE_ValueDate(t *testing.T) {
	ics := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:dateonly-1\r\nSUMMARY:AllDay\r\n" +
		"DTSTART;VALUE=DATE:20260801\r\nDTEND;VALUE=DATE:20260802\r\nRRULE:FREQ=DAILY\r\n" +
		"EXDATE;VALUE=DATE:20260805\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	objs, err := ParseICalObjects(ics)
	if err != nil {
		t.Fatalf("ParseICalObjects: %v", err)
	}
	if len(objs[0].EXDATE) != 1 {
		t.Fatalf("expected 1 EXDATE, got %d", len(objs[0].EXDATE))
	}
	want := time.Date(2026, 8, 5, 0, 0, 0, 0, time.UTC)
	if !objs[0].EXDATE[0].Equal(want) {
		t.Errorf("EXDATE;VALUE=DATE: got %v, want %v", objs[0].EXDATE[0], want)
	}
}

func TestParseICalRoundTrip(t *testing.T) {
	original := CalendarEvent{
		UID:         "test-event-123@example.com",
		Title:       "Team Meeting",
		Description: "Discuss Q3 roadmap",
		Location:    "Conference Room A",
		Start:       time.Date(2024, 6, 15, 10, 0, 0, 0, time.UTC),
		End:         time.Date(2024, 6, 15, 11, 0, 0, 0, time.UTC),
		Timezone:    "UTC",
		Status:      "confirmed",
		Attendees: []Attendee{
			{Email: "alice@example.com", Name: "Alice", Role: "required", Status: "accepted", RSVP: true},
			{Email: "bob@example.com", Name: "Bob", Role: "optional", Status: "needs-action", RSVP: true},
		},
	}

	ical := eventToICal(original)
	if !strings.Contains(ical, "UID:test-event-123@example.com") {
		t.Error("missing UID in serialized iCalendar")
	}
	if !strings.Contains(ical, "SUMMARY:Team Meeting") {
		t.Error("missing SUMMARY in serialized iCalendar")
	}
	if !strings.Contains(ical, "DESCRIPTION:Discuss Q3 roadmap") {
		t.Error("missing DESCRIPTION in serialized iCalendar")
	}
	if !strings.Contains(ical, "ATTENDEE;CN=Alice;ROLE=REQ-PARTICIPANT;PARTSTAT=ACCEPTED;RSVP=TRUE:mailto:alice@example.com") {
		t.Error("missing or malformed attendee line")
	}

	parsed, err := parseICal(ical)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if parsed.UID != original.UID {
		t.Errorf("UID mismatch: got %q, want %q", parsed.UID, original.UID)
	}
	if parsed.Title != original.Title {
		t.Errorf("Title mismatch: got %q, want %q", parsed.Title, original.Title)
	}
	if parsed.Description != original.Description {
		t.Errorf("Description mismatch: got %q, want %q", parsed.Description, original.Description)
	}
	if parsed.Location != original.Location {
		t.Errorf("Location mismatch: got %q, want %q", parsed.Location, original.Location)
	}
	if parsed.Status != original.Status {
		t.Errorf("Status mismatch: got %q, want %q", parsed.Status, original.Status)
	}
	if len(parsed.Attendees) != 2 {
		t.Errorf("Attendee count: got %d, want 2", len(parsed.Attendees))
	}
}

func TestParseICalAllDay(t *testing.T) {
	input := `BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
UID:allday@example.com
SUMMARY:Holiday
DTSTART;VALUE=DATE:20240615
DTEND;VALUE=DATE:20240616
END:VEVENT
END:VCALENDAR`

	ev, err := parseICal(input)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if !ev.AllDay {
		t.Error("expected all-day event")
	}
	if ev.UID != "allday@example.com" {
		t.Errorf("UID: got %q", ev.UID)
	}
}

func TestParseICalWithTimezone(t *testing.T) {
	input := `BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
UID:tz@example.com
SUMMARY:Meeting
DTSTART;TZID=America/New_York:20240615T100000
DTEND;TZID=America/New_York:20240615T110000
END:VEVENT
END:VCALENDAR`

	ev, err := parseICal(input)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if ev.Timezone != "America/New_York" {
		t.Errorf("Timezone: got %q, want America/New_York", ev.Timezone)
	}
	if ev.Start.IsZero() {
		t.Error("Start time is zero")
	}
}

func TestParseICalWithOrganizer(t *testing.T) {
	input := `BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
UID:org@example.com
SUMMARY:Meeting
ORGANIZER;CN=Boss:mailto:boss@example.com
DTSTART:20240615T100000Z
DTEND:20240615T110000Z
END:VEVENT
END:VCALENDAR`

	ev, err := parseICal(input)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if ev.Organizer.Email == "" {
		t.Fatal("missing organizer")
	}
	if ev.Organizer.Email != "boss@example.com" {
		t.Errorf("Organizer email: got %q", ev.Organizer.Email)
	}
	if ev.Organizer.Name != "Boss" {
		t.Errorf("Organizer name: got %q", ev.Organizer.Name)
	}
}

func TestUnfoldLines(t *testing.T) {
	input := "DESCRIPTION:This is a very long line that has been folded\r\n  across multiple lines\r\nSUMMARY:Short"
	lines := unfoldLines(input)
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}
	if !strings.Contains(lines[0], "across multiple lines") {
		t.Errorf("line not unfolded correctly: %q", lines[0])
	}
}

func TestEscapeLine(t *testing.T) {
	long := strings.Repeat("a", 100)
	escaped := escapeLine(long)
	lines := strings.Split(escaped, "\r\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines after folding, got %d", len(lines))
	}
}

func TestWebDAVMultistatusSerialization(t *testing.T) {
	ms := &multistatus{
		Xmlns:  nsDAV,
		XmlnsC: nsCalDAV,
		Responses: []webdav.Response{
			{
				Href: "/caldav/1/",
				Propstats: []webdav.Propstat{
					{
						Prop: props{
							DisplayName: "Work",
							ResourceType: &resourceTypeProp{
								Collection: "",
								Calendar:   "",
							},
						},
						Status: "HTTP/1.1 200 OK",
					},
				},
			},
		},
	}

	out, err := xml.MarshalIndent(ms, "", "  ")
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	str := string(out)
	if !strings.Contains(str, `<href>/caldav/1/</href>`) {
		t.Error("missing href in output")
	}
	if !strings.Contains(str, `<displayname>Work</displayname>`) {
		t.Error("missing displayname in output")
	}
}

func TestParseTimeRange(t *testing.T) {
	filter := &calendarFilter{
		CompFilter: &compFilter{
			Name: "VEVENT",
			TimeRange: &timeRangeFilter{
				Start: "20240615T000000Z",
				End:   "20240616T000000Z",
			},
		},
	}
	start, end := parseTimeRange(filter)
	if start != "20240615T000000Z" {
		t.Errorf("start: got %q", start)
	}
	if end != "20240616T000000Z" {
		t.Errorf("end: got %q", end)
	}
}

// TestBuildPropstatNotFoundNoPanic guards the C8-webdav fix: a PROPFIND that
// requests resourcetype (and other collection-only props) on a leaf resource
// must not panic on the nil type-assertion, and must emit a 404 propstat naming
// the absent properties. Before the fix this panicked on every real CalDAV
// client (they all request resourcetype).
func TestBuildPropstatNotFoundNoPanic(t *testing.T) {
	req := &propReq{
		ResourceType:         &struct{}{},
		DisplayName:          &struct{}{},
		CurrentUserPrincipal: &struct{}{}, // collection/principal prop, absent on a leaf
	}
	// Mirrors propfindEvent's leaf builder: resourcetype and principal props
	// resolve as not-found.
	builder := func(name webdav.PropertyName) (propertyValue, bool) {
		if name == "displayname" {
			return textProperty("Meeting"), true
		}
		return propertyValue{}, false
	}

	var resp *webdav.Response
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("buildPropstat panicked on not-found property: %v", r)
			}
		}()
		resp = buildPropstat("/caldav/1/event.ics", req, builder)
	}()

	ms := &multistatus{Xmlns: nsDAV, XmlnsC: nsCalDAV, Responses: []webdav.Response{*resp}}
	out, err := xml.MarshalIndent(ms, "", "  ")
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	str := string(out)
	if !strings.Contains(str, "404 Not Found") {
		t.Errorf("expected a 404 propstat for absent properties, got:\n%s", str)
	}
	if !strings.Contains(str, "<resourcetype>") {
		t.Errorf("expected empty resourcetype element in 404 propstat, got:\n%s", str)
	}
	if !strings.Contains(str, "<displayname>Meeting</displayname>") {
		t.Errorf("expected displayname in 200 propstat, got:\n%s", str)
	}
}
