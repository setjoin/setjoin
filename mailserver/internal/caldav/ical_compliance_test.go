package caldav

import (
	"strings"
	"testing"
	"time"
)

// TestICalendar_DTSTAMP_Mandatory verifies RFC 5545 §3.8.7.2:
// DTSTAMP is MANDATORY in VEVENT/VTODO/VJOURNAL/VFREEBUSY.
func TestICalendar_DTSTAMP_Mandatory(t *testing.T) {
	ev := CalendarEvent{
		UID:   "test-uid",
		Title: "Test Event",
		Start: time.Now(),
		End:   time.Now().Add(1 * time.Hour),
	}
	ical := eventToICal(ev)
	if !strings.Contains(ical, "DTSTAMP:") {
		t.Error("iCalendar output MUST contain DTSTAMP property (RFC 5545 §3.8.7.2)")
	}
	// DTSTAMP must appear after BEGIN:VEVENT and before END:VEVENT
	beginIdx := strings.Index(ical, "BEGIN:VEVENT")
	dtstampIdx := strings.Index(ical, "DTSTAMP:")
	endIdx := strings.Index(ical, "END:VEVENT")
	if dtstampIdx < beginIdx || dtstampIdx > endIdx {
		t.Error("DTSTAMP must be inside VEVENT component")
	}
}

// TestICalendar_SEQUENCE_Presence verifies RFC 5545 §3.8.7.4:
// SEQUENCE property must be present in iCalendar output.
func TestICalendar_SEQUENCE_Presence(t *testing.T) {
	ev := CalendarEvent{
		UID:      "test-uid",
		Title:    "Test Event",
		Start:    time.Now(),
		End:      time.Now().Add(1 * time.Hour),
		Sequence: 3,
	}
	ical := eventToICal(ev)
	if !strings.Contains(ical, "SEQUENCE:3") {
		t.Error("iCalendar output MUST contain SEQUENCE property (RFC 5545 §3.8.7.4)")
	}
}

// TestICalendar_ValueEscaping verifies RFC 5545 §3.3.11:
// Property values must escape \ ; , and newline characters.
func TestICalendar_ValueEscaping(t *testing.T) {
	ev := CalendarEvent{
		UID:         "test-uid",
		Title:       "Test; Event, With\\Special\nChars",
		Description: "Description with; commas, and\\backslashes",
		Start:       time.Now(),
		End:         time.Now().Add(1 * time.Hour),
	}
	ical := eventToICal(ev)

	// The escaped values should appear in the output
	if !strings.Contains(ical, "SUMMARY:Test\\;") {
		t.Error("semicolons in SUMMARY must be escaped as \\; (RFC 5545 §3.3.11)")
	}
	if !strings.Contains(ical, "DESCRIPTION:Description") {
		t.Error("DESCRIPTION must be present in output")
	}
}

// TestICalendar_LineFolding_UTF8_Safe verifies RFC 5545 §3.1:
// Line folding must not split multi-byte UTF-8 characters.
func TestICalendar_LineFolding_UTF8_Safe(t *testing.T) {
	// Create a string just over 75 bytes with a multi-byte character at the boundary
	longStr := strings.Repeat("a", 70) + "é" + strings.Repeat("b", 10)
	result := escapeLine(longStr)

	// The result must not contain the UTF-8 replacement character or broken sequences
	if strings.Contains(result, "\ufffd") {
		t.Error("line folding must not produce invalid UTF-8")
	}

	// Every segment should be valid content (no corrupted multi-byte chars)
	segments := strings.Split(result, "\r\n ")
	for _, seg := range segments {
		if len(seg) > 75 {
			t.Errorf("folded line segment exceeds 75 octets: %d bytes", len(seg))
		}
	}
}

// TestICalendar_LineFolding_ShortLines_Unchanged verifies short lines aren't folded.
func TestICalendar_LineFolding_ShortLines_Unchanged(t *testing.T) {
	short := "SUMMARY:Hello World"
	result := escapeLine(short)
	if result != short {
		t.Error("lines <= 75 octets must not be folded")
	}
}

// TestICalendar_ParseDateTime_UTC verifies UTC date-time parsing.
func TestICalendar_ParseDateTime_UTC(t *testing.T) {
	tm, err := parseDateTime("20260101T120000Z")
	if err != nil {
		t.Fatalf("failed to parse UTC date-time: %v", err)
	}
	if !tm.UTC().Equal(tm) {
		t.Error("UTC date-time must return UTC time")
	}
	if tm.Year() != 2026 || tm.Month() != 1 || tm.Day() != 1 {
		t.Errorf("wrong date: %v", tm)
	}
}

// TestICalendar_ParseDateTime_Offset verifies UTC offset parsing.
func TestICalendar_ParseDateTime_Offset(t *testing.T) {
	tm, err := parseDateTime("20260101T120000-0700")
	if err != nil {
		t.Fatalf("failed to parse offset date-time: %v", err)
	}
	expected := time.Date(2026, 1, 1, 19, 0, 0, 0, time.UTC)
	if !tm.Equal(expected) {
		t.Errorf("UTC offset -0700: expected %v, got %v", expected, tm)
	}
}

// TestICalendar_ParseDateTime_Floating verifies floating time parsing.
func TestICalendar_ParseDateTime_Floating(t *testing.T) {
	tm, err := parseDateTime("20260101T120000")
	if err != nil {
		t.Fatalf("failed to parse floating date-time: %v", err)
	}
	if tm.Year() != 2026 || tm.Month() != 1 || tm.Day() != 1 {
		t.Errorf("wrong date from floating time: %v", tm)
	}
}

// TestICalendar_ParseDateTime_FractionalSeconds verifies fractional second parsing.
func TestICalendar_ParseDateTime_FractionalSeconds(t *testing.T) {
	tm, err := parseDateTime("20260101T120000.500Z")
	if err != nil {
		t.Fatalf("failed to parse date-time with fractional seconds: %v", err)
	}
	if tm.Year() != 2026 || tm.Minute() != 0 {
		t.Errorf("fractional seconds should not affect time parsing: %v", tm)
	}
}

// TestICalendar_ParseDateTime_DateOnly verifies date-only format parsing.
func TestICalendar_ParseDateTime_DateOnly(t *testing.T) {
	tm, err := parseDateTime("20260101")
	if err != nil {
		t.Fatalf("failed to parse date-only format: %v", err)
	}
	if tm.Year() != 2026 || tm.Month() != 1 || tm.Day() != 1 {
		t.Errorf("wrong date from date-only: %v", tm)
	}
}

// TestICalendar_Structure_HasRequiredFields verifies RFC 5545 §3.6.1:
// VEVENT must contain DTSTAMP, UID, and at minimum one of DTSTART.
func TestICalendar_Structure_HasRequiredFields(t *testing.T) {
	ev := CalendarEvent{
		UID:   "test-uid",
		Title: "Test Event",
		Start: time.Now(),
		End:   time.Now().Add(1 * time.Hour),
	}
	ical := eventToICal(ev)

	required := []string{
		"BEGIN:VCALENDAR",
		"VERSION:2.0",
		"PRODID:",
		"BEGIN:VEVENT",
		"DTSTAMP:",
		"SEQUENCE:",
		"UID:",
		"SUMMARY:",
		"DTSTART:",
		"DTEND:",
		"END:VEVENT",
		"END:VCALENDAR",
	}
	for _, req := range required {
		if !strings.Contains(ical, req) {
			t.Errorf("iCalendar output missing required field: %s", req)
		}
	}
}

// TestICalendar_AllDay_Event_Format verifies all-day event date format.
func TestICalendar_AllDay_Event_Format(t *testing.T) {
	ev := CalendarEvent{
		UID:    "test-uid",
		Title:  "All Day Event",
		Start:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		End:    time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
		AllDay: true,
	}
	ical := eventToICal(ev)
	if !strings.Contains(ical, "DTSTART;VALUE=DATE:20260101") {
		t.Error("all-day events must use VALUE=DATE format")
	}
	if !strings.Contains(ical, "DTEND;VALUE=DATE:20260102") {
		t.Error("all-day events must have DTEND in VALUE=DATE format")
	}
}

// TestICalendar_FormatAttendee_CN_Escaped verifies attendee CN values are escaped.
func TestICalendar_FormatAttendee_CN_Escaped(t *testing.T) {
	a := Attendee{
		Email:  "test@example.com",
		Name:   "Smith; John",
		Role:   "required",
		Status: "accepted",
		RSVP:   true,
	}
	line := formatAttendee("ATTENDEE", a)
	// Semicolons in names must be escaped
	if strings.Contains(line, "CN=Smith;") {
		t.Error("semicolons in attendee CN must be escaped")
	}
}

// TestICalendar_RoundTrip preserves event data through parse→serialize→parse.
func TestICalendar_RoundTrip(t *testing.T) {
	original := CalendarEvent{
		UID:         "test-uid-123",
		Title:       "Test Event",
		Description: "A test event",
		Location:    "Room 101",
		Start:       time.Date(2026, 6, 15, 14, 0, 0, 0, time.UTC),
		End:         time.Date(2026, 6, 15, 15, 0, 0, 0, time.UTC),
		Status:      "confirmed",
		Sequence:    1,
		Organizer:   Attendee{Email: "org@example.com", Name: "Organizer"},
		Attendees: []Attendee{
			{Email: "alice@example.com", Name: "Alice", Role: "required", Status: "accepted"},
		},
	}

	ical := eventToICal(original)
	parsed, err := parseICal(ical)
	if err != nil {
		t.Fatalf("round-trip parse failed: %v", err)
	}

	if parsed.UID != original.UID {
		t.Errorf("round-trip UID: expected %q, got %q", original.UID, parsed.UID)
	}
	if parsed.Title != original.Title {
		t.Errorf("round-trip Title: expected %q, got %q", original.Title, parsed.Title)
	}
	if parsed.Description != original.Description {
		t.Errorf("round-trip Description: expected %q, got %q", original.Description, parsed.Description)
	}
	if parsed.Status != original.Status {
		t.Errorf("round-trip Status: expected %q, got %q", original.Status, parsed.Status)
	}
}

// TestICalendar_DefaultSequence_IsZero verifies default sequence value is 0.
func TestICalendar_DefaultSequence_IsZero(t *testing.T) {
	ev := CalendarEvent{
		UID:   "test",
		Title: "Test",
		Start: time.Now(),
		End:   time.Now().Add(1 * time.Hour),
	}
	ical := eventToICal(ev)
	if !strings.Contains(ical, "SEQUENCE:0") {
		t.Error("default SEQUENCE must be 0")
	}
}

// TestICalendar_EXDATE_Output verifies EXDATE is serialized in iCal output.
func TestICalendar_EXDATE_Output(t *testing.T) {
	exDate := time.Date(2026, 6, 10, 14, 0, 0, 0, time.UTC)
	ev := CalendarEvent{
		UID:    "recurring-uid",
		Title:  "Weekly Standup",
		Start:  time.Date(2026, 1, 5, 9, 0, 0, 0, time.UTC),
		End:    time.Date(2026, 1, 5, 9, 30, 0, 0, time.UTC),
		RRULE:  "FREQ=WEEKLY",
		EXDATE: []time.Time{exDate},
	}
	ical := eventToICal(ev)
	if !strings.Contains(ical, "EXDATE:20260610T140000Z") {
		t.Errorf("iCal must contain EXDATE; got:\n%s", ical)
	}
}

// TestICalendar_EXDATE_Empty produces no EXDATE lines when slice is empty.
func TestICalendar_EXDATE_Empty(t *testing.T) {
	ev := CalendarEvent{
		UID:    "recurring-uid",
		Title:  "Weekly Standup",
		Start:  time.Date(2026, 1, 5, 9, 0, 0, 0, time.UTC),
		End:    time.Date(2026, 1, 5, 9, 30, 0, 0, time.UTC),
		RRULE:  "FREQ=WEEKLY",
		EXDATE: nil,
	}
	ical := eventToICal(ev)
	if strings.Contains(ical, "EXDATE:") {
		t.Error("iCal must NOT contain EXDATE when slice is nil")
	}
}

// TestICalendar_TRANSP_Output verifies TRANSP is written when set.
func TestICalendar_TRANSP_Output(t *testing.T) {
	ev := CalendarEvent{
		UID:    "transparent-event",
		Title:  "Lunch Break",
		Start:  time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC),
		End:    time.Date(2026, 6, 5, 13, 0, 0, 0, time.UTC),
		Transp: "TRANSPARENT",
	}
	ical := eventToICal(ev)
	if !strings.Contains(ical, "TRANSP:TRANSPARENT") {
		t.Errorf("iCal must contain TRANSP:TRANSPARENT; got:\n%s", ical)
	}
}

// TestICalendar_TRANSP_Default_Omitted verifies TRANSP is omitted when empty.
func TestICalendar_TRANSP_Default_Omitted(t *testing.T) {
	ev := CalendarEvent{
		UID:   "opaque-event",
		Title: "Default Event",
		Start: time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC),
		End:   time.Date(2026, 6, 5, 13, 0, 0, 0, time.UTC),
	}
	ical := eventToICal(ev)
	if strings.Contains(ical, "TRANSP:") {
		t.Error("iCal must NOT contain TRANSP when not set")
	}
}
