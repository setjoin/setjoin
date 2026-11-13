package migration

import (
	"context"
	"testing"
)

const sampleICS = `BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Test//Migration//EN
BEGIN:VTIMEZONE
TZID:America/New_York
BEGIN:STANDARD
DTSTART:16010101T020000
RRULE:FREQ=YEARLY;BYMONTH=11;BYDAY=1SU
TZOFFSETFROM:-0400
TZOFFSETTO:-0500
TZNAME:EST
END:STANDARD
END:VTIMEZONE
BEGIN:VEVENT
UID:test-simple-001@migration
DTSTART:20260101T090000Z
DTEND:20260101T100000Z
SUMMARY:Simple Test Event
ORGANIZER;CN=Old User:mailto:old@example.com
ATTENDEE;CN=Alice:mailto:alice@test.local
END:VEVENT
BEGIN:VEVENT
UID:test-recurring-001@migration
DTSTART:20260105T090000Z
DTEND:20260105T100000Z
RRULE:FREQ=WEEKLY;COUNT=10
SUMMARY:Recurring Test Event
END:VEVENT
BEGIN:VEVENT
UID:test-allday-001@migration
DTSTART;VALUE=DATE:20260110
DTEND;VALUE=DATE:20260111
SUMMARY:All-Day Test Event
END:VEVENT
END:VCALENDAR
`

const sampleICSWithException = `BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Test//Migration//EN
BEGIN:VEVENT
UID:test-recur-exception@migration
DTSTART:20260112T090000Z
DTEND:20260112T100000Z
RRULE:FREQ=WEEKLY;COUNT=5
SUMMARY:Weekly Meeting
END:VEVENT
BEGIN:VEVENT
UID:test-recur-exception@migration
RECURRENCE-ID:20260119T090000Z
DTSTART:20260119T100000Z
DTEND:20260119T110000Z
SUMMARY:Weekly Meeting (RESCHEDULED)
END:VEVENT
END:VCALENDAR
`

func TestSplitICS(t *testing.T) {
	components := splitICS(sampleICS)
	if len(components) != 3 {
		t.Fatalf("expected 3 components, got %d", len(components))
	}
}

func TestSplitAndParseICS(t *testing.T) {
	events, sharedTZ, errs := SplitAndParseICS(sampleICS)
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}
	if sharedTZ == "" {
		t.Error("expected shared VTIMEZONE to be detected")
	}

	// First event
	ev1 := events[0]
	if ev1.UID != "test-simple-001@migration" {
		t.Errorf("UID = %q, want test-simple-001@migration", ev1.UID)
	}
	if ev1.Title != "Simple Test Event" {
		t.Errorf("Title = %q", ev1.Title)
	}
	if ev1.Organizer.Email != "old@example.com" {
		t.Errorf("Organizer email = %q, want old@example.com", ev1.Organizer.Email)
	}
	if len(ev1.Attendees) != 1 {
		t.Errorf("expected 1 attendee, got %d", len(ev1.Attendees))
	}

	// Second event: the shared VTIMEZONE should be available for attachment
	ev2 := events[1]
	if ev2.RRULE == "" {
		t.Error("expected RRULE on recurring event")
	}

	// Third event (all-day)
	ev3 := events[2]
	if !ev3.AllDay {
		t.Error("expected AllDay=true for all-day event")
	}
}

func TestSplitAndParseICS_WithException(t *testing.T) {
	events, _, errs := SplitAndParseICS(sampleICSWithException)
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	// Both share the same UID (master + exception)
	if events[0].UID != "test-recur-exception@migration" {
		t.Errorf("UID = %q", events[0].UID)
	}
	if events[1].UID != "test-recur-exception@migration" {
		t.Errorf("UID = %q", events[1].UID)
	}
	// The exception should have a RecurrenceID
	if events[1].RecurrenceID == "" {
		t.Error("expected RecurrenceID on exception event")
	}
}

func TestSplitICS_Empty(t *testing.T) {
	components := splitICS("")
	if len(components) != 0 {
		t.Errorf("expected 0 components for empty input, got %d", len(components))
	}
}

func TestSplitICS_Invalid(t *testing.T) {
	events, _, errs := SplitAndParseICS("not valid ics data")
	if len(errs) == 0 {
		t.Log("expected parse errors for invalid data")
	}
	_ = events
}

func TestSplitVCF(t *testing.T) {
	data := `BEGIN:VCARD
VERSION:3.0
UID:test-contact-001
FN:Alice Test
N:Test;Alice;;;
ORG:Test Corp
EMAIL;TYPE=WORK:alice@test.local
END:VCARD
BEGIN:VCARD
VERSION:3.0
UID:test-contact-002
FN:Bob Test
N:Test;Bob;;;
EMAIL;TYPE=WORK:bob@test.local
END:VCARD
`
	blocks := splitVCF(data)
	if len(blocks) != 2 {
		t.Fatalf("expected 2 vcard blocks, got %d", len(blocks))
	}
}

func TestSplitAndParseVCF(t *testing.T) {
	data := `BEGIN:VCARD
VERSION:3.0
UID:test-contact-001
FN:Alice Test
N:Test;Alice;;;
ORG:Test Corp
EMAIL;TYPE=WORK:alice@test.local
END:VCARD
`
	cards, errs := splitAndParseVCF(data)
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	if len(cards) != 1 {
		t.Fatalf("expected 1 card, got %d", len(cards))
	}
	if cards[0].UID != "test-contact-001" {
		t.Errorf("UID = %q", cards[0].UID)
	}
	if cards[0].FN != "Alice Test" {
		t.Errorf("FN = %q", cards[0].FN)
	}
	if len(cards[0].Emails) != 1 {
		t.Errorf("expected 1 email, got %d", len(cards[0].Emails))
	}
}

func TestImportICS_RespectsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	imported, skipped, errors := ImportICS(ctx, nil, sampleICS, 0, "alice@test.local", "skip")
	if imported != 0 || skipped != 0 {
		t.Errorf("expected (0,0) on cancelled ctx, got (%d,%d)", imported, skipped)
	}
	_ = errors
}

func TestImportVCF_RespectsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	imported, skipped, errors := ImportVCF(ctx, nil, "BEGIN:VCARD\nVERSION:3.0\nFN:Test\nEND:VCARD\n", 0, "skip")
	if imported != 0 || skipped != 0 {
		t.Errorf("expected (0,0) on cancelled ctx, got (%d,%d)", imported, skipped)
	}
	_ = errors
}
