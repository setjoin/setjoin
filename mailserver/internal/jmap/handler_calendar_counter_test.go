package jmap

import (
	"encoding/json"
	"strings"
	"testing"
)

// counterHeaderLine returns the first RFC822 header line beginning with prefix (e.g.
// "From:") in the MIME message, CR-trimmed. Empty if absent.
func counterHeaderLine(mime, prefix string) string {
	for _, raw := range strings.Split(mime, "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	return ""
}

// TestBuildCounterMIME_Direction is the load-bearing correctness proof for the outbound
// iTIP COUNTER: a counter travels attendee→organizer — the INVERSION of the invite
// direction. org@x is the organizer, me@y the invitee proposing 10:00–10:30. The reducer
// payload's UID + sequence are the STORED values; the start/end are the PROPOSAL.
func TestBuildCounterMIME_Direction(t *testing.T) {
	payload := json.RawMessage(`{
		"uid":"evt-counter-1","title":"Design Sync","description":"","location":"HQ",
		"start":"2026-07-02T10:00:00Z","end":"2026-07-02T10:30:00Z",
		"allDay":false,"timezone":"UTC","sequence":4,
		"organizerEmail":"org@x","organizerName":"Org",
		"attendeeEmail":"me@y","attendeeName":"Me"
	}`)

	mime, _, recipients, p, err := buildCounterMIME(payload)
	if err != nil {
		t.Fatalf("buildCounterMIME: %v", err)
	}

	// The iCal body must declare METHOD:COUNTER.
	if !strings.Contains(mime, "METHOD:COUNTER") {
		t.Errorf("iCal body missing METHOD:COUNTER:\n%s", mime)
	}

	// THE INVERSION (the proof): From: = attendee (me@y), To: = organizer (org@x).
	from := counterHeaderLine(mime, "From:")
	if !strings.Contains(from, "me@y") {
		t.Errorf("From: must be the attendee me@y; got %q", from)
	}
	if strings.Contains(from, "org@x") {
		t.Errorf("From: must NOT carry the organizer; got %q", from)
	}
	to := counterHeaderLine(mime, "To:")
	if !strings.Contains(to, "org@x") {
		t.Errorf("To: must be the organizer org@x; got %q", to)
	}
	if strings.Contains(to, "me@y") {
		t.Errorf("To: must NOT carry the attendee; got %q", to)
	}

	// Envelope: from_addr = attendee, recipients = [organizer] (NOT the invite direction).
	if p.AttendeeEmail != "me@y" {
		t.Errorf("from_addr = %q, want me@y", p.AttendeeEmail)
	}
	if strings.Join(recipients, ",") != "org@x" {
		t.Errorf("recipients = %v, want [org@x]", recipients)
	}

	// DTSTART/DTEND carry the PROPOSED times (10:00 / 10:30 UTC), not a stored event time.
	if !strings.Contains(mime, "DTSTART:20260702T100000Z") {
		t.Errorf("DTSTART must be the proposed 10:00; body:\n%s", mime)
	}
	if !strings.Contains(mime, "DTEND:20260702T103000Z") {
		t.Errorf("DTEND must be the proposed 10:30; body:\n%s", mime)
	}

	// UID + SEQUENCE are unchanged — a counter proposes, it does not re-version the event.
	if p.UID != "evt-counter-1" || !strings.Contains(mime, "UID:evt-counter-1") {
		t.Errorf("UID must be unchanged (evt-counter-1); got p.UID=%q, body:\n%s", p.UID, mime)
	}
	if p.Sequence != 4 || !strings.Contains(mime, "SEQUENCE:4") {
		t.Errorf("SEQUENCE must be unchanged (4); got p.Sequence=%d, body:\n%s", p.Sequence, mime)
	}
}
