package jmap

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestBuildInviteMIMEFromReducerPayload is the serialize-only worker's unit test
// (payload in → MIME/enqueue-row out). It feeds buildInviteMIME the exact shape the
// calendar_finalize_create_invites reducer produces and asserts the gateway serializes it
// byte-for-byte the way the old client-JSON-driven path did: the iCal carries the event +
// every attendee, the recipient envelope excludes the organizer, and the blob key is the
// content hash of the MIME. No decision is made here — the reducer already decided.
func TestBuildInviteMIMEFromReducerPayload(t *testing.T) {
	// Reducer payload: organizer + one required attendee + one resource (room), Z-normalized
	// start/end, attendees in stored (client array) order with status/rsvp keys.
	payload := json.RawMessage(`{
		"eventId": "18",
		"uid": "fixture-evt-1",
		"title": "Quarterly Sync",
		"description": "Plan the quarter",
		"location": "HQ",
		"start": "2026-07-01T15:00:00Z",
		"end": "2026-07-01T16:00:00Z",
		"allDay": false,
		"timezone": "UTC",
		"status": "confirmed",
		"sequence": 0,
		"rrule": null,
		"organizerEmail": "organizer@x.test",
		"organizerName": "",
		"attendees": [
			{"email":"organizer@x.test","name":"Organizer","role":"organizer","status":"accepted","rsvp":false},
			{"email":"guest@x.test","name":"Guest","role":"required","status":"needs-action","rsvp":true},
			{"email":"roomZ@x.test","name":"Room Z","role":"resource","status":"needs-action","rsvp":false}
		]
	}`)

	mime, blobKey, recipients, p, err := buildInviteMIME(payload)
	if err != nil {
		t.Fatalf("buildInviteMIME error: %v", err)
	}
	if mime == "" {
		t.Fatal("expected a MIME message, got empty")
	}

	// outbound_queue row fields come straight off the payload (no re-derivation).
	if p.UID != "fixture-evt-1" {
		t.Errorf("message_id (uid) = %q, want fixture-evt-1", p.UID)
	}
	if p.OrganizerEmail != "organizer@x.test" {
		t.Errorf("from_addr (organizer) = %q, want organizer@x.test", p.OrganizerEmail)
	}

	// Recipient envelope = attendees minus the organizer, in order. The room IS a
	// recipient (this preserves the old create-path behavior, which serialized every
	// attendee and excluded only the organizer from the envelope).
	wantRcpts := []string{"guest@x.test", "roomZ@x.test"}
	if len(recipients) != len(wantRcpts) {
		t.Fatalf("recipients = %v, want %v", recipients, wantRcpts)
	}
	for i, r := range wantRcpts {
		if recipients[i] != r {
			t.Errorf("recipient[%d] = %q, want %q", i, recipients[i], r)
		}
	}

	// Blob key is the content hash of the MIME (content-addressed), .eml suffix.
	if !strings.HasPrefix(blobKey, "imip/") || !strings.HasSuffix(blobKey, ".eml") {
		t.Errorf("blobKey = %q, want imip/<hash>.eml", blobKey)
	}

	// MIME content invariants (the BuildIMip format is unchanged; only the decision
	// source moved). DTSTART/DTEND are UTC-normalized; the iCal lists the event and a
	// REQUEST method; the organizer and all three attendees appear.
	for _, want := range []string{
		"METHOD:REQUEST",
		"UID:fixture-evt-1",
		"SUMMARY:Quarterly Sync",
		"DTSTART:20260701T150000Z",
		"DTEND:20260701T160000Z",
		"ORGANIZER",
		"organizer@x.test",
		"guest@x.test",
		"roomZ@x.test",
		"Subject: Invitation: Quarterly Sync",
	} {
		if !strings.Contains(mime, want) {
			t.Errorf("MIME missing %q", want)
		}
	}
}

// TestBuildInviteMIMEOccurrenceCancel: the occurrence-scoped iTIP shape
// jmap_calendar_event_set_occurrence's invitePayload carries (Task 9) — a
// {"method":"CANCEL", "recurrenceId":"..."} payload must build a
// METHOD:CANCEL iCal carrying RECURRENCE-ID, not a bare full-series REQUEST/
// CANCEL (which would wrongly cancel every occurrence, not just this one).
func TestBuildInviteMIMEOccurrenceCancel(t *testing.T) {
	payload := json.RawMessage(`{
		"uid": "series-1",
		"title": "Standup",
		"start": "2026-08-10T14:00:00Z",
		"end": "2026-08-10T14:30:00Z",
		"organizerEmail": "organizer@x.test",
		"recurrenceId": "2026-08-10T10:00:00Z",
		"method": "CANCEL",
		"attendees": [
			{"email":"organizer@x.test","name":"Organizer","role":"organizer","status":"accepted","rsvp":false},
			{"email":"guest@x.test","name":"Guest","role":"required","status":"accepted","rsvp":true}
		]
	}`)
	mime, _, recipients, p, err := buildInviteMIME(payload)
	if err != nil {
		t.Fatalf("buildInviteMIME error: %v", err)
	}
	if p.Method != "CANCEL" || p.RecurrenceID != "2026-08-10T10:00:00Z" {
		t.Errorf("payload fields not parsed: method=%q recurrenceId=%q", p.Method, p.RecurrenceID)
	}
	// The producer's RFC 3339 recurrenceId is echoed on the payload struct, but
	// the iCal wire carries the normalized RFC 5545 §3.3.4 DATE-TIME form
	// (caldav item 5: the extended-ISO form never reaches the wire — a §3.3.4
	// reader could not re-parse it, and occurrence matching keys on the
	// iCalendar form).
	for _, want := range []string{"METHOD:CANCEL", "RECURRENCE-ID:20260810T100000Z", "UID:series-1"} {
		if !strings.Contains(mime, want) {
			t.Errorf("MIME missing %q:\n%s", want, mime)
		}
	}
	if len(recipients) != 1 || recipients[0] != "guest@x.test" {
		t.Errorf("recipients = %v, want [guest@x.test]", recipients)
	}
}

// TestBuildInviteMIMEOccurrenceRequestDefaultsMethod: an occurrence payload
// with no "method" key (the default, non-recurring create/send-update shape)
// still defaults to REQUEST — backward compatible with every existing caller.
func TestBuildInviteMIMEOccurrenceRequestDefaultsMethod(t *testing.T) {
	payload := json.RawMessage(`{
		"uid": "series-1", "title": "Standup",
		"start": "2026-08-10T14:00:00Z", "end": "2026-08-10T14:30:00Z",
		"organizerEmail": "organizer@x.test", "recurrenceId": "2026-08-10T10:00:00Z",
		"attendees": [{"email":"guest@x.test","name":"Guest","role":"required","status":"accepted","rsvp":true}]
	}`)
	mime, _, _, _, err := buildInviteMIME(payload)
	if err != nil {
		t.Fatalf("buildInviteMIME error: %v", err)
	}
	if !strings.Contains(mime, "METHOD:REQUEST") {
		t.Errorf("expected default METHOD:REQUEST:\n%s", mime)
	}
}

// TestExtractInvitePayload_SetOccurrenceResult: jmap_calendar_event_set_occurrence's
// result nests the iTIP shape under "invitePayload" (Task 9) — extractInvitePayload
// pulls just that sub-object out for sendUpdateInvite/serializeAndEnqueueInvite,
// which expect the calendar_send_invite-shaped payload directly, not the
// {ok,eventId,scope,newState,invitePayload} wrapper.
func TestExtractInvitePayload_SetOccurrenceResult(t *testing.T) {
	result := json.RawMessage(`{"ok":true,"eventId":"5","scope":"this","newState":"3",
		"invitePayload":{"uid":"s1","method":"CANCEL","attendees":[{"email":"a@x.test"}]}}`)
	payload, ok := extractInvitePayload(result)
	if !ok {
		t.Fatal("expected ok=true for a present, non-null invitePayload")
	}
	var p invitePayload
	if err := json.Unmarshal(payload, &p); err != nil {
		t.Fatalf("extracted payload does not parse as invitePayload: %v", err)
	}
	if p.UID != "s1" || p.Method != "CANCEL" {
		t.Errorf("extracted payload: uid=%q method=%q", p.UID, p.Method)
	}
}

// TestExtractInvitePayload_Absent: a non-meeting or non-'this'-scope result has no
// invitePayload key (JSON null via jsonb_build_object) — ok=false, nothing to send.
func TestExtractInvitePayload_Absent(t *testing.T) {
	result := json.RawMessage(`{"ok":true,"eventId":"5","scope":"series","newState":"3","invitePayload":null}`)
	if _, ok := extractInvitePayload(result); ok {
		t.Error("expected ok=false for a null invitePayload")
	}
	if _, ok := extractInvitePayload(json.RawMessage(`{"ok":true}`)); ok {
		t.Error("expected ok=false when the key is entirely absent")
	}
}

// TestBuildInviteMIMENoAttendees confirms an attendee-less payload serializes to nothing
// (the worker's "skip, not error" path — mirrors the reducer skipping no-recipient events).
func TestBuildInviteMIMENoAttendees(t *testing.T) {
	payload := json.RawMessage(`{"uid":"x","start":"2026-07-01T15:00:00Z","end":"2026-07-01T16:00:00Z","attendees":[]}`)
	mime, _, _, _, err := buildInviteMIME(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mime != "" {
		t.Errorf("expected empty MIME for no attendees, got %d bytes", len(mime))
	}
}

// TestBuildInviteMIMEDeterministicRecipients confirms the recipient envelope is derived
// purely from the payload's attendee list and organizer (the gateway makes no decision).
func TestBuildInviteMIMEParseErrorSurfaces(t *testing.T) {
	// A non-RFC3339 start surfaces as an error (worker logs + skips; create not failed).
	payload := json.RawMessage(`{"uid":"x","start":"not-a-time","end":"2026-07-01T16:00:00Z","organizerEmail":"o@x.test","attendees":[{"email":"a@x.test","role":"required"}]}`)
	if _, _, _, _, err := buildInviteMIME(payload); err == nil {
		t.Fatal("expected a parse error for an invalid start time")
	}
}
