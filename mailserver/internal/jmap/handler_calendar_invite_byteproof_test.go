package jmap

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"setjoin.com/mailserver/internal/caldav"
)

// mustParseRFC3339 parses an RFC3339 instant or fails the test.
func mustParseRFC3339(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse time %q: %v", s, err)
	}
	return ts
}

// stripVolatile removes the iMIP MIME lines that embed time.Now() and so already vary
// call-to-call (the multipart boundary, the Date header, the Message-ID, and the VEVENT
// DTSTAMP). What remains is the deterministic envelope + iCal body the conformance gate
// inspects.
func stripVolatile(mime string) string {
	out := mime
	out = regexp.MustCompile(`(?m)^Date: .*\r?\n`).ReplaceAllString(out, "")
	out = regexp.MustCompile(`(?m)^Message-ID: .*\r?\n`).ReplaceAllString(out, "")
	out = regexp.MustCompile(`(?m)^DTSTAMP:.*\r?\n`).ReplaceAllString(out, "")
	// The boundary token = "mailserver-imip-<nanos>"; normalize it everywhere.
	out = regexp.MustCompile(`mailserver-imip-\d+`).ReplaceAllString(out, "BOUNDARY")
	return out
}

// rawClientCreateJSON is the iMIP-relevant slice of a SINGLE CalendarEvent/set `create`
// object EXACTLY as the webmail client sends it (src/lib/types/jmap.ts: CalendarEvent +
// EventAttendee). The decisive detail is the attendee shape: the client sends
// `participationStatus` (NOT `status`) and NO `rsvp`/`expectReply` key. This is the literal
// wire payload HEAD's deleted sendInvitesForCreatedEvents parsed.
const rawClientCreateJSON = `{
	"uid":"fixture-evt-1","title":"Quarterly Sync","description":"Plan the quarter",
	"location":"HQ","start":"2026-07-01T15:00:00Z","end":"2026-07-01T16:00:00Z",
	"allDay":false,"timezone":"UTC","status":"confirmed",
	"attendees":[
		{"email":"organizer@x.test","name":"Organizer","role":"organizer","participationStatus":"accepted"},
		{"email":"guest@x.test","name":"Guest","role":"required","participationStatus":"needs-action"},
		{"email":"roomZ@x.test","name":"Room Z","role":"resource","participationStatus":"needs-action"}
	]
}`

// headCreatePathMIME reconstructs the OLD (pre-wave-6, non-conformant) create-path
// serialization byte-for-byte. It parses the raw client create JSON the way that path did —
// by unmarshalling the attendees into a TAG-LESS caldav.Attendee shape (the struct as it was
// before this wave's JSON tags). Because the client sends `participationStatus` (no `status`)
// and no `rsvp` key, the tag-less case-insensitive unmarshal leaves Status=""/RSVP=false, so
// the old ATTENDEE lines carry NO PARTSTAT and NO RSVP. This is the genuine
// "old non-conformant" reference the new conformant bytes must DIFFER from; nothing here is
// hand-set to agree with — or disagree with — the new path.
func headCreatePathMIME(t *testing.T, organizerEmail, organizerName, clientCreateJSON string) string {
	t.Helper()

	// The struct as caldav.Attendee was BEFORE the wave-6 JSON tags: no tags → only a
	// literal `status`/`rsvp` key (case-insensitive) would populate it. The client sends
	// neither, so both stay zero — faithfully reproducing the old wire.
	type legacyAttendee struct {
		Email  string
		Name   string
		Role   string
		Status string
		RSVP   bool
	}

	var ev struct {
		UID         string          `json:"uid"`
		Title       string          `json:"title"`
		Description string          `json:"description"`
		Location    string          `json:"location"`
		Start       string          `json:"start"`
		End         string          `json:"end"`
		AllDay      bool            `json:"allDay"`
		Timezone    string          `json:"timezone"`
		Status      string          `json:"status"`
		RRULE       string          `json:"rrule"`
		Attendees   json.RawMessage `json:"attendees"`
	}
	if err := json.Unmarshal([]byte(clientCreateJSON), &ev); err != nil {
		t.Fatalf("head parse create JSON: %v", err)
	}
	var legacy []legacyAttendee
	if ev.Attendees != nil {
		if err := json.Unmarshal(ev.Attendees, &legacy); err != nil {
			t.Fatalf("head parse attendees: %v", err)
		}
	}
	attendees := make([]caldav.Attendee, len(legacy))
	for i, a := range legacy {
		attendees[i] = caldav.Attendee{Email: a.Email, Name: a.Name, Role: a.Role, Status: a.Status, RSVP: a.RSVP}
	}
	start := mustParseRFC3339(t, ev.Start)
	end := mustParseRFC3339(t, ev.End)
	event := caldav.CalendarEvent{
		UID:         ev.UID,
		Title:       ev.Title,
		Description: ev.Description,
		Location:    ev.Location,
		Start:       start,
		End:         end,
		AllDay:      ev.AllDay,
		Timezone:    ev.Timezone,
		Status:      ev.Status,
		RRULE:       ev.RRULE,
		Organizer:   caldav.Attendee{Email: organizerEmail, Name: organizerName, Role: "organizer"},
		Attendees:   attendees,
	}
	mime, _, err := caldav.BuildIMip(caldav.MethodRequest, event, organizerEmail, organizerName)
	if err != nil {
		t.Fatalf("head BuildIMip: %v", err)
	}
	return mime
}

// createPayloadJMAPShape returns the iMIP payload calendar_finalize_create_invites emits
// AFTER the wave-6 wire fix: each attendee carries the STORED participation status under the
// canonical JMAP keys participationStatus/expectReply (the keys the JSON-tagged
// caldav.Attendee reads). For an organizer creating a new meeting, the stored values are the
// create reducer's defaults (jmap_calendar.sql:165-166): participationStatus='needs-action',
// expectReply=true for a fresh invitee. This mirrors the reducer transform exactly — it is
// NOT the test deciding what the conformant bytes are; the RFC oracle below decides that.
func createPayloadJMAPShape() json.RawMessage {
	return json.RawMessage(`{
		"eventId":"18","uid":"fixture-evt-1","title":"Quarterly Sync",
		"description":"Plan the quarter","location":"HQ",
		"start":"2026-07-01T15:00:00Z","end":"2026-07-01T16:00:00Z",
		"allDay":false,"timezone":"UTC","status":"confirmed","sequence":0,"rrule":null,
		"organizerEmail":"organizer@x.test","organizerName":"",
		"attendees":[
			{"email":"organizer@x.test","name":"Organizer","role":"organizer","participationStatus":"accepted","expectReply":true},
			{"email":"guest@x.test","name":"Guest","role":"required","participationStatus":"needs-action","expectReply":true},
			{"email":"roomZ@x.test","name":"Room Z","role":"resource","participationStatus":"needs-action","expectReply":true}
		]
	}`)
}

// sendUpdatePayloadJMAPShape returns the iMIP payload calendar_send_invite (the sendUpdate
// path) emits. calendar_send_invite has ALWAYS emitted the stored values under
// participationStatus/expectReply (calendar_itip.sql:141-142) and excludes resources +
// organizer. Before this wave's JSON tags on caldav.Attendee those keys did NOT match the
// tag-less struct, so the sendUpdate ATTENDEE line silently carried NO PARTSTAT/RSVP — a
// LATENT defect this wave fixes for free via the struct tag (D4). The guest here is a fresh
// invitee: stored needs-action / rsvp=true.
func sendUpdatePayloadJMAPShape() json.RawMessage {
	return json.RawMessage(`{
		"eventId":"18","uid":"fixture-evt-1","title":"Quarterly Sync",
		"description":"Plan the quarter","location":"HQ",
		"start":"2026-07-01T15:00:00Z","end":"2026-07-01T16:00:00Z",
		"allDay":false,"timezone":"UTC","status":"confirmed","sequence":1,"rrule":null,
		"organizerEmail":"organizer@x.test","organizerName":"",
		"attendees":[
			{"email":"guest@x.test","name":"Guest","role":"required","participationStatus":"needs-action","expectReply":true}
		]
	}`)
}

// guestAttendeeLine returns the single ATTENDEE iCal line for guest@x.test in the given MIME
// (the line is unfolded; iMIP lines here are short enough not to fold). Empty if absent.
func guestAttendeeLine(mime string) string {
	for _, raw := range strings.Split(mime, "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.HasPrefix(line, "ATTENDEE") && strings.Contains(line, "mailto:guest@x.test") {
			return line
		}
	}
	return ""
}

// TestCreateInviteIsRFC5546Conformant is the conformance gate for the create-path iMIP
// REQUEST. Its oracle is EXTERNAL — RFC 5546 §3.2.2 — NOT "whatever the new code emits":
//
//	RFC 5546 §3.2.2 (METHOD:REQUEST, "Inviting Attendees"): the Organizer sends a REQUEST to
//	the invitees; each ATTENDEE the Organizer expects a response from MUST be marked
//	RSVP=TRUE, and a freshly-invited Attendee who has not yet responded is PARTSTAT=NEEDS-ACTION
//	(the default participation status; RFC 5545 §3.2.12 — NEEDS-ACTION is the implied PARTSTAT
//	before any reply). So a new-meeting REQUEST to a guest who has not replied MUST carry
//	ATTENDEE;...;PARTSTAT=NEEDS-ACTION;RSVP=TRUE.
//
// The test asserts the guest's ATTENDEE line satisfies THAT spec requirement, and that the
// bytes DIFFER from the old non-conformant create path (headCreatePathMIME, which carried
// neither token). A regression-to-blank — dropping PARTSTAT/RSVP again, or matching the old
// path — fails this test against the spec, not merely against a captured golden output.
func TestCreateInviteIsRFC5546Conformant(t *testing.T) {
	const orgEmail = "organizer@x.test"
	const orgName = ""

	newMIME, _, recipients, p, err := buildInviteMIME(createPayloadJMAPShape())
	if err != nil {
		t.Fatalf("create buildInviteMIME: %v", err)
	}

	// RFC 5546 §3.2.2: the fresh guest's ATTENDEE line MUST carry PARTSTAT=NEEDS-ACTION;RSVP=TRUE.
	guest := guestAttendeeLine(newMIME)
	if guest == "" {
		t.Fatalf("create MIME has no ATTENDEE line for the guest:\n%s", newMIME)
	}
	if !strings.Contains(guest, "PARTSTAT=NEEDS-ACTION") {
		t.Errorf("RFC 5546 §3.2.2: a freshly-invited ATTENDEE MUST be PARTSTAT=NEEDS-ACTION; got:\n%s", guest)
	}
	if !strings.Contains(guest, "RSVP=TRUE") {
		t.Errorf("RFC 5546 §3.2.2: an ATTENDEE the Organizer expects a reply from MUST be RSVP=TRUE; got:\n%s", guest)
	}

	// The conformant bytes must DIFFER from the OLD non-conformant create path, which carried
	// neither token. This is the regression-to-blank tripwire: if a future change reverts to
	// the wave-6 blanking, the new MIME collapses back onto headCreatePathMIME and this fires.
	headMIME := headCreatePathMIME(t, orgEmail, orgName, rawClientCreateJSON)
	if strings.Contains(headMIME, "PARTSTAT") || strings.Contains(headMIME, "RSVP") {
		t.Fatalf("old-path reference unexpectedly carries PARTSTAT/RSVP — the conformance diff would be vacuous:\n%s", headMIME)
	}
	if stripVolatile(newMIME) == stripVolatile(headMIME) {
		t.Errorf("create MIME is byte-identical to the OLD non-conformant path (no PARTSTAT/RSVP) — regression to blank")
	}

	// Envelope unchanged: message_id, from_addr, and the recipient set (every attendee minus
	// the organizer email, in order) still match the established behavior.
	if p.UID != "fixture-evt-1" {
		t.Errorf("message_id = %q, want fixture-evt-1", p.UID)
	}
	if p.OrganizerEmail != orgEmail {
		t.Errorf("from_addr = %q, want %q", p.OrganizerEmail, orgEmail)
	}
	wantRcpts := []string{"guest@x.test", "roomZ@x.test"}
	if strings.Join(recipients, ",") != strings.Join(wantRcpts, ",") {
		t.Errorf("recipients = %v, want %v", recipients, wantRcpts)
	}
}

// TestSendUpdateInviteCarriesPARTSTAT closes the asymmetry (D4): the sendUpdate path
// (calendar_send_invite → buildInviteMIME, the SAME worker the create path uses) must ALSO
// emit RFC 5546 §3.2.2-conformant PARTSTAT/RSVP for a fresh invitee.
//
// This is the Phase-0 latent-defect test: calendar_send_invite has always produced
// participationStatus/expectReply keys, but BEFORE this wave's JSON tags on caldav.Attendee
// those keys did not populate .Status/.RSVP, so the ATTENDEE line silently carried neither
// token. With the struct tag it now does. Running this body against the pre-tag struct is RED
// (no PARTSTAT); with the tag it is GREEN — proving the tag, not a golden capture, is what
// fixes sendUpdate.
func TestSendUpdateInviteCarriesPARTSTAT(t *testing.T) {
	updMIME, _, recipients, _, err := buildInviteMIME(sendUpdatePayloadJMAPShape())
	if err != nil {
		t.Fatalf("sendUpdate buildInviteMIME: %v", err)
	}

	guest := guestAttendeeLine(updMIME)
	if guest == "" {
		t.Fatalf("sendUpdate MIME has no ATTENDEE line for the guest:\n%s", updMIME)
	}
	// RFC 5546 §3.2.2: same requirement on the re-issued REQUEST to a not-yet-responded guest.
	if !strings.Contains(guest, "PARTSTAT=NEEDS-ACTION") {
		t.Errorf("sendUpdate dropped PARTSTAT (the latent caldav.Attendee tag defect); got:\n%s", guest)
	}
	if !strings.Contains(guest, "RSVP=TRUE") {
		t.Errorf("sendUpdate dropped RSVP (the latent caldav.Attendee tag defect); got:\n%s", guest)
	}
	// calendar_send_invite excludes resources + organizer: the guest is the sole recipient.
	if strings.Join(recipients, ",") != "guest@x.test" {
		t.Errorf("sendUpdate recipients = %v, want [guest@x.test]", recipients)
	}
}
