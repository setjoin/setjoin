package caldav

// Typed-serialization acceptance tests (med-shard2-011): the iMIP writer
// (buildITIPCalendar) and the shared CalDAV serializer (writeVEVENT /
// eventToICal) must serialize every wire position through EXACTLY ONE
// strategy keyed on the value's RFC 5545 type:
//
//   - TEXT positions (UID/SUMMARY/DESCRIPTION/LOCATION) escape per §3.3.11 so
//     stored CR/LF-bearing text can never inject properties recipients
//     auto-process (hidden attendees, spoofed organizer, forged PARTSTAT);
//   - parameter positions quote/validate per §3.1/§3.2 so crafted TZID/CN/ROLE
//     values cannot split into additional parameters;
//   - structured positions (RRULE, RECURRENCE-ID/RDATE/EXDATE, CAL-ADDRESS)
//     emit native structured syntax after validation — never TEXT-escaped —
//     and malformed structure is rejected instead of serialized.

import (
	"strings"
	"testing"
	"time"
)

const typedSerialInjectedAttendee = "ATTENDEE;PARTSTAT=ACCEPTED:mailto:attacker@evil.example"
const typedSerialInjectedOrganizer = "ORGANIZER;CN=Evil:mailto:spoof@evil.example"

// typedSerialEvilEvent carries CR/LF-bearing TEXT values that attempt to inject
// an auto-processed ATTENDEE, a spoofed ORGANIZER, and a component break.
func typedSerialEvilEvent() CalendarEvent {
	return CalendarEvent{
		UID:         "inj@example.com",
		Title:       "Legit\r\n" + typedSerialInjectedAttendee + "\r\nEND:VEVENT\nBEGIN:VEVENT\r\n" + typedSerialInjectedOrganizer,
		Description: "Desc\n" + typedSerialInjectedOrganizer,
		Start:       time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC),
		End:         time.Date(2026, 6, 15, 11, 0, 0, 0, time.UTC),
		Attendees: []Attendee{
			{Email: "real@example.com", Name: "Real", Role: "required", Status: "needs-action"},
		},
	}
}

// TestTypedSerialization_TextPositionsEscapeCRLF_InBothWriters: CR/LF-bearing
// event text is escaped per the TEXT layer in BOTH the CalDAV serializer and
// the iMIP writer — parsing the wire back yields exactly one VEVENT with the
// original multi-line text as a VALUE, no injected attendee, and no spoofed
// organizer.
func TestTypedSerialization_TextPositionsEscapeCRLF_InBothWriters(t *testing.T) {
	evil := typedSerialEvilEvent()

	writers := map[string]func(CalendarEvent) string{
		"caldav": func(ev CalendarEvent) string { return eventToICal(ev) },
		"imip":   func(ev CalendarEvent) string { return buildITIPCalendar(MethodRequest, ev) },
	}
	for name, write := range writers {
		wire := write(evil)
		objs, err := ParseICalObjects(wire)
		if err != nil {
			t.Fatalf("%s: parse wire: %v\nwire:\n%s", name, err, wire)
		}
		if len(objs) != 1 {
			t.Errorf("%s: injected TEXT split the payload into %d components, want 1", name, len(objs))
			continue
		}
		got := objs[0]
		if got.Title != evil.Title {
			t.Errorf("%s: TEXT round-trip: Title = %q, want original %q", name, got.Title, evil.Title)
		}
		if got.Description != evil.Description {
			t.Errorf("%s: TEXT round-trip: Description = %q, want original %q", name, got.Description, evil.Description)
		}
		if len(got.Attendees) != 1 || got.Attendees[0].Email != "real@example.com" {
			t.Errorf("%s: injected attendee reached the wire: %+v", name, got.Attendees)
		}
		if got.Organizer.Email != "" {
			t.Errorf("%s: spoofed organizer reached the wire: %+v", name, got.Organizer)
		}
		if strings.Contains(wire, typedSerialInjectedAttendee+"\r\n") {
			t.Errorf("%s: wire contains the injected ATTENDEE line verbatim:\n%s", name, wire)
		}
	}
}

// TestTypedSerialization_ParametersNeverSplit: crafted parameter values are
// quoted or validated away per RFC 5545 §3.1/§3.2 — a crafted TZID can neither
// reach the wire nor split DTSTART into additional parameters; a crafted CN is
// quoted; a crafted ROLE is dropped.
func TestTypedSerialization_ParametersNeverSplit(t *testing.T) {
	// Crafted TZID: not a resolvable, parameter-safe timezone id — must fall
	// back to the UTC 'Z' DATE-TIME form, never reach the wire.
	craft := CalendarEvent{
		UID:      "tz@example.com",
		Title:    "TZ",
		Start:    time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC),
		End:      time.Date(2026, 6, 15, 11, 0, 0, 0, time.UTC),
		Timezone: `UTC;ROLE=CHAIR:mailto:evil@x.test`,
	}
	// Known-good TZID: must be preserved verbatim.
	good := craft
	good.UID = "tz-good@example.com"
	good.Timezone = "America/New_York"

	for name, ev := range map[string]CalendarEvent{"crafted": craft, "known-good": good} {
		wire := eventToICal(ev)
		switch name {
		case "crafted":
			if strings.Contains(wire, "TZID=") {
				t.Errorf("crafted TZID parameter reached the wire:\n%s", wire)
			}
			if !strings.Contains(wire, "DTSTART:20260615T100000Z") {
				t.Errorf("crafted TZID must fall back to the UTC Z form:\n%s", wire)
			}
		case "known-good":
			if !strings.Contains(wire, "DTSTART;TZID=America/New_York:20260615T100000") {
				t.Errorf("known-good TZID parameter must be preserved:\n%s", wire)
			}
		}
	}

	// Crafted CN with an embedded DQUOTE: §3.1 has NO valid parameter
	// encoding for a DQUOTE (quoted-string = DQUOTE *QSAFE-CHAR DQUOTE, and
	// no escape exists — the former `"` → `\"` replacement left a raw DQUOTE
	// on the wire that terminated quoting early and introduced additional
	// parameters). The CN parameter is rejected outright.
	a := Attendee{
		Email:  "victim@example.com",
		Name:   `Ev";CN=Inject;ROLE=REQ-PARTICIPANT`,
		Status: "accepted",
	}
	line := formatAttendee("ATTENDEE", a)
	wantLine := `ATTENDEE;PARTSTAT=ACCEPTED:mailto:victim@example.com`
	if line != wantLine {
		t.Errorf("CN with an embedded DQUOTE must be rejected, not encoded:\n got %q\nwant %q", line, wantLine)
	}
	if strings.Contains(line, "CN=") {
		t.Errorf("rejected CN must not reach the wire in any form: %q", line)
	}

	// Crafted CN without a DQUOTE: semicolons/colons stay INSIDE one quoted
	// CN parameter — the parameter list may not resume before the quoted
	// value closes.
	cnPlain := Attendee{
		Email:  "victim@example.com",
		Name:   `Ev;CN=Inject;ROLE=REQ-PARTICIPANT`,
		Status: "accepted",
	}
	line = formatAttendee("ATTENDEE", cnPlain)
	wantLine = `ATTENDEE;CN="Ev;CN=Inject;ROLE=REQ-PARTICIPANT";PARTSTAT=ACCEPTED:mailto:victim@example.com`
	if line != wantLine {
		t.Errorf("crafted CN must serialize as ONE quoted parameter:\n got %q\nwant %q", line, wantLine)
	}
	if idx := strings.Index(line, `;PARTSTAT=`); idx >= 0 && !strings.HasSuffix(line[:idx], `"`) {
		t.Errorf("parameter list resumed before the quoted CN value closed: %q", line)
	}

	// Crafted ROLE: validated against the known-good §3.2.16 set — anything
	// else is dropped, never inlined raw.
	b := Attendee{Email: "victim@example.com", Role: "REQ-PARTICIPANT;X=Y"}
	if line := formatAttendee("ATTENDEE", b); strings.Contains(line, "ROLE=") {
		t.Errorf("crafted ROLE must be validated away: %q", line)
	}
	if line := formatAttendee("ATTENDEE", Attendee{Email: "victim@example.com", Role: "required"}); !strings.Contains(line, "ROLE=REQ-PARTICIPANT") {
		t.Errorf("known-good ROLE must be preserved: %q", line)
	}
}

// TestTypedSerialization_RRULE_SeparatorsVerbatim pins the named defect: a
// valid RRULE serializes with LITERAL unescaped ';' separators on the wire from
// BOTH writers (before the typed-dispatch fix the CalDAV/VTODO writers applied
// §3.3.11 TEXT escaping at the RRULE position, mangling every separator), and
// the rule round-trips byte-faithfully through serialize/parse.
func TestTypedSerialization_RRULE_SeparatorsVerbatim(t *testing.T) {
	const rule = "FREQ=DAILY;INTERVAL=1;COUNT=5"
	ev := CalendarEvent{
		UID:   "rrule@example.com",
		Title: "Series",
		Start: time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC),
		End:   time.Date(2026, 6, 15, 11, 0, 0, 0, time.UTC),
		RRULE: rule,
	}
	todo := ev
	todo.Component = "VTODO"

	wires := map[string]string{
		"caldav-vevent": eventToICal(ev),
		"imip":          buildITIPCalendar(MethodRequest, ev),
		"caldav-vtodo":  componentToICalTodo(todo),
	}
	for name, wire := range wires {
		if !strings.Contains(wire, "RRULE:"+rule+"\r\n") {
			t.Errorf("%s: valid RRULE must appear verbatim with literal ';' separators, got:\n%s", name, wire)
		}
		if strings.Contains(wire, `FREQ=DAILY\;INTERVAL=1\;COUNT=5`) {
			t.Errorf("%s: RRULE position must never be TEXT-escaped (§3.3.10 native syntax):\n%s", name, wire)
		}
	}

	parsed, err := parseICal(eventToICal(ev))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.RRULE != rule {
		t.Errorf("RRULE round-trip: got %q, want %q", parsed.RRULE, rule)
	}
}

// TestTypedSerialization_RecurrenceDateForms_RoundTrip: RECURRENCE-ID/RDATE/
// EXDATE preserve both supported RFC 5545 value forms — the timed DATE-TIME
// form and the all-day DATE form (VALUE=DATE) — with the distinguishing
// VALUE/TZID parameters carried intact, accepted on parse and emitted on the
// wire by the shared serializer. No TEXT escaping appears at these structured
// positions.
func TestTypedSerialization_RecurrenceDateForms_RoundTrip(t *testing.T) {
	const in = "BEGIN:VCALENDAR\r\n" +
		"VERSION:2.0\r\n" +
		"BEGIN:VEVENT\r\n" +
		"UID:forms@example.com\r\n" +
		"SUMMARY:Series\r\n" +
		"DTSTART;TZID=America/New_York:20260105T090000\r\n" +
		"DTEND;TZID=America/New_York:20260105T100000\r\n" +
		"RRULE:FREQ=WEEKLY;BYDAY=MO\r\n" +
		"RDATE;VALUE=DATE:20260202\r\n" +
		"EXDATE;TZID=America/New_York:20260112T090000\r\n" +
		"EXDATE;VALUE=DATE:20260119\r\n" +
		"RECURRENCE-ID;TZID=America/New_York:20260126T090000\r\n" +
		"END:VEVENT\r\n" +
		"END:VCALENDAR\r\n"

	ev, err := parseICal(in)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	wire := eventToICal(ev)

	for _, want := range []string{
		"RDATE;VALUE=DATE:20260202\r\n",
		"EXDATE;TZID=America/New_York:20260112T090000\r\n",
		"EXDATE;VALUE=DATE:20260119\r\n",
		"RECURRENCE-ID;TZID=America/New_York:20260126T090000\r\n",
	} {
		if !strings.Contains(wire, want) {
			t.Errorf("wire must carry %q with its parameters intact; got:\n%s", want, wire)
		}
	}
	if strings.Contains(wire, "RDATE:20260202") || strings.Contains(wire, `EXDATE:20260119T000000Z`) {
		t.Errorf("all-day recurrence dates must keep the DATE (VALUE=DATE) form; got:\n%s", wire)
	}

	// The emitted forms re-parse to the same instants and round-trip again.
	reparsed, err := parseICal(wire)
	if err != nil {
		t.Fatalf("reparse: %v\nwire:\n%s", err, wire)
	}
	nyd, _ := time.LoadLocation("America/New_York")
	wantEX := time.Date(2026, 1, 12, 9, 0, 0, 0, nyd)
	if len(reparsed.EXDATE) != 2 || !reparsed.EXDATE[0].Equal(wantEX) {
		t.Errorf("timed EXDATE round-trip: got %+v, want %v", reparsed.EXDATE, wantEX)
	}
	wantRD := time.Date(2026, 2, 2, 0, 0, 0, 0, time.UTC)
	if len(reparsed.RDATE) != 1 || !reparsed.RDATE[0].Equal(wantRD) {
		t.Errorf("all-day RDATE round-trip: got %+v, want %v", reparsed.RDATE, wantRD)
	}
	if reparsed.RecurrenceIDTime.IsZero() {
		t.Error("timed RECURRENCE-ID round-trip: RecurrenceIDTime zero")
	}
	if reparsed.RRULE != "FREQ=WEEKLY;BYDAY=MO" {
		t.Errorf("RRULE round-trip: got %q", reparsed.RRULE)
	}

	// The RFC 8984/JMAP producer form (calendar_recurrence.sql emits strict
	// RFC 3339 into the iMIP occurrence payload) is accepted as input and
	// NORMALIZED to iCalendar §3.3.4 DATE-TIME syntax on the wire — the
	// extended ISO form never reaches the wire (a §3.3.4 reader could not
	// re-parse it, and occurrence matching keys on the iCalendar form).
	ev3339 := CalendarEvent{
		UID:          "r3339@example.com",
		Title:        "Occurrence",
		Start:        time.Date(2026, 8, 10, 14, 0, 0, 0, time.UTC),
		End:          time.Date(2026, 8, 10, 14, 30, 0, 0, time.UTC),
		RecurrenceID: "2026-08-10T10:00:00Z",
	}
	wire3339 := buildITIPCalendar(MethodCancel, ev3339)
	if !strings.Contains(wire3339, "RECURRENCE-ID:20260810T100000Z\r\n") {
		t.Errorf("RFC 3339 producer input must normalize to iCalendar DATE-TIME on the iMIP wire:\n%s", wire3339)
	}
	if strings.Contains(wire3339, "2026-08-10T10:00:00Z") {
		t.Errorf("extended ISO form must not reach the wire verbatim:\n%s", wire3339)
	}
	if _, err := parseICal(wire3339); err != nil {
		t.Errorf("normalized RECURRENCE-ID wire must re-parse: %v\nwire:\n%s", err, wire3339)
	}

	// The all-day DATE form of RECURRENCE-ID is accepted on parse and emitted
	// with its VALUE=DATE parameter intact.
	const inDate = "BEGIN:VCALENDAR\r\n" +
		"VERSION:2.0\r\n" +
		"BEGIN:VEVENT\r\n" +
		"UID:forms-date@example.com\r\n" +
		"SUMMARY:AllDay\r\n" +
		"DTSTART;VALUE=DATE:20260105\r\n" +
		"DTEND;VALUE=DATE:20260106\r\n" +
		"RECURRENCE-ID;VALUE=DATE:20260119\r\n" +
		"END:VEVENT\r\n" +
		"END:VCALENDAR\r\n"
	evDate, err := parseICal(inDate)
	if err != nil {
		t.Fatalf("parse all-day: %v", err)
	}
	wireDate := eventToICal(evDate)
	if !strings.Contains(wireDate, "RECURRENCE-ID;VALUE=DATE:20260119\r\n") {
		t.Errorf("all-day RECURRENCE-ID must keep the VALUE=DATE form; got:\n%s", wireDate)
	}
}

// TestTypedSerialization_AllDayDerivedForms: DB-derived rows (no parse-time
// form tracking) serialize an all-day series' recurrence dates in the DATE
// (VALUE=DATE) form and a timed series' in the UTC DATE-TIME form.
func TestTypedSerialization_AllDayDerivedForms(t *testing.T) {
	ex := time.Date(2026, 1, 19, 0, 0, 0, 0, time.UTC)
	rd := time.Date(2026, 2, 2, 0, 0, 0, 0, time.UTC)

	allDay := eventRowToCalendarEvent(&eventRow{
		UID: "allday@example.com", Title: "AllDay", AllDay: true,
		StartAt: ex, EndAt: ex.Add(24 * time.Hour),
		RDATE: []time.Time{rd}, EXDATE: []time.Time{ex},
	})
	wire := eventToICal(allDay)
	if !strings.Contains(wire, "EXDATE;VALUE=DATE:20260119\r\n") {
		t.Errorf("all-day series EXDATE must emit the DATE (VALUE=DATE) form:\n%s", wire)
	}
	if !strings.Contains(wire, "RDATE;VALUE=DATE:20260202\r\n") {
		t.Errorf("all-day series RDATE must emit the DATE (VALUE=DATE) form:\n%s", wire)
	}

	timed := eventRowToCalendarEvent(&eventRow{
		UID: "timed@example.com", Title: "Timed",
		StartAt: time.Date(2026, 1, 19, 10, 0, 0, 0, time.UTC),
		EndAt:   time.Date(2026, 1, 19, 11, 0, 0, 0, time.UTC),
		EXDATE:  []time.Time{time.Date(2026, 1, 19, 10, 0, 0, 0, time.UTC)},
	})
	wire = eventToICal(timed)
	if !strings.Contains(wire, "EXDATE:20260119T100000Z\r\n") {
		t.Errorf("timed series EXDATE must emit the UTC DATE-TIME form:\n%s", wire)
	}
	if strings.Contains(wire, "VALUE=DATE") {
		t.Errorf("timed series must not carry VALUE=DATE:\n%s", wire)
	}
}

// TestTypedSerialization_MalformedStructured_Rejected: malformed structured
// values are rejected, not serialized — no RRULE/RECURRENCE-ID line and no
// CAL-ADDRESS line reaches the wire from either writer.
func TestTypedSerialization_MalformedStructured_Rejected(t *testing.T) {
	malformedRules := []string{
		"FREQ",                                // no '=' part
		";;",                                  // empty parts
		"BYDAY=MO",                            // FREQ mandatory (§3.3.10)
		"FREQ=DAILY;X",                        // trailing part without '='
		"FREQ=DAILY;CO UNT=5",                 // space in part value
		"FREQ=DAILY;UNTIL=20260201T00:00:00Z", // colon inside a rule part value
	}
	for _, rule := range malformedRules {
		ev := CalendarEvent{
			UID:   "bad@example.com",
			Title: "Bad",
			Start: time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC),
			End:   time.Date(2026, 6, 15, 11, 0, 0, 0, time.UTC),
			RRULE: rule,
		}
		for name, wire := range map[string]string{
			"caldav": eventToICal(ev),
			"imip":   buildITIPCalendar(MethodRequest, ev),
		} {
			if strings.Contains(wire, "RRULE:") {
				t.Errorf("%s: malformed RRULE %q must be rejected, not serialized:\n%s", name, rule, wire)
			}
		}
	}

	// A valid UNTIL-bearing rule keeps working (charset sanity for the validator).
	valid := CalendarEvent{
		UID:   "until@example.com",
		Title: "Until",
		Start: time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC),
		End:   time.Date(2026, 6, 15, 11, 0, 0, 0, time.UTC),
		RRULE: "FREQ=DAILY;UNTIL=20260201T000000Z",
	}
	if wire := eventToICal(valid); !strings.Contains(wire, "RRULE:FREQ=DAILY;UNTIL=20260201T000000Z\r\n") {
		t.Errorf("valid UNTIL rule must serialize verbatim:\n%s", wire)
	}

	// Malformed RECURRENCE-ID values (neither DATE nor DATE-TIME) are rejected.
	badRec := CalendarEvent{
		UID:          "badrec@example.com",
		Title:        "BadRec",
		Start:        time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC),
		End:          time.Date(2026, 6, 15, 11, 0, 0, 0, time.UTC),
		RecurrenceID: "not-a-date",
	}
	for name, wire := range map[string]string{
		"caldav": eventToICal(badRec),
		"imip":   buildITIPCalendar(MethodRequest, badRec),
	} {
		if strings.Contains(wire, "RECURRENCE-ID:") {
			t.Errorf("%s: malformed RECURRENCE-ID must be rejected, not serialized:\n%s", name, wire)
		}
	}

	// A malformed CAL-ADDRESS rejects the whole line — no injectable value.
	badAddr := CalendarEvent{
		UID:       "badaddr@example.com",
		Title:     "BadAddr",
		Start:     time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC),
		End:       time.Date(2026, 6, 15, 11, 0, 0, 0, time.UTC),
		Organizer: Attendee{Email: "organizer@example.com"},
		Attendees: []Attendee{{Email: "evil@x.example;ROLE=REQ-PARTICIPANT:mailto:y"}},
	}
	wire := eventToICal(badAddr)
	if strings.Contains(wire, "ATTENDEE;") || strings.Contains(wire, "mailto:y") {
		t.Errorf("malformed CAL-ADDRESS must be rejected, not serialized:\n%s", wire)
	}
	if !strings.Contains(wire, "ORGANIZER:mailto:organizer@example.com") {
		t.Errorf("valid ORGANIZER on the same event must survive:\n%s", wire)
	}
}

// TestTypedSerialization_CalAddress_RoundTripByteFaithful: a valid mailto
// CAL-ADDRESS round-trips byte-faithfully through serialize/parse.
func TestTypedSerialization_CalAddress_RoundTripByteFaithful(t *testing.T) {
	const email = "usr.name+tag@sub.example.com"
	ev := CalendarEvent{
		UID:       "addr@example.com",
		Title:     "Addr",
		Start:     time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC),
		End:       time.Date(2026, 6, 15, 11, 0, 0, 0, time.UTC),
		Organizer: Attendee{Email: email, Name: "Org"},
	}
	wire := eventToICal(ev)
	want := "ORGANIZER;CN=Org:mailto:" + email + "\r\n"
	if !strings.Contains(wire, want) {
		t.Errorf("CAL-ADDRESS wire line must be byte-faithful, want %q in:\n%s", want, wire)
	}
	parsed, err := parseICal(wire)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.Organizer.Email != email {
		t.Errorf("CAL-ADDRESS round-trip: got %q, want %q", parsed.Organizer.Email, email)
	}
}

// TestTypedSerialization_StrategyDiscriminators: each strategy wrapper carries
// its RFC 5545 value-type discriminator — one wrapper (and one serialization
// strategy) per value type, so no wire position can pick the wrong strategy.
func TestTypedSerialization_StrategyDiscriminators(t *testing.T) {
	if got := textValue("x").Type(); got != icalValueText {
		t.Errorf("TEXT wrapper discriminator = %v, want icalValueText", got)
	}
	if got := (icalRuleValue)("FREQ=DAILY").Type(); got != icalValueStructured {
		t.Errorf("structured wrapper discriminator = %v, want icalValueStructured", got)
	}
	addr, ok := calAddressValue("user@example.com")
	if !ok || addr.Type() != icalValueCalAddress {
		t.Errorf("CAL-ADDRESS wrapper discriminator = %v (ok=%v), want icalValueCalAddress", addr.Type(), ok)
	}
	if addr.wire() != "mailto:user@example.com" {
		t.Errorf("CAL-ADDRESS wire() must emit the mailto URI, got %q", addr.wire())
	}
	if _, ok := calAddressValue("bad addr;:x"); ok {
		t.Error("CAL-ADDRESS constructor must reject a non-URI-safe addr-spec")
	}
}

// TestTypedSerialization_RecurrenceID_WholeValueValidated pins the
// fractional-suffix defect: the §3.3.4 validator must validate the ENTIRE
// RECURRENCE-ID value. `20260126T090000.\r\nATTENDEE:mailto:evil@example.com`
// formerly validated (the unchecked junk after '.' was discarded) and BOTH
// wire writers emitted it raw as a RECURRENCE-ID plus an injected ATTENDEE
// line. Now the value is rejected in both writers, and digits are the only
// content allowed between the fraction marker and the Z/offset terminator.
func TestTypedSerialization_RecurrenceID_WholeValueValidated(t *testing.T) {
	evil := CalendarEvent{
		UID:          "frac@example.com",
		Title:        "Fraction",
		Start:        time.Date(2026, 1, 26, 9, 0, 0, 0, time.UTC),
		End:          time.Date(2026, 1, 26, 10, 0, 0, 0, time.UTC),
		RecurrenceID: "20260126T090000.\r\nATTENDEE:mailto:evil@example.com",
	}
	for name, wire := range map[string]string{
		"caldav": eventToICal(evil),
		"imip":   buildITIPCalendar(MethodCancel, evil),
	} {
		if strings.Contains(wire, "RECURRENCE-ID:") {
			t.Errorf("%s: fractional-suffix RECURRENCE-ID with unchecked content must be rejected, not serialized:\n%s", name, wire)
		}
		if strings.Contains(wire, "ATTENDEE:mailto:evil@example.com") {
			t.Errorf("%s: injected ATTENDEE line reached the wire:\n%s", name, wire)
		}
	}

	// Whole-value acceptance: a true fractional second stays valid; any
	// non-digit between the fraction and the terminator (or trailing junk)
	// invalidates the whole value.
	cases := []struct {
		v    string
		want bool
	}{
		{"20260126T090000Z", true},
		{"20260126T090000", true},
		{"20260126T090000-0700", true},
		{"20260126T090000.5Z", true},
		{"20260126T090000.123456", true},
		{"20260126T090000.5-0700", true},
		{"20260126T090000.\r\nATTENDEE:mailto:evil@example.com", false},
		{"20260126T090000.5\r\nX:y", false},
		{"20260126T090000.Z", false},
		{"20260126T090000.junk", false},
		{"20260126T090000.5x", false},
		{"20260126T090000.5Z ", false},
	}
	for _, tc := range cases {
		if got := validICalDateTime(tc.v); got != tc.want {
			t.Errorf("validICalDateTime(%q) = %v, want %v", tc.v, got, tc.want)
		}
	}
}

// TestTypedSerialization_ExactValueParamMatching pins the VALUE-parameter
// defect: parameter values must be matched EXACTLY. The former
// Contains("VALUE=DATE") match also matched VALUE=DATE-TIME, making valid
// timed recurrence values parse as all-day DATE and disappear (re-serialized
// as VALUE=DATE with the time dropped). TZID semantics are preserved
// alongside.
func TestTypedSerialization_ExactValueParamMatching(t *testing.T) {
	const in = "BEGIN:VCALENDAR\r\n" +
		"VERSION:2.0\r\n" +
		"BEGIN:VEVENT\r\n" +
		"UID:exact@example.com\r\n" +
		"SUMMARY:Timed\r\n" +
		"DTSTART;TZID=America/New_York:20260105T090000\r\n" +
		"DTEND;TZID=America/New_York:20260105T100000\r\n" +
		"RRULE:FREQ=WEEKLY;BYDAY=MO\r\n" +
		"RDATE;VALUE=DATE-TIME;TZID=America/New_York:20260202T090000\r\n" +
		"EXDATE;VALUE=DATE-TIME:20260112T140000Z\r\n" +
		"RECURRENCE-ID;VALUE=DATE-TIME;TZID=America/New_York:20260126T090000\r\n" +
		"END:VEVENT\r\n" +
		"END:VCALENDAR\r\n"

	ev, err := parseICal(in)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if ev.RecurrenceIDDateOnly {
		t.Error("RECURRENCE-ID;VALUE=DATE-TIME must not parse as the all-day DATE form")
	}
	if len(ev.RDATE) != 1 || len(ev.EXDATE) != 1 {
		t.Fatalf("timed RDATE/EXDATE must parse: RDATE=%v EXDATE=%v", ev.RDATE, ev.EXDATE)
	}
	nyd, _ := time.LoadLocation("America/New_York")
	if !ev.RDATE[0].Equal(time.Date(2026, 2, 2, 9, 0, 0, 0, nyd)) {
		t.Errorf("timed RDATE instant: got %v", ev.RDATE[0])
	}
	if !ev.EXDATE[0].Equal(time.Date(2026, 1, 12, 14, 0, 0, 0, time.UTC)) {
		t.Errorf("timed EXDATE instant: got %v", ev.EXDATE[0])
	}

	wire := eventToICal(ev)
	for _, want := range []string{
		"RDATE;TZID=America/New_York:20260202T090000\r\n",
		"EXDATE:20260112T140000Z\r\n",
		"RECURRENCE-ID;TZID=America/New_York:20260126T090000\r\n",
	} {
		if !strings.Contains(wire, want) {
			t.Errorf("timed recurrence value must keep the timed form, want %q in:\n%s", want, wire)
		}
	}
	if strings.Contains(wire, "VALUE=DATE:") || strings.Contains(wire, ";VALUE=DATE\r\n") {
		t.Errorf("timed values must not degrade to the all-day DATE form:\n%s", wire)
	}

	// The true all-day DATE form still parses and serializes as before.
	const inDate = "BEGIN:VCALENDAR\r\n" +
		"VERSION:2.0\r\n" +
		"BEGIN:VEVENT\r\n" +
		"UID:exact-date@example.com\r\n" +
		"SUMMARY:AllDay\r\n" +
		"DTSTART;VALUE=DATE:20260105\r\n" +
		"DTEND;VALUE=DATE:20260106\r\n" +
		"EXDATE;VALUE=DATE:20260119\r\n" +
		"END:VEVENT\r\n" +
		"END:VCALENDAR\r\n"
	evDate, err := parseICal(inDate)
	if err != nil {
		t.Fatalf("parse all-day: %v", err)
	}
	if len(evDate.EXDATE) != 1 || !evDate.EXDATE[0].Equal(time.Date(2026, 1, 19, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("all-day EXDATE must parse: %v", evDate.EXDATE)
	}
	if wire := eventToICal(evDate); !strings.Contains(wire, "EXDATE;VALUE=DATE:20260119\r\n") {
		t.Errorf("all-day EXDATE must keep the VALUE=DATE form:\n%s", wire)
	}
}

// TestTypedSerialization_ITipRecurrenceDates_BothWriters pins the iMIP
// RDATE/EXDATE omission: buildITIPCalendar must emit recurrence dates through
// the SAME shared structured serializer as the CalDAV writer — timed entries
// in the UTC 'Z' or TZID-qualified DATE-TIME form, all-day entries in the
// DATE (VALUE=DATE) form — so the approved acceptance holds for both writers.
func TestTypedSerialization_ITipRecurrenceDates_BothWriters(t *testing.T) {
	ny, _ := time.LoadLocation("America/New_York")
	forms := []icalDateForm{
		{DateOnly: false, TZID: "America/New_York"},
		{DateOnly: true},
	}
	ev := CalendarEvent{
		UID:         "itip-dates@example.com",
		Title:       "Series",
		Start:       time.Date(2026, 1, 5, 9, 0, 0, 0, ny),
		End:         time.Date(2026, 1, 5, 10, 0, 0, 0, ny),
		Timezone:    "America/New_York",
		RRULE:       "FREQ=WEEKLY;BYDAY=MO",
		RDATE:       []time.Time{time.Date(2026, 2, 2, 9, 0, 0, 0, ny), time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)},
		RDATEForms:  forms,
		EXDATE:      []time.Time{time.Date(2026, 1, 12, 9, 0, 0, 0, ny), time.Date(2026, 1, 19, 0, 0, 0, 0, time.UTC)},
		EXDATEForms: forms,
	}
	wantLines := []string{
		"RDATE;TZID=America/New_York:20260202T090000\r\n",
		"RDATE;VALUE=DATE:20260209\r\n",
		"EXDATE;TZID=America/New_York:20260112T090000\r\n",
		"EXDATE;VALUE=DATE:20260119\r\n",
	}
	for name, wire := range map[string]string{
		"caldav": eventToICal(ev),
		"imip":   buildITIPCalendar(MethodRequest, ev),
	} {
		for _, want := range wantLines {
			if !strings.Contains(wire, want) {
				t.Errorf("%s: recurrence dates must keep their own value form, want %q in:\n%s", name, want, wire)
			}
		}
	}

	// DB-derived rows (no parse-time form tracking): a timed series emits the
	// UTC 'Z' DATE-TIME form and an all-day series the VALUE=DATE form on the
	// iMIP wire too.
	timed := CalendarEvent{
		UID: "itip-db@example.com", Title: "Timed",
		Start:  time.Date(2026, 1, 19, 10, 0, 0, 0, time.UTC),
		End:    time.Date(2026, 1, 19, 11, 0, 0, 0, time.UTC),
		RRULE:  "FREQ=DAILY",
		RDATE:  []time.Time{time.Date(2026, 1, 21, 10, 0, 0, 0, time.UTC)},
		EXDATE: []time.Time{time.Date(2026, 1, 20, 10, 0, 0, 0, time.UTC)},
	}
	wire := buildITIPCalendar(MethodRequest, timed)
	for _, want := range []string{"RDATE:20260121T100000Z\r\n", "EXDATE:20260120T100000Z\r\n"} {
		if !strings.Contains(wire, want) {
			t.Errorf("DB-derived timed series must emit UTC DATE-TIME on the iMIP wire, want %q in:\n%s", want, wire)
		}
	}

	allDay := CalendarEvent{
		UID: "itip-allday@example.com", Title: "AllDay", AllDay: true,
		Start:  time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC),
		End:    time.Date(2026, 2, 10, 0, 0, 0, 0, time.UTC),
		RRULE:  "FREQ=DAILY",
		RDATE:  []time.Time{time.Date(2026, 2, 16, 0, 0, 0, 0, time.UTC)},
		EXDATE: []time.Time{time.Date(2026, 2, 10, 0, 0, 0, 0, time.UTC)},
	}
	wire = buildITIPCalendar(MethodRequest, allDay)
	for _, want := range []string{"RDATE;VALUE=DATE:20260216\r\n", "EXDATE;VALUE=DATE:20260210\r\n"} {
		if !strings.Contains(wire, want) {
			t.Errorf("DB-derived all-day series must emit VALUE=DATE on the iMIP wire, want %q in:\n%s", want, wire)
		}
	}
}
