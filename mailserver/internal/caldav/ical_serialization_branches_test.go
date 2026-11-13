package caldav

// Branch-coverage acceptance tests for the typed serialization and parse
// helpers: every validation rejection path must reject (property omitted,
// never serialized raw) and every accepted form must round-trip. Complements
// ical_typed_serialization_test.go, which owns the injection scenarios.

import (
	"strings"
	"testing"
	"time"
)

// TestCacheLocation_IdempotentPerKey: a second cacheLocation call for an
// already-cached zone must keep the original entry and FIFO position (no
// duplicate insertion, no FIFO growth for the same key).
func TestCacheLocation_IdempotentPerKey(t *testing.T) {
	tzLocationMu.Lock()
	origCache := make(map[string]*time.Location, len(tzLocationCache))
	origFIFO := make([]string, len(tzLocationFIFO))
	for k, v := range tzLocationCache {
		origCache[k] = v
	}
	copy(origFIFO, tzLocationFIFO)
	tzLocationMu.Unlock()
	t.Cleanup(func() {
		tzLocationMu.Lock()
		tzLocationCache = origCache
		tzLocationFIFO = origFIFO
		tzLocationMu.Unlock()
	})

	tzLocationMu.Lock()
	tzLocationCache = make(map[string]*time.Location)
	tzLocationFIFO = tzLocationFIFO[:0]
	tzLocationMu.Unlock()

	const zone = "Test/BranchZone"
	first := time.FixedZone(zone, 0)
	cacheLocation(zone, first)
	tzLocationMu.Lock()
	fifoLen := len(tzLocationFIFO)
	tzLocationMu.Unlock()

	cacheLocation(zone, time.FixedZone(zone, 3600))

	tzLocationMu.Lock()
	got, ok := tzLocationCache[zone]
	fifoLenAfter := len(tzLocationFIFO)
	tzLocationMu.Unlock()
	if !ok {
		t.Fatal("cached zone must remain cached after a duplicate insert")
	}
	if got != first {
		t.Error("duplicate cacheLocation must keep the FIRST stored location")
	}
	if fifoLenAfter != fifoLen {
		t.Errorf("FIFO length changed on duplicate insert: %d -> %d", fifoLen, fifoLenAfter)
	}
}

// TestWriteVEVENT_DelegatedOrganizerSentBy: DelegatedFromEmail re-emerges as a
// validated SENT-BY parameter on the ORGANIZER line; a malformed delegate
// address omits the parameter instead of serializing raw.
func TestWriteVEVENT_DelegatedOrganizerSentBy(t *testing.T) {
	base := CalendarEvent{
		UID:       "deleg@example.com",
		Title:     "Delegated",
		Start:     time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC),
		End:       time.Date(2026, 6, 15, 11, 0, 0, 0, time.UTC),
		Organizer: Attendee{Email: "boss@example.com"},
	}

	valid := base
	valid.DelegatedFromEmail = "assistant@example.com"
	wire := eventToICal(valid)
	if !strings.Contains(wire, "ORGANIZER;SENT-BY=\"mailto:assistant@example.com\":mailto:boss@example.com") {
		t.Errorf("delegated organizer must emit a quoted SENT-BY parameter:\n%s", wire)
	}

	invalid := base
	invalid.DelegatedFromEmail = "not an addr;:x"
	wire = eventToICal(invalid)
	if strings.Contains(wire, "SENT-BY") {
		t.Errorf("malformed delegate address must not reach the wire:\n%s", wire)
	}
	if !strings.Contains(wire, "ORGANIZER:mailto:boss@example.com") {
		t.Errorf("organizer line itself must survive an invalid SENT-BY:\n%s", wire)
	}
}

// TestIcalPropertyParams_MalformedAndQuotedTokens: parameter segments without
// '=' are skipped; quoted values keep their inner text with the DQUOTEs
// stripped; keys are upper-cased.
func TestIcalPropertyParams_MalformedAndQuotedTokens(t *testing.T) {
	params := icalPropertyParams(`RECURRENCE-ID;;TZID="America/New_York";NOVALUE`)
	if len(params) != 1 {
		t.Fatalf("params = %v, want exactly the quoted TZID (empty '='-less token and bare key skipped)", params)
	}
	if params[0][0] != "TZID" || params[0][1] != "America/New_York" {
		t.Errorf("params = %v, want [TZID America/New_York] with quotes stripped", params)
	}
}

// TestParseRecurrenceID_MalformedLines: a RECURRENCE-ID line without a colon
// mutates nothing.
func TestParseRecurrenceID_MalformedLines(t *testing.T) {
	ev := &CalendarEvent{}
	parseRecurrenceID(ev, "RECURRENCE-ID;VALUE=DATE")
	if ev.RecurrenceID != "" || ev.RecurrenceIDDateOnly || !ev.RecurrenceIDTime.IsZero() {
		t.Errorf("colon-less RECURRENCE-ID must be ignored, got %+v", ev)
	}
}

// TestAppendRecurrenceDates_MalformedLine: an RDATE/EXDATE line without a
// colon mutates nothing.
func TestAppendRecurrenceDates_MalformedLine(t *testing.T) {
	ev := &CalendarEvent{}
	appendRecurrenceDates(ev, "RDATE", "RDATE;VALUE=DATE")
	appendRecurrenceDates(ev, "EXDATE", "EXDATE;TZID=Europe/Berlin")
	if len(ev.RDATE) != 0 || len(ev.EXDATE) != 0 {
		t.Errorf("colon-less recurrence date lines must be ignored, got RDATE=%v EXDATE=%v", ev.RDATE, ev.EXDATE)
	}
}

// TestRuleValue_Rejections: ruleValue rejects the empty rule, non-NAME=value
// parts, non-alphabetic names, and values carrying characters outside the
// recurrence-value-safe set; accepted rules keep the literal separators.
func TestRuleValue_Rejections(t *testing.T) {
	rejected := []string{
		"",
		"FREQ",
		"FREQ=DAILY;NOSIGN",
		"=DAILY",
		"FREQ=",
		"1REQ=DAILY",
		"FREQ=DA ILY",
		"FREQ=DAILY;UNTIL=20260701T000000Z;BYDAY=MO,WE;EXTRA<INJ>",
	}
	for _, raw := range rejected {
		if _, ok := ruleValue(raw); ok {
			t.Errorf("ruleValue(%q) must be rejected", raw)
		}
	}

	for _, raw := range []string{
		"FREQ=DAILY;INTERVAL=2",
		"FREQ=WEEKLY;UNTIL=20260701T000000Z",
		"FREQ=MONTHLY;BYDAY=1MO,3FR",
		"FREQ=YEARLY;BYYEARDAY=1.5",
		"FREQ=DAILY;UNTIL=20260701T000000+0100",
		"FREQ=DAILY;COUNT=-3",
	} {
		if got, ok := ruleValue(raw); !ok || got.wire() != raw {
			t.Errorf("ruleValue(%q) = %q, %v; want the raw rule verbatim, true", raw, got.wire(), ok)
		}
	}

	ev := CalendarEvent{
		UID:   "rrule-empty@example.com",
		Title: "No rule",
		Start: time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC),
		End:   time.Date(2026, 6, 15, 11, 0, 0, 0, time.UTC),
	}
	if wire := eventToICal(ev); strings.Contains(wire, "RRULE") {
		t.Errorf("empty RRULE must omit the property entirely:\n%s", wire)
	}
}

// TestSerializeRecurrenceIDLine_ValueForms: each stored value form serializes
// with its own parameters, the RFC 3339 producer form is normalized to
// §3.3.4 syntax, and values validating as no form are omitted.
func TestSerializeRecurrenceIDLine_ValueForms(t *testing.T) {
	t.Run("dateOnlyWithInvalidDateRejected", func(t *testing.T) {
		ev := CalendarEvent{RecurrenceID: "2026061", RecurrenceIDDateOnly: true}
		if line, ok := serializeRecurrenceIDLine(ev); ok {
			t.Errorf("DATE-flagged non-DATE value must be omitted, got %q", line)
		}
	})
	t.Run("rawDateValueGainsValueDate", func(t *testing.T) {
		ev := CalendarEvent{RecurrenceID: "20260615"}
		line, ok := serializeRecurrenceIDLine(ev)
		if !ok || line != "RECURRENCE-ID;VALUE=DATE:20260615" {
			t.Errorf("bare DATE value = %q, %v", line, ok)
		}
	})
	t.Run("rfc3339Normalized", func(t *testing.T) {
		ev := CalendarEvent{RecurrenceID: "2026-06-15T10:00:00Z"}
		line, ok := serializeRecurrenceIDLine(ev)
		if !ok || line != "RECURRENCE-ID:20260615T100000Z" {
			t.Errorf("RFC 3339 value must normalize to §3.3.4 form, got %q, %v", line, ok)
		}
	})
	t.Run("unparseableOmitted", func(t *testing.T) {
		ev := CalendarEvent{RecurrenceID: "not-a-date\r\nATTENDEE:mailto:evil@example.com"}
		if line, ok := serializeRecurrenceIDLine(ev); ok {
			t.Errorf("junk RECURRENCE-ID must be omitted, got %q", line)
		}
	})
	t.Run("timedWithTZID", func(t *testing.T) {
		ev := CalendarEvent{RecurrenceID: "20260615T100000", RecurrenceIDTZID: "Europe/Berlin"}
		line, ok := serializeRecurrenceIDLine(ev)
		if !ok || line != "RECURRENCE-ID;TZID=Europe/Berlin:20260615T100000" {
			t.Errorf("timed TZID value = %q, %v", line, ok)
		}
	})
}

// TestValidICalDateRejectsNonDigits: §3.3.5 validation checks every digit.
func TestValidICalDateRejectsNonDigits(t *testing.T) {
	for _, v := range []string{"", "2026061", "202606159", "2026-6-15", "2026061a", "abcdefgh"} {
		if validICalDate(v) {
			t.Errorf("validICalDate(%q) must be false", v)
		}
	}
	if !validICalDate("20260615") {
		t.Error("validICalDate(20260615) must be true")
	}
}

// TestValidICalDateTimeRejections: the §3.3.4 validator rejects short values,
// non-digit cores, and non-digit offsets.
func TestValidICalDateTimeRejections(t *testing.T) {
	for _, v := range []string{
		"",
		"2026061T100000",
		"20260615T10000a",
		"20260615T100000.Z",
		"20260615T100000+010a",
		"20260615T100000X",
	} {
		if validICalDateTime(v) {
			t.Errorf("validICalDateTime(%q) must be false", v)
		}
	}
	for _, v := range []string{"20260615T100000", "20260615T100000Z", "20260615T100000.123Z", "20260615T100000+0100"} {
		if !validICalDateTime(v) {
			t.Errorf("validICalDateTime(%q) must be true", v)
		}
	}
}

// TestValidRecurrenceTZID_Edges: the empty TZID is rejected, "UTC" is accepted
// by the parameter-safe fast path, and junk characters are rejected before any
// tz load.
func TestValidRecurrenceTZID_Edges(t *testing.T) {
	if validRecurrenceTZID("") {
		t.Error("empty TZID must be rejected")
	}
	if !validRecurrenceTZID("UTC") {
		t.Error("UTC must be accepted without a tz load")
	}
	for _, tz := range []string{"Etc/GMT;ROLE=CHAIR", "Am\"erica/New_York", "Europe/Berli:"} {
		if validRecurrenceTZID(tz) {
			t.Errorf("validRecurrenceTZID(%q) must be false", tz)
		}
	}
}

// TestIcalParamValue_Edges: the empty parameter value serializes as an empty
// quoted string; quoted-forced rendering strips control characters and never
// emits an embedded DQUOTE.
func TestIcalParamValue_Edges(t *testing.T) {
	if got := icalParamValue(""); got != `""` {
		t.Errorf("icalParamValue(\"\") = %q, want %q", got, `""`)
	}
	if got := icalParamValue("Europe/Berlin"); got != "Europe/Berlin" {
		t.Errorf("safe param must stay bare, got %q", got)
	}
	if got := icalParamValue("a,b:c;d\"e"); got != `"a,b:c;de"` {
		t.Errorf("unsafe param must be quoted with the DQUOTE dropped, got %q", got)
	}
	if got := icalParamValueQuoted("sent\r\nby\"x"); got != `"sentbyx"` {
		t.Errorf("icalParamValueQuoted = %q, want control chars and DQUOTE dropped", got)
	}
}

// TestCalAddressValue_DomainShape: leading/trailing hyphens and dot runs in
// the domain are rejected; the local part may carry at-ext specials.
func TestCalAddressValue_DomainShape(t *testing.T) {
	for _, email := range []string{
		"user@-example.com",
		"user@example.com-",
		"user@exa..mple.com",
		"@example.com",
		"user@",
		"userexample.com",
		"user;@example.com",
	} {
		if _, ok := calAddressValue(email); ok {
			t.Errorf("calAddressValue(%q) must be rejected", email)
		}
	}
	if _, ok := calAddressValue("first.last+tag@ex-ample.com"); !ok {
		t.Error("legitimate addr-spec must be accepted")
	}
}

// TestFormatAttendee_RoleAndPartStatSets: only the RFC 5545 known-good
// ROLE/PARTSTAT sets reach the wire; unknown values are validated away
// (ROLE dropped, PARTSTAT failed safe to NEEDS-ACTION); CHAIR,
// NON-PARTICIPANT, DECLINED and TENTATIVE are carried verbatim.
func TestFormatAttendee_RoleAndPartStatSets(t *testing.T) {
	cases := []struct {
		role, status, want string
	}{
		{"resource", "accepted", "ROLE=NON-PARTICIPANT;PARTSTAT=ACCEPTED"},
		{"non-participant", "declined", "ROLE=NON-PARTICIPANT;PARTSTAT=DECLINED"},
		{"chair", "tentative", "ROLE=CHAIR;PARTSTAT=TENTATIVE"},
		{"chair", "weird", "ROLE=CHAIR;PARTSTAT=NEEDS-ACTION"},
		{"bogus-role", "accepted", "PARTSTAT=ACCEPTED"},
	}
	for _, tc := range cases {
		a := Attendee{Email: "att@example.com", Role: tc.role, Status: tc.status}
		line := formatAttendee("ATTENDEE", a)
		if !strings.Contains(line, tc.want) {
			t.Errorf("formatAttendee(role=%q status=%q) = %q, want it to contain %q", tc.role, tc.status, line, tc.want)
		}
	}
	if line := formatAttendee("ATTENDEE", Attendee{Email: "att@example.com", RSVP: true}); !strings.Contains(line, "RSVP=TRUE") {
		t.Errorf("RSVP attendee = %q, want RSVP=TRUE", line)
	}
	if line := formatAttendee("ORGANIZER", Attendee{Email: "org@example.com"}); line != "ORGANIZER:mailto:org@example.com" {
		t.Errorf("parameter-free ORGANIZER = %q", line)
	}
}
