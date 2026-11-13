package caldav

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// tzLocationCap bounds tzLocationCache. The IANA zone set is ~600 entries, so
// 1024 is comfortably above every legitimate workload while an attacker spraying
// crafted TZID parameters (PUT/report bodies) can no longer grow the cache
// without bound (D-MAILSERVER-INTERNAL-CALDAV-007: entries are small strings,
// but the old cache never evicted AND stored the UTC fallback for every failed
// load, so the key space was attacker-controlled and unbounded).
const tzLocationCap = 1024

// tzLocationCache caches time.LoadLocation results to avoid repeated filesystem
// hits on the embedded tzdata for the same TZID within a request burst.
// Bounded + resolvable-only: unresolvable TZIDs are NOT cached (they fall back
// to UTC per attempt — junk keys cannot plant entries), and eviction is FIFO
// once tzLocationCap is reached.
var (
	tzLocationMu    sync.Mutex
	tzLocationCache = make(map[string]*time.Location)
	tzLocationFIFO  = make([]string, 0, tzLocationCap)
)

func loadLocation(tzid string) *time.Location {
	tzLocationMu.Lock()
	if loc, ok := tzLocationCache[tzid]; ok {
		tzLocationMu.Unlock()
		return loc
	}
	tzLocationMu.Unlock()
	loc, err := time.LoadLocation(tzid)
	if err != nil || loc == nil {
		// Uncached fallback: an attacker-supplied TZID must not plant an entry,
		// no matter how many times the same junk value is parsed.
		return time.UTC
	}
	if loc == time.UTC {
		// time.LoadLocation("UTC") and "" both return the UTC singleton — a
		// constant, not worth a bounded-cache entry.
		return loc
	}
	cacheLocation(tzid, loc)
	return loc
}

// cacheLocation stores a successfully resolved, non-UTC location under the
// FIFO cap. Separated from loadLocation so tests can pin the eviction and
// skip-unresolvable behavior.
func cacheLocation(tzid string, loc *time.Location) {
	tzLocationMu.Lock()
	defer tzLocationMu.Unlock()
	if _, ok := tzLocationCache[tzid]; ok {
		return
	}
	if len(tzLocationFIFO) >= tzLocationCap {
		evict := tzLocationFIFO[0]
		tzLocationFIFO = tzLocationFIFO[1:]
		delete(tzLocationCache, evict)
	}
	tzLocationCache[tzid] = loc
	tzLocationFIFO = append(tzLocationFIFO, tzid)
}

// CalendarEvent holds the fields we care about from a VEVENT.
type CalendarEvent struct {
	UID         string
	Title       string
	Description string
	Location    string
	Start       time.Time
	End         time.Time
	AllDay      bool
	Timezone    string
	Status      string
	Transp      string
	RRULE       string
	RDATE       []time.Time
	EXDATE      []time.Time
	// Typed-serialization form tracking (RFC 5545 §3.3.4/§3.3.5): per-entry
	// value form for RDATE/EXDATE so wire output preserves the all-day DATE
	// (VALUE=DATE) vs timed DATE-TIME distinction. Set by the parser;
	// DB-derived rows derive them from AllDay (eventRowToCalendarEvent). A
	// nil/short slice means "derive from AllDay" (recurrenceDateForm).
	RDATEForms  []icalDateForm
	EXDATEForms []icalDateForm
	Sequence    int
	Organizer   Attendee
	Attendees   []Attendee
	VTIMEZONE   string // raw VTIMEZONE iCalendar block
	Component   string // VEVENT, VTODO, VJOURNAL
	// RECURRENCE-ID parameters carried from parse and re-emitted as validated
	// parameters (serializeRecurrenceIDLine).
	RecurrenceID         string    // RECURRENCE-ID raw value; empty if not an exception
	RecurrenceIDTime     time.Time // RECURRENCE-ID parsed to a UTC instant (TZID/VALUE=DATE resolved); zero if not an exception
	RecurrenceIDDateOnly bool      // parsed from the all-day VALUE=DATE form
	RecurrenceIDTZID     string    // parsed TZID parameter value (validated at serialization)
	Priority             int
	PercentComplete      int
	CompletedAt          time.Time
	DueAt                time.Time
	Alarms               []Alarm // parsed VALARM components
	DelegatedFromEmail   string  // email of the delegate (adds SENT-BY to ORGANIZER)
}

// CalendarTodo holds the fields for a VTODO component.
type CalendarTodo struct {
	UID             string
	Title           string
	Description     string
	Status          string
	Priority        int
	PercentComplete int
	Start           time.Time
	Due             time.Time
	Completed       time.Time
	RRULE           string
	RDATE           []time.Time
	EXDATE          []time.Time
	Sequence        int
	Organizer       Attendee
	Attendees       []Attendee
	VTIMEZONE       string
	Component       string // VTODO
}

// CalendarJournal holds the fields for a VJOURNAL component.
type CalendarJournal struct {
	UID         string
	Title       string
	Description string
	Start       time.Time
	Sequence    int
	Organizer   Attendee
	Attendees   []Attendee
	Component   string // VJOURNAL
}

// Alarm holds VALARM data parsed from iCalendar.
type Alarm struct {
	Trigger     string `json:"trigger"`
	Action      string `json:"action"`
	Description string `json:"description,omitempty"`
}

// TimezoneDef holds parsed VTIMEZONE component data for DB storage.
type TimezoneDef struct {
	TZID     string          `json:"tzid"`
	Standard *TZSubComponent `json:"standard,omitempty"`
	Daylight *TZSubComponent `json:"daylight,omitempty"`
}

// TZSubComponent holds STANDARD or DAYLIGHT sub-component data from a VTIMEZONE.
type TZSubComponent struct {
	OffsetFrom string `json:"offset_from"`
	OffsetTo   string `json:"offset_to"`
	DTStart    string `json:"dtstart"`
	RRULE      string `json:"rrule,omitempty"`
	TZName     string `json:"tzname,omitempty"`
}

// Attendee represents a VEVENT attendee or organizer.
//
// The JSON tags fix the ONE canonical iMIP attendee wire shape: the JMAP-vocabulary
// keys `participationStatus`/`expectReply`. This is the shape both invite-payload
// reducers already speak (calendar_send_invite for sendUpdate; calendar_finalize_create_invites
// for create — wave-6 wire fix, RFC 5546 §3.2.2). The ONLY JSON decode of this struct is
// invitePayload.Attendees (jmap/calendar.go), reached by buildInviteMIME for both the create
// and the sendUpdate paths; the CalDAV PUT path parses iCal TEXT, not JSON, and populates
// these fields by the iCal parser, so the tags do not affect it.
type Attendee struct {
	Email         string `json:"email"`
	Name          string `json:"name"`
	Role          string `json:"role"`                // organizer, required, optional, resource
	Status        string `json:"participationStatus"` // needs-action, accepted, declined, tentative
	RSVP          bool   `json:"expectReply"`
	DelegatedFrom string `json:"-"` // SENT-BY email when this role is delegated
}

// writeDTProps writes DTSTART and DTEND properties with appropriate formatting.
// The TZID parameter is a validated parameter (§3.2.19): a known-good,
// parameter-safe timezone id rides the wire verbatim; anything else (crafted
// or unresolvable) falls back to the UTC 'Z' DATE-TIME form instead of
// splitting DTSTART into additional parameters.
func writeDTProps(b *strings.Builder, allDay bool, timezone string, start, end time.Time) {
	if allDay {
		b.WriteString(fmt.Sprintf("DTSTART;VALUE=DATE:%s\r\n", start.Format("20060102")))
		b.WriteString(fmt.Sprintf("DTEND;VALUE=DATE:%s\r\n", end.Format("20060102")))
	} else if timezone != "" && timezone != "UTC" && validRecurrenceTZID(timezone) {
		b.WriteString(fmt.Sprintf("DTSTART;TZID=%s:%s\r\n", icalParamValue(timezone), start.Format("20060102T150405")))
		b.WriteString(fmt.Sprintf("DTEND;TZID=%s:%s\r\n", icalParamValue(timezone), end.Format("20060102T150405")))
	} else {
		b.WriteString(fmt.Sprintf("DTSTART:%s\r\n", start.UTC().Format("20060102T150405Z")))
		b.WriteString(fmt.Sprintf("DTEND:%s\r\n", end.UTC().Format("20060102T150405Z")))
	}
}

// eventToICal serializes a CalendarEvent into an iCalendar VEVENT component.
func eventToICal(ev CalendarEvent) string {
	var b strings.Builder
	b.WriteString("BEGIN:VCALENDAR\r\n")
	b.WriteString("VERSION:2.0\r\n")
	b.WriteString("PRODID:-//Mailserver//CalDAV//EN\r\n")

	// Emit VTIMEZONE if available (RFC 5545 §3.6.5)
	if ev.VTIMEZONE != "" {
		b.WriteString(ev.VTIMEZONE)
	} else if ev.Timezone != "" && ev.Timezone != "UTC" {
		if tz := generateVTIMEZONE(ev.Timezone); tz != "" {
			b.WriteString(tz)
		}
	}

	writeVEVENT(&b, ev)

	b.WriteString("END:VCALENDAR\r\n")
	return b.String()
}

// writeVEVENT writes just the BEGIN:VEVENT…END:VEVENT block (no VCALENDAR
// envelope, no VTIMEZONE) for ev into b. Split out of eventToICal so a recurring
// master and its detached-occurrence overrides can share ONE VCALENDAR envelope
// with multiple VEVENTs (eventToICalWithOverrides, caldav.go) — RFC 4791 §4.1: an
// exception rides inside the master's resource, not as a second resource sharing
// the same UID.
func writeVEVENT(b *strings.Builder, ev CalendarEvent) {
	b.WriteString("BEGIN:VEVENT\r\n")
	b.WriteString(fmt.Sprintf("DTSTAMP:%s\r\n", time.Now().UTC().Format("20060102T150405Z")))
	b.WriteString(fmt.Sprintf("SEQUENCE:%d\r\n", ev.Sequence))
	// TEXT strategy (RFC 5545 §3.3.11) — escaping applies ONLY at these
	// TEXT-typed positions; line folding (escapeLine) is a separate layer.
	b.WriteString(escapeLine("UID:"+textValue(ev.UID).wire()) + "\r\n")
	b.WriteString(escapeLine("SUMMARY:"+textValue(ev.Title).wire()) + "\r\n")
	if ev.Description != "" {
		b.WriteString(escapeLine("DESCRIPTION:"+textValue(ev.Description).wire()) + "\r\n")
	}
	if ev.Location != "" {
		b.WriteString(escapeLine("LOCATION:"+textValue(ev.Location).wire()) + "\r\n")
	}

	// Date/time formatting
	writeDTProps(b, ev.AllDay, ev.Timezone, ev.Start, ev.End)

	if ev.Status != "" {
		b.WriteString(fmt.Sprintf("STATUS:%s\r\n", strings.ToUpper(ev.Status)))
	}
	if ev.Transp != "" {
		b.WriteString(fmt.Sprintf("TRANSP:%s\r\n", strings.ToUpper(ev.Transp)))
	}
	// STRUCTURED strategy (RFC 5545 §3.3.10): a validated RRULE emits its
	// native name=value parts joined by literal ';' separators; malformed
	// rules are rejected instead of serialized.
	if ev.RRULE != "" {
		if rule, ok := ruleValue(ev.RRULE); ok {
			b.WriteString("RRULE:" + rule.wire() + "\r\n")
		}
	}
	// STRUCTURED strategy (§3.3.4/§3.3.5): each recurrence date keeps its own
	// DATE (VALUE=DATE) vs DATE-TIME (UTC Z or TZID-qualified) form.
	for i, rdate := range ev.RDATE {
		b.WriteString(serializeRecurrenceDateLine("RDATE", rdate, recurrenceDateForm(ev.RDATEForms, i, ev.AllDay)) + "\r\n")
	}
	for i, exdate := range ev.EXDATE {
		b.WriteString(serializeRecurrenceDateLine("EXDATE", exdate, recurrenceDateForm(ev.EXDATEForms, i, ev.AllDay)) + "\r\n")
	}
	if line, ok := serializeRecurrenceIDLine(ev); ok {
		b.WriteString(line + "\r\n")
	}

	if ev.Organizer.Email != "" {
		org := ev.Organizer
		if ev.DelegatedFromEmail != "" {
			org.DelegatedFrom = ev.DelegatedFromEmail
		}
		if line := formatAttendee("ORGANIZER", org); line != "" {
			b.WriteString(line + "\r\n")
		}
	}
	for _, a := range ev.Attendees {
		if line := formatAttendee("ATTENDEE", a); line != "" {
			b.WriteString(line + "\r\n")
		}
	}

	b.WriteString("END:VEVENT\r\n")
}

// parseICal parses a minimal iCalendar VEVENT/VTODO/VJOURNAL into a CalendarEvent.
// Single-object convenience wrapper over ParseICalObjects — every pre-existing
// caller (migration ics_import.go, PUT of a non-recurring resource) wants
// exactly this: the FIRST component. A multi-VEVENT payload (Apple/Google
// recurring exception PUT) is the one case this drops information for — those
// callers must use ParseICalObjects instead (caldav.go handlePut, Task 7).
func parseICal(data string) (CalendarEvent, error) {
	objs, err := ParseICalObjects(data)
	if err != nil {
		return CalendarEvent{}, err
	}
	return objs[0], nil
}

// ParseICalObjects parses a full iCalendar payload into one CalendarEvent per
// top-level VEVENT/VTODO/VJOURNAL component. Apple/Google PUT a recurring
// master's exception as a SECOND VEVENT (same UID, RECURRENCE-ID set) in the
// same request body; folding them into one struct by field-overwrite silently
// drops the exception (the bug this replaces). VTIMEZONE is shared calendar-wide
// (RFC 5545 §3.6.5) and attached to every returned object so each can still
// resolve its own TZID-parameterized DTSTART/EXDATE/RECURRENCE-ID.
func ParseICalObjects(data string) ([]CalendarEvent, error) {
	lines := unfoldLines(data)
	inComponent := false
	inTZ := false
	inAlarm := false
	var tzLines []string
	var alarmLines []string
	var vtimezone string
	var objs []CalendarEvent
	var cur *CalendarEvent

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "BEGIN:VTIMEZONE" {
			inTZ = true
			tzLines = nil
			continue
		}
		if line == "END:VTIMEZONE" {
			inTZ = false
			if len(tzLines) > 0 {
				vtimezone = "BEGIN:VTIMEZONE\r\n" + strings.Join(tzLines, "\r\n") + "\r\nEND:VTIMEZONE\r\n"
			}
			continue
		}
		if inTZ {
			tzLines = append(tzLines, line)
			continue
		}

		if line == "BEGIN:VEVENT" || line == "BEGIN:VTODO" || line == "BEGIN:VJOURNAL" {
			inComponent = true
			cur = &CalendarEvent{Component: strings.TrimPrefix(line, "BEGIN:")}
			continue
		}
		if line == "END:VEVENT" || line == "END:VTODO" || line == "END:VJOURNAL" {
			inComponent = false
			if cur != nil {
				finalizeParsedEvent(cur)
				objs = append(objs, *cur)
				cur = nil
			}
			continue
		}
		if line == "BEGIN:VALARM" {
			inAlarm = true
			alarmLines = nil
			continue
		}
		if line == "END:VALARM" {
			inAlarm = false
			if cur != nil {
				cur.Alarms = append(cur.Alarms, parseAlarm(alarmLines))
			}
			continue
		}
		if inAlarm {
			alarmLines = append(alarmLines, line)
			continue
		}
		if !inComponent || cur == nil {
			continue
		}
		parseComponentLine(cur, line)
	}

	if len(objs) == 0 {
		return nil, fmt.Errorf("no VEVENT/VTODO/VJOURNAL component found")
	}
	if objs[0].UID == "" {
		return nil, fmt.Errorf("missing UID")
	}
	for i := range objs {
		objs[i].VTIMEZONE = vtimezone
	}
	return objs, nil
}

// finalizeParsedEvent applies the same UID/title/status defaults parseICal used
// to apply once at the end of the whole payload — now per-component, since
// each VEVENT/VTODO/VJOURNAL in a multi-object payload needs its own defaults.
func finalizeParsedEvent(ev *CalendarEvent) {
	if ev.Title == "" {
		ev.Title = "Untitled"
	}
	if ev.Status == "" {
		switch ev.Component {
		case "VTODO":
			ev.Status = "needs-action"
		case "VJOURNAL":
			ev.Status = "draft"
		default:
			ev.Status = "confirmed"
		}
	}
}

// icalPropertyParams parses the parameter segment of a content-line name
// (everything before ':') per RFC 5545 §3.1: the first ';' token is the
// property name, each following NAME=VALUE pair one parameter. Parameter
// names are uppercased and values returned with surrounding DQUOTES stripped,
// so callers match parameters EXACTLY — a substring test such as
// Contains("VALUE=DATE") wrongly matches VALUE=DATE-TIME and turns valid
// timed recurrence values into the all-day DATE form.
func icalPropertyParams(nameSegment string) [][2]string {
	tokens := strings.Split(nameSegment, ";")
	var params [][2]string
	for _, tok := range tokens[1:] {
		k, v, ok := strings.Cut(tok, "=")
		if !ok || k == "" {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
			v = v[1 : len(v)-1]
		}
		params = append(params, [2]string{strings.ToUpper(strings.TrimSpace(k)), v})
	}
	return params
}

// icalParamLookup returns the value of parameter key (exact, case-insensitive
// name match) from icalPropertyParams output, or "" when absent.
func icalParamLookup(params [][2]string, key string) string {
	for _, kv := range params {
		if kv[0] == key {
			return kv[1]
		}
	}
	return ""
}

// parseComponentLine parses one line inside a VEVENT/VTODO/VJOURNAL component
// into ev. Split out of parseICal so ParseICalObjects can apply it per-component
// across a multi-VEVENT payload.
func parseComponentLine(ev *CalendarEvent, line string) {
	upper := strings.ToUpper(line)
	switch {
	case strings.HasPrefix(upper, "UID:"):
		ev.UID = unescape(strings.TrimPrefix(line, "UID:"))
	case strings.HasPrefix(upper, "SUMMARY:"):
		ev.Title = unescape(strings.TrimPrefix(line, "SUMMARY:"))
	case strings.HasPrefix(upper, "DESCRIPTION:"):
		ev.Description = unescape(strings.TrimPrefix(line, "DESCRIPTION:"))
	case strings.HasPrefix(upper, "LOCATION:"):
		ev.Location = unescape(strings.TrimPrefix(line, "LOCATION:"))
	case strings.HasPrefix(upper, "STATUS:"):
		ev.Status = strings.ToLower(strings.TrimPrefix(line, "STATUS:"))
	case strings.HasPrefix(upper, "RRULE:"):
		ev.RRULE = strings.TrimPrefix(line, "RRULE:")
	case strings.HasPrefix(upper, "RDATE"):
		// Handles bare RDATE:, RDATE;TZID=...: and RDATE;VALUE=DATE:.
		appendRecurrenceDates(ev, "RDATE", line)
	case strings.HasPrefix(upper, "EXDATE"):
		// Handles bare EXDATE:, EXDATE;TZID=...: (Apple), and EXDATE;VALUE=DATE:
		// (whole-day exclusion) — a bare "EXDATE:" and a parameterized
		// "EXDATE;TZID=...:"/"EXDATE;VALUE=DATE:" all fall into this one prefix
		// match since Go's switch tests prefixes, not exact equality.
		appendRecurrenceDates(ev, "EXDATE", line)
	case strings.HasPrefix(upper, "RECURRENCE-ID"):
		parseRecurrenceID(ev, line)
	case strings.HasPrefix(upper, "DTSTART;VALUE=DATE:"):
		ev.AllDay = true
		dt := strings.TrimPrefix(line, "DTSTART;VALUE=DATE:")
		t, err := time.Parse("20060102", dt)
		if err == nil {
			ev.Start = t
		}
	case strings.HasPrefix(upper, "DTSTART;TZID="):
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			tzPart := strings.TrimPrefix(parts[0], "DTSTART;TZID=")
			ev.Timezone = tzPart
			loc := loadLocation(tzPart)
			t, err := time.ParseInLocation("20060102T150405", parts[1], loc)
			if err == nil {
				ev.Start = t
			}
		}
	case strings.HasPrefix(upper, "DTSTART:"):
		dt := strings.TrimPrefix(line, "DTSTART:")
		t, err := parseDateTime(dt)
		if err == nil {
			ev.Start = t
		}
	case strings.HasPrefix(upper, "DTEND;VALUE=DATE:"):
		ev.AllDay = true
		dt := strings.TrimPrefix(line, "DTEND;VALUE=DATE:")
		t, err := time.Parse("20060102", dt)
		if err == nil {
			ev.End = t
		}
	case strings.HasPrefix(upper, "DTEND;TZID="):
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			tzPart := strings.TrimPrefix(parts[0], "DTEND;TZID=")
			loc := loadLocation(tzPart)
			t, err := time.ParseInLocation("20060102T150405", parts[1], loc)
			if err == nil {
				ev.End = t
			}
		}
	case strings.HasPrefix(upper, "DTEND:"):
		dt := strings.TrimPrefix(line, "DTEND:")
		t, err := parseDateTime(dt)
		if err == nil {
			ev.End = t
		}
	case strings.HasPrefix(upper, "SEQUENCE:"):
		seq, _ := fmt.Sscanf(strings.TrimPrefix(line, "SEQUENCE:"), "%d")
		if seq > 0 {
			ev.Sequence = seq
		}
	case strings.HasPrefix(upper, "ORGANIZER"):
		if o := parseAttendeeLine(line); o != nil {
			ev.Organizer = *o
		}
	case strings.HasPrefix(upper, "ATTENDEE"):
		if a := parseAttendeeLine(line); a != nil {
			ev.Attendees = append(ev.Attendees, *a)
		}
	// VTODO-specific
	case strings.HasPrefix(upper, "PRIORITY:"):
		_, _ = fmt.Sscanf(strings.TrimPrefix(line, "PRIORITY:"), "%d", &ev.Priority)
	case strings.HasPrefix(upper, "PERCENT-COMPLETE:"):
		_, _ = fmt.Sscanf(strings.TrimPrefix(line, "PERCENT-COMPLETE:"), "%d", &ev.PercentComplete)
	case strings.HasPrefix(upper, "COMPLETED:"):
		dt := strings.TrimPrefix(line, "COMPLETED:")
		if t, err := parseDateTime(dt); err == nil {
			ev.CompletedAt = t
		}
	case strings.HasPrefix(upper, "DUE;VALUE=DATE:"):
		ev.AllDay = true
		dt := strings.TrimPrefix(line, "DUE;VALUE=DATE:")
		if t, err := time.Parse("20060102", dt); err == nil {
			ev.DueAt = t
		}
	case strings.HasPrefix(upper, "DUE;TZID="):
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			loc := loadLocation(strings.TrimPrefix(parts[0], "DUE;TZID="))
			if t, err := time.ParseInLocation("20060102T150405", parts[1], loc); err == nil {
				ev.DueAt = t
			}
		}
	case strings.HasPrefix(upper, "DUE:"):
		dt := strings.TrimPrefix(line, "DUE:")
		if t, err := parseDateTime(dt); err == nil {
			ev.DueAt = t
		}
	}
}

// parseRecurrenceID parses a RECURRENCE-ID line (bare, TZID-qualified, or
// VALUE=DATE) into ev, carrying the raw value and its value-form parameters
// through to serialization (serializeRecurrenceIDLine).
func parseRecurrenceID(ev *CalendarEvent, line string) {
	name, val, ok := strings.Cut(line, ":")
	if !ok {
		return
	}
	params := icalPropertyParams(name)
	ev.RecurrenceID = val
	// Exact parameter values (§3.2): VALUE=DATE-TIME must not satisfy a
	// VALUE=DATE test — a substring match turned valid timed recurrence
	// values into the all-day DATE form, dropping their time. TZID keeps its
	// own exact parameter, preserving TZID semantics.
	ev.RecurrenceIDDateOnly = strings.EqualFold(icalParamLookup(params, "VALUE"), "DATE")
	ev.RecurrenceIDTZID = icalParamLookup(params, "TZID")
	loc := time.UTC
	if ev.RecurrenceIDTZID != "" {
		loc = loadLocation(ev.RecurrenceIDTZID)
	}
	if t, err := parseDateTimeIn(strings.TrimSpace(val), loc, ev.RecurrenceIDDateOnly); err == nil {
		ev.RecurrenceIDTime = t
	}
}

// appendRecurrenceDates parses one RDATE or EXDATE property line (bare,
// TZID-qualified, or VALUE=DATE) into ev's date list, tracking each entry's
// value form so serialization preserves the DATE vs DATE-TIME distinction.
func appendRecurrenceDates(ev *CalendarEvent, prop, line string) {
	name, val, ok := strings.Cut(line, ":")
	if !ok {
		return
	}
	params := icalPropertyParams(name)
	// Exact parameter values: VALUE=DATE only for the all-day DATE form —
	// VALUE=DATE-TIME is a timed value (the old Contains match swallowed
	// those into the DATE form). TZID semantics preserved per parameter.
	form := icalDateForm{
		DateOnly: strings.EqualFold(icalParamLookup(params, "VALUE"), "DATE"),
		TZID:     icalParamLookup(params, "TZID"),
	}
	loc := time.UTC
	if form.TZID != "" {
		loc = loadLocation(form.TZID)
	}
	for _, dt := range strings.Split(val, ",") {
		if t, err := parseDateTimeIn(strings.TrimSpace(dt), loc, form.DateOnly); err == nil {
			if prop == "RDATE" {
				ev.RDATE = append(ev.RDATE, t)
				ev.RDATEForms = append(ev.RDATEForms, form)
			} else {
				ev.EXDATE = append(ev.EXDATE, t)
				ev.EXDATEForms = append(ev.EXDATEForms, form)
			}
		}
	}
}

// parseDateTimeIn parses a DATE-TIME (or, if dateOnly, a DATE) value in loc —
// the resolved TZID location for a TZID-parameterized property, or time.UTC for
// a bare/Z-suffixed value. Mirrors parseDateTime's fractional-seconds handling.
func parseDateTimeIn(dt string, loc *time.Location, dateOnly bool) (time.Time, error) {
	if dateOnly {
		return time.ParseInLocation("20060102", dt, loc)
	}
	if idx := strings.Index(dt, "."); idx >= 0 {
		rest := dt[idx:]
		if next := strings.IndexAny(rest, "Z+-"); next >= 0 {
			dt = dt[:idx] + rest[next:]
		} else {
			dt = dt[:idx]
		}
	}
	if strings.HasSuffix(dt, "Z") {
		return time.ParseInLocation("20060102T150405Z", dt, time.UTC)
	}
	if t, err := time.ParseInLocation("20060102T150405-0700", dt, loc); err == nil {
		return t, nil
	}
	return time.ParseInLocation("20060102T150405", dt, loc)
}

// ParseICal is the public wrapper for parseICal (used by the migration package).
func ParseICal(data string) (CalendarEvent, error) {
	return parseICal(data)
}

// unfoldLines handles iCalendar line folding (lines starting with space/tab continue previous line).
func unfoldLines(data string) []string {
	lines := strings.Split(data, "\n")
	var out []string
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			if len(out) > 0 {
				out[len(out)-1] += strings.TrimLeft(line, " \t")
			}
		} else {
			out = append(out, line)
		}
	}
	return out
}

// escapeLine folds long lines per RFC 5545 (max 75 octets per line).
// Does not split multi-byte UTF-8 characters.
func escapeLine(s string) string {
	if len(s) <= 75 {
		return s
	}
	var parts []string
	for len(s) > 75 {
		split := 75
		for split > 0 && split < len(s) && s[split]&0xC0 == 0x80 {
			split-- // back up to a complete rune boundary
		}
		if split == 0 {
			split = 75
		}
		parts = append(parts, s[:split])
		s = s[split:]
	}
	parts = append(parts, s)
	return strings.Join(parts, "\r\n ")
}

// escape applies iCalendar/vCard property value escaping (RFC 5545 §3.3.11).
func escape(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, ";", "\\;")
	s = strings.ReplaceAll(s, ",", "\\,")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\n", "\\n")
	return s
}

// unescape reverses iCalendar escaping.
func unescape(s string) string {
	s = strings.ReplaceAll(s, "\\n", "\n")
	s = strings.ReplaceAll(s, "\\r", "\r")
	s = strings.ReplaceAll(s, "\\,", ",")
	s = strings.ReplaceAll(s, "\\;", ";")
	s = strings.ReplaceAll(s, "\\\\", "\\")
	return s
}

// ---------------------------------------------------------------------------
// Typed serialization: EXCLUSIVE dispatch keyed on value type (RFC 5545)
//
// Every wire position in the CalDAV serializer (writeVEVENT) and the iMIP
// writer (buildITIPCalendar) is written by exactly ONE strategy, chosen by the
// value's RFC 5545 type, so TEXT escaping can never reach a non-TEXT position
// (the escape(ev.RRULE) defect: §3.3.11 escaping mangles the literal ';'
// separators of every valid recurrence rule) and a structured value can never
// hit the wire without passing its validation constructor first:
//
//	icalValueText       — UID/SUMMARY/DESCRIPTION/LOCATION (§3.3.11 escaping)
//	icalValueStructured — RRULE (§3.3.10), RECURRENCE-ID/RDATE/EXDATE
//	                      (§3.3.4/§3.3.5): validated, native syntax
//	icalValueCalAddress — ORGANIZER/ATTENDEE mailto URIs (§3.3.3): validated
//
// Parameter positions (TZID, CN, ROLE, PARTSTAT, SENT-BY) are a separate
// strategy (§3.1/§3.2): values are quoted or validated against known-good
// sets — an embedded DQUOTE, which §3.1 cannot encode, is rejected — so a
// crafted parameter can never split into an additional parameter or a second
// property. Malformed structured values are rejected — the property is
// omitted — never serialized.
// ---------------------------------------------------------------------------

// icalValueType enumerates the RFC 5545 value types the writers serialize; it
// keys the exclusive dispatch and is carried by every strategy wrapper below
// via Type().
type icalValueType int

const (
	icalValueText       icalValueType = iota // RFC 5545 §3.3.11 TEXT
	icalValueStructured                      // RFC 5545 §3.3.10 RRULE / §3.3.4-§3.3.5 DATE & DATE-TIME
	icalValueCalAddress                      // RFC 5545 §3.3.3 CAL-ADDRESS (mailto URI)
)

// icalTextValue is a TEXT-typed property value (UID, SUMMARY, DESCRIPTION,
// LOCATION) — the ONLY kind the §3.3.11 escaping strategy applies to.
type icalTextValue string

// textValue lifts a stored string into the TEXT serialization strategy.
func textValue(s string) icalTextValue { return icalTextValue(s) }

// Type reports the value-type discriminator this strategy is keyed on.
func (icalTextValue) Type() icalValueType { return icalValueText }

// wire serializes the value per RFC 5545 §3.3.11: backslash, semicolon,
// comma, CR and LF are escaped, so stored CR/LF-bearing text cannot inject
// properties recipients auto-process. (Line folding is the separate
// escapeLine layer and never touches value semantics.)
func (v icalTextValue) wire() string { return escape(string(v)) }

// icalRuleValue is a STRUCTURED RRULE value (§3.3.10). It is constructible
// only through ruleValue, which validates the name=value structure — only a
// validated rule can reach an RRULE wire position.
type icalRuleValue string

// ruleValue validates a stored RRULE: semicolon-separated parts, each
// NAME=value with an alphabetic name and a recurrence-value-safe charset
// (letters, digits and , . + - only — no ';', ':' or whitespace). FREQ is
// mandatory as the first part (§3.3.10). Malformed input returns ok=false:
// the caller rejects it (omits the property) instead of serializing it.
func ruleValue(raw string) (icalRuleValue, bool) {
	if raw == "" {
		return "", false
	}
	sawFreq := false
	for i, part := range strings.Split(raw, ";") {
		name, value, ok := strings.Cut(part, "=")
		if !ok || name == "" || value == "" {
			return "", false
		}
		if !isASCIILetters(name) {
			return "", false
		}
		for _, r := range value {
			switch {
			case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			case r == ',' || r == '.' || r == '+' || r == '-':
			default:
				return "", false
			}
		}
		if i == 0 && strings.EqualFold(name, "FREQ") {
			sawFreq = true
		}
	}
	if !sawFreq {
		return "", false
	}
	return icalRuleValue(raw), true
}

// Type reports the value-type discriminator this strategy is keyed on.
func (icalRuleValue) Type() icalValueType { return icalValueStructured }

// wire emits the validated rule with its literal ';' separators — never
// TEXT-escaped (§3.3.10 requires the verbatim separators on the wire).
func (v icalRuleValue) wire() string { return string(v) }

func isASCIILetters(s string) bool {
	for _, r := range s {
		if (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') {
			return false
		}
	}
	return s != ""
}

// icalDateForm records the RFC 5545 value form of one RDATE/EXDATE entry so
// wire output preserves the all-day DATE (§3.3.5, VALUE=DATE) vs timed
// DATE-TIME (§3.3.4) distinction with its distinguishing parameter intact.
type icalDateForm struct {
	DateOnly bool
	TZID     string // parsed TZID parameter value; validated at serialization
}

// recurrenceDateForm returns the wire form for RDATE/EXDATE entry i: the
// parser-recorded form when the tracking slice is aligned, else derived from
// the event's all-day flag (DB-derived rows carry instants only).
func recurrenceDateForm(forms []icalDateForm, i int, allDay bool) icalDateForm {
	if i < len(forms) {
		return forms[i]
	}
	return icalDateForm{DateOnly: allDay}
}

// serializeRecurrenceDateLine writes one RDATE/EXDATE property line in the
// entry's own RFC 5545 form: DATE (VALUE=DATE) for all-day values,
// TZID-qualified DATE-TIME when the parser carried a validated TZID, else the
// UTC 'Z' DATE-TIME form. The value is native structured syntax — never
// TEXT-escaped.
func serializeRecurrenceDateLine(name string, t time.Time, form icalDateForm) string {
	if form.DateOnly {
		return name + ";VALUE=DATE:" + t.Format("20060102")
	}
	if form.TZID != "" && validRecurrenceTZID(form.TZID) {
		return name + ";TZID=" + icalParamValue(form.TZID) + ":" + t.Format("20060102T150405")
	}
	return name + ":" + t.UTC().Format("20060102T150405Z")
}

// serializeRecurrenceIDLine writes the RECURRENCE-ID property line for ev.
// The value keeps its parsed RFC 5545 form (timed DATE-TIME or all-day DATE)
// with the distinguishing VALUE/TZID parameters carried intact as validated
// parameters. The RFC 8984/JMAP producer form (strict RFC 3339, emitted by
// calendar_recurrence.sql into the iMIP occurrence payload) is accepted as
// input and NORMALIZED to §3.3.4 DATE-TIME syntax — the extended ISO form
// never reaches the wire (a §3.3.4 reader could not re-parse it, and
// occurrence matching keys on the iCalendar form). A value that validates as
// no known form is rejected — the property is omitted, never serialized raw.
func serializeRecurrenceIDLine(ev CalendarEvent) (string, bool) {
	v := ev.RecurrenceID
	if v == "" {
		return "", false
	}
	var params string
	switch {
	case ev.RecurrenceIDDateOnly:
		if !validICalDate(v) {
			return "", false
		}
		params = ";VALUE=DATE"
	case validICalDateTime(v):
		if ev.RecurrenceIDTZID != "" && validRecurrenceTZID(ev.RecurrenceIDTZID) {
			params = ";TZID=" + icalParamValue(ev.RecurrenceIDTZID)
		}
	case validICalDate(v):
		params = ";VALUE=DATE"
	case validRFC3339(v):
		// RFC 8984/JMAP producer form — accepted as input, normalized to
		// iCalendar DATE-TIME syntax: the offset is folded into the UTC 'Z'
		// form instead of being emitted verbatim in extended ISO syntax.
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return "", false
		}
		v = t.UTC().Format("20060102T150405Z")
	default:
		return "", false
	}
	return "RECURRENCE-ID" + params + ":" + v, true
}

// validRFC3339 reports whether v is a strict RFC 3339 instant — the form the
// JMAP-vocabulary invitePayload reducers emit (calendar_recurrence.sql to_char
// 'YYYY-MM-DD"T"HH24:MI:SS"Z"'); serializeRecurrenceIDLine accepts it and
// normalizes it to the §3.3.4 DATE-TIME wire form.
func validRFC3339(v string) bool {
	_, err := time.Parse(time.RFC3339, v)
	return err == nil
}

// validICalDate reports whether v is an RFC 5545 §3.3.5 DATE value (YYYYMMDD).
func validICalDate(v string) bool {
	if len(v) != 8 {
		return false
	}
	for i := 0; i < 8; i++ {
		if v[i] < '0' || v[i] > '9' {
			return false
		}
	}
	return true
}

// validICalDateTime reports whether v is an RFC 5545 §3.3.4 DATE-TIME form the
// parser accepts: YYYYMMDDTHHMMSS[.frac][Z | ±HHMM | floating]. The ENTIRE
// value is validated — a fractional suffix may only carry digits up to the
// Z/offset terminator, so no control character or unchecked content can
// validate (and later be emitted raw as a RECURRENCE-ID by either wire
// writer).
func validICalDateTime(v string) bool {
	if len(v) < 15 || v[8] != 'T' {
		return false
	}
	for i := 0; i < 15; i++ {
		if i == 8 {
			continue
		}
		if v[i] < '0' || v[i] > '9' {
			return false
		}
	}
	rest := v[15:]
	if strings.HasPrefix(rest, ".") {
		// §3.3.4: the fraction is 1*DIGIT immediately after the seconds, and
		// the value ends at Z, a ±HHMM offset, or nothing. Digits are the
		// ONLY content allowed before that terminator — discarding unchecked
		// junk instead (the former IndexAny scan) let a value like
		// `20260126T090000.\r\nATTENDEE:mailto:evil@example.com` validate and
		// both wire writers emit it raw as a RECURRENCE-ID.
		i := 1
		for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
			i++
		}
		if i == 1 {
			return false
		}
		rest = rest[i:]
	}
	switch {
	case rest == "", rest == "Z":
		return true
	case len(rest) == 5 && (rest[0] == '+' || rest[0] == '-'):
		for i := 1; i < 5; i++ {
			if rest[i] < '0' || rest[i] > '9' {
				return false
			}
		}
		return true
	}
	return false
}

// validRecurrenceTZID validates a TZID parameter value against the known-good
// set (§3.2.19): a parameter-safe IANA timezone id resolvable by the tz
// database. A crafted TZID (one containing ';', ':', '"' or controls) can
// neither split into an additional parameter nor reach the wire; unresolvable
// values make callers fall back to the UTC 'Z' DATE-TIME form.
func validRecurrenceTZID(tzid string) bool {
	if tzid == "" {
		return false
	}
	for _, r := range tzid {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '/' || r == '_' || r == '-' || r == '+' || r == '.':
		default:
			return false
		}
	}
	if tzid == "UTC" {
		return true
	}
	loc := loadLocation(tzid)
	return loc != nil && loc != time.UTC
}

// icalParamValue renders one property PARAMETER value per RFC 5545 §3.1/§3.2:
// bare paramtext when safe, a DQUOTE-quoted string otherwise. Control
// characters are dropped; an embedded DQUOTE has NO valid parameter encoding
// (QSAFE-CHAR admits none and §3.1 defines no escape), so it never reaches
// the wire — callers reject values containing one and icalQuotedInnerText
// drops any that slip through. The result can never split into an additional
// parameter or a second property — a crafted CN or TZID is quoted away,
// never inlined raw.
func icalParamValue(s string) string {
	s = stripParamCtrl(s)
	if s == "" {
		return `""`
	}
	if strings.ContainsAny(s, `";:,`) {
		return `"` + icalQuotedInnerText(s) + `"`
	}
	return s
}

// icalParamValueQuoted is icalParamValue with forced DQUOTE quoting (for
// quoted-string parameter values such as SENT-BY).
func icalParamValueQuoted(s string) string {
	return `"` + icalQuotedInnerText(stripParamCtrl(s)) + `"`
}

// icalQuotedInnerText renders s as the inner text of a DQUOTE-quoted
// parameter value (§3.1: quoted-string = DQUOTE *QSAFE-CHAR DQUOTE).
// QSAFE-CHAR admits no DQUOTE and defines no escape for one — the historic
// `"` → `\"` replacement left a raw DQUOTE on the wire that terminated the
// quoted value early and let a crafted value introduce additional
// parameters. Embedded DQUOTES are therefore rejected: callers refuse values
// containing one, and any that slips through is dropped here, never emitted.
func icalQuotedInnerText(s string) string {
	s = strings.ReplaceAll(s, `"`, "")
	return strings.ReplaceAll(s, `\`, `\\`)
}

func stripParamCtrl(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7F {
			return -1
		}
		return r
	}, s)
}

// icalCalAddressValue is a CAL-ADDRESS value (§3.3.3) — a validated mailto
// URI. It is constructible only through calAddressValue, so only a validated
// address can reach an ORGANIZER/ATTENDEE value position.
type icalCalAddressValue string

// calAddressValue validates an email address for a CAL-ADDRESS value position:
// the serialized form is `mailto:<addr>` inside a single unfolded line, so the
// addr-spec must be a plain local@domain over URI/RFC 5322-safe characters —
// no spaces, quotes, CR/LF or property/parameter punctuation. Anything else is
// rejected (the caller omits the line), never serialized.
func calAddressValue(email string) (icalCalAddressValue, bool) {
	local, domain, ok := strings.Cut(email, "@")
	if !ok || local == "" || domain == "" {
		return "", false
	}
	for _, r := range email {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("!#$%&'*+-/=?^_`{|}~.", r):
		case r == '@':
		default:
			return "", false
		}
	}
	if strings.HasPrefix(domain, "-") || strings.HasSuffix(domain, "-") || strings.Contains(domain, "..") {
		return "", false
	}
	return icalCalAddressValue(email), true
}

// Type reports the value-type discriminator this strategy is keyed on.
func (icalCalAddressValue) Type() icalValueType { return icalValueCalAddress }

// wire emits the validated mailto URI — native CAL-ADDRESS syntax, never
// TEXT-escaped.
func (v icalCalAddressValue) wire() string { return "mailto:" + string(v) }

// formatAttendee serializes an ORGANIZER/ATTENDEE line through the
// CAL-ADDRESS value strategy (§3.3.3: validated mailto URI — a malformed
// address rejects the whole line, returned as "") plus the separate parameter
// strategy (§3.1/§3.2: CN quoted when needed, SENT-BY quoted, ROLE/PARTSTAT
// validated against known-good sets). Used by BOTH writers.
func formatAttendee(kind string, a Attendee) string {
	addr, ok := calAddressValue(a.Email)
	if !ok {
		return ""
	}
	var params []string
	if a.Name != "" && !strings.ContainsRune(a.Name, '"') {
		// §3.1 has no valid encoding for a DQUOTE inside a parameter value
		// (quoted-string admits none, no escape exists), so a CN containing
		// one is rejected — the parameter is omitted, never backslash-escaped
		// (a raw DQUOTE would terminate quoting and introduce parameters).
		params = append(params, "CN="+icalParamValue(a.Name))
	}
	if a.DelegatedFrom != "" && kind == "ORGANIZER" {
		if d, valid := calAddressValue(a.DelegatedFrom); valid {
			params = append(params, "SENT-BY="+icalParamValueQuoted(d.wire()))
		}
	}
	if role := attendeeRoleParam(a.Role); role != "" {
		params = append(params, "ROLE="+role)
	}
	if a.Status != "" {
		params = append(params, "PARTSTAT="+attendeePartStatParam(a.Status))
	}
	if a.RSVP {
		params = append(params, "RSVP=TRUE")
	}
	if len(params) > 0 {
		return fmt.Sprintf("%s;%s:%s", kind, strings.Join(params, ";"), addr.wire())
	}
	return fmt.Sprintf("%s:%s", kind, addr.wire())
}

// attendeeRoleParam maps a stored role to the known-good RFC 5545 §3.2.16
// parameter set; anything else is validated away (no ROLE param) — never
// inlined raw, where a crafted value could split into an additional parameter.
func attendeeRoleParam(role string) string {
	switch role {
	case "required", "req-participant":
		return "REQ-PARTICIPANT"
	case "optional", "opt-participant":
		return "OPT-PARTICIPANT"
	case "resource", "non-participant":
		return "NON-PARTICIPANT"
	case "chair":
		return "CHAIR"
	default:
		return ""
	}
}

// attendeePartStatParam maps a participation status to the known-good
// RFC 5545 §3.2.12 set (unknown values fail safe to NEEDS-ACTION).
func attendeePartStatParam(status string) string {
	switch status {
	case "accepted":
		return "ACCEPTED"
	case "declined":
		return "DECLINED"
	case "tentative":
		return "TENTATIVE"
	default:
		return "NEEDS-ACTION"
	}
}

func parseAttendeeLine(line string) *Attendee {
	// Format: ATTENDEE;CN=Name;ROLE=REQ-PARTICIPANT;PARTSTAT=ACCEPTED:mailto:email@example.com
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return nil
	}
	var email string
	if strings.HasPrefix(parts[1], "mailto:") {
		email = strings.TrimPrefix(parts[1], "mailto:")
	} else {
		email = parts[1]
	}

	a := &Attendee{Email: email, RSVP: true, Status: "needs-action"}
	paramStr := parts[0]
	for _, p := range strings.Split(paramStr, ";") {
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.ToUpper(kv[0])
		val := kv[1]
		switch key {
		case "CN":
			a.Name = val
		case "ROLE":
			v := strings.ToLower(val)
			switch {
			case v == "req-participant":
				a.Role = "required"
			case v == "opt-participant":
				a.Role = "optional"
			default:
				a.Role = v
			}
		case "PARTSTAT":
			a.Status = strings.ToLower(val)
		case "RSVP":
			a.RSVP = strings.ToUpper(val) == "TRUE"
		}
	}
	return a
}

// parseDateTime handles iCalendar DATE-TIME values including fractional seconds and UTC offsets.
func parseDateTime(dt string) (time.Time, error) {
	// Strip fractional seconds (e.g., 20260101T120000.5 → 20260101T120000)
	if idx := strings.Index(dt, "."); idx >= 0 {
		rest := dt[idx:]
		if next := strings.IndexAny(rest, "Z+-"); next >= 0 {
			dt = dt[:idx] + rest[next:] // keep Z or offset, remove ".5"
		} else {
			dt = dt[:idx]
		}
	}
	if t, err := time.Parse("20060102T150405Z", dt); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.Parse("20060102T150405-0700", dt); err == nil {
		return t, nil
	}
	if t, err := time.Parse("20060102T150405", dt); err == nil {
		return t, nil
	}
	if t, err := time.Parse("20060102", dt); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("cannot parse date-time: %s", dt)
}

// busyIntervalsToVFREEBUSY renders busy intervals as a VFREEBUSY iCalendar component (RFC 5545 §3.6.4).
// Used by the CalDAV free-busy-query REPORT (RFC 4791 §7.10).
func busyIntervalsToVFREEBUSY(intervals []BusyInterval, dtstamp time.Time) string {
	var b strings.Builder
	b.WriteString("BEGIN:VCALENDAR\r\n")
	b.WriteString("VERSION:2.0\r\n")
	b.WriteString("PRODID:-//mailserver//NONSGML CalDAV//EN\r\n")
	b.WriteString("BEGIN:VFREEBUSY\r\n")
	b.WriteString(fmt.Sprintf("DTSTAMP:%s\r\n", dtstamp.Format("20060102T150405Z")))

	for _, iv := range intervals {
		fbType := "BUSY"
		if iv.Status == "tentative" {
			fbType = "BUSY-TENTATIVE"
		} else if iv.Status == "free" {
			continue
		}
		b.WriteString(fmt.Sprintf("FREEBUSY;FBTYPE=%s:%s/%s\r\n",
			fbType,
			iv.Start.Format("20060102T150405Z"),
			iv.End.Format("20060102T150405Z"),
		))
	}

	b.WriteString("END:VFREEBUSY\r\n")
	b.WriteString("END:VCALENDAR\r\n")
	return b.String()
}

// BusyInterval represents a busy time period from the free/busy query.
type BusyInterval struct {
	Start  time.Time `json:"start"`
	End    time.Time `json:"end"`
	Status string    `json:"status"`
}

// generateVTIMEZONE creates a minimal VTIMEZONE iCalendar component for a TZID
// using Go's timezone database. Used when no stored VTIMEZONE is available.
func generateVTIMEZONE(tzid string) string {
	loc := loadLocation(tzid)
	if loc == time.UTC && tzid != "UTC" {
		return ""
	}

	now := time.Now().In(loc)
	_, offset := now.Zone()
	offsetHours := offset / 3600
	offsetMins := (abs(offset) % 3600) / 60

	var sign string
	if offset < 0 {
		sign = "-"
	} else {
		sign = "+"
	}
	if offsetHours < 0 {
		offsetHours = -offsetHours
	}

	offsetStr := fmt.Sprintf("%s%02d%02d", sign, offsetHours, offsetMins)

	var b strings.Builder
	b.WriteString("BEGIN:VTIMEZONE\r\n")
	b.WriteString(fmt.Sprintf("TZID:%s\r\n", tzid))
	b.WriteString("BEGIN:STANDARD\r\n")
	b.WriteString("DTSTART:19700101T000000\r\n")
	b.WriteString(fmt.Sprintf("TZOFFSETFROM:%s\r\n", offsetStr))
	b.WriteString(fmt.Sprintf("TZOFFSETTO:%s\r\n", offsetStr))
	b.WriteString("END:STANDARD\r\n")
	b.WriteString("END:VTIMEZONE\r\n")
	return b.String()
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func parseAlarm(lines []string) Alarm {
	alarm := Alarm{Action: "DISPLAY"}
	for _, line := range lines {
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "TRIGGER"):
			alarm.Trigger = strings.TrimPrefix(strings.TrimPrefix(line, "TRIGGER:"), "TRIGGER;RELATED=START:")
		case strings.HasPrefix(upper, "ACTION:"):
			alarm.Action = strings.TrimPrefix(line, "ACTION:")
		case strings.HasPrefix(upper, "DESCRIPTION:"):
			alarm.Description = strings.TrimPrefix(line, "DESCRIPTION:")
		}
	}
	return alarm
}
