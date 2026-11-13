package caldav

import (
	"fmt"
	"strings"
	"time"
)

// stripHeaderCtrl removes CR, LF, and NUL from a value before it is written
// into an RFC 822 header — prevents header injection via user-controlled fields
// such as event Title, organizer/attendee names and email addresses.
func stripHeaderCtrl(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == 0 {
			return -1
		}
		return r
	}, s)
}

func BuildIMip(method ITIPMethod, event CalendarEvent, fromEmail string, fromName string) (mimeMessage string, recipients []string, err error) {
	boundary := "mailserver-imip-" + fmt.Sprintf("%d", time.Now().UnixNano())

	// Sanitize header-injectable fields once before use.
	safeFromName := stripHeaderCtrl(fromName)
	safeFromEmail := stripHeaderCtrl(fromEmail)
	safeTitle := stripHeaderCtrl(event.Title)

	var textBody strings.Builder
	textBody.WriteString(fmt.Sprintf("%s: %s\n", methodLabel(method), safeTitle))
	textBody.WriteString(fmt.Sprintf("When: %s", formatDateTime(event.Start, event.AllDay, event.Timezone)))
	if !event.AllDay {
		textBody.WriteString(fmt.Sprintf(" - %s", formatDateTime(event.End, event.AllDay, event.Timezone)))
	}
	textBody.WriteString("\n")
	if event.Location != "" {
		textBody.WriteString(fmt.Sprintf("Where: %s\n", event.Location))
	}
	if event.Organizer.Email != "" {
		textBody.WriteString(fmt.Sprintf("Organizer: %s <%s>\n", event.Organizer.Name, event.Organizer.Email))
	}
	if len(event.Attendees) > 0 {
		textBody.WriteString("Attendees:\n")
		for _, a := range event.Attendees {
			textBody.WriteString(fmt.Sprintf("  - %s <%s> (%s)\n", a.Name, a.Email, a.Status))
		}
	}
	if event.Description != "" {
		textBody.WriteString(fmt.Sprintf("\n%s\n", event.Description))
	}

	icalPayload := buildITIPCalendar(method, event)

	var mail strings.Builder
	mail.WriteString(fmt.Sprintf("From: %s <%s>\r\n", safeFromName, safeFromEmail))
	mail.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(recipientList(event, fromEmail), ", ")))
	mail.WriteString(fmt.Sprintf("Subject: %s: %s\r\n", methodLabel(method), safeTitle))
	mail.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().Format(time.RFC1123Z)))
	mail.WriteString(fmt.Sprintf("Message-ID: <%s@mailserver>\r\n", fmt.Sprintf("%d", time.Now().UnixNano())))
	mail.WriteString("MIME-Version: 1.0\r\n")
	mail.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=%s\r\n", boundary))
	mail.WriteString("\r\n")

	mail.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	mail.WriteString("Content-Type: text/plain; charset=utf-8\r\n\r\n")
	mail.WriteString(textBody.String())
	mail.WriteString("\r\n")

	mail.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	mail.WriteString(fmt.Sprintf("Content-Type: text/calendar; method=%s; component=VEVENT; charset=utf-8\r\n", string(method)))
	mail.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
	mail.WriteString(icalPayload)
	mail.WriteString("\r\n")

	mail.WriteString(fmt.Sprintf("--%s--\r\n", boundary))

	for _, a := range event.Attendees {
		if a.Email != fromEmail {
			recipients = append(recipients, a.Email)
		}
	}

	return mail.String(), recipients, nil
}

func buildITIPCalendar(method ITIPMethod, event CalendarEvent) string {
	var b strings.Builder
	b.WriteString("BEGIN:VCALENDAR\r\n")
	b.WriteString("VERSION:2.0\r\n")
	b.WriteString(fmt.Sprintf("METHOD:%s\r\n", string(method)))
	b.WriteString("PRODID:-//Mailserver//iMIP//EN\r\n")
	b.WriteString("BEGIN:VEVENT\r\n")
	b.WriteString(fmt.Sprintf("DTSTAMP:%s\r\n", time.Now().UTC().Format("20060102T150405Z")))
	b.WriteString(fmt.Sprintf("SEQUENCE:%d\r\n", event.Sequence))
	// TEXT strategy (RFC 5545 §3.3.11) — stored CR/LF-bearing text cannot
	// inject properties recipients auto-process. Identical dispatch to the
	// CalDAV serializer (writeVEVENT); folding (escapeLine) stays separate.
	b.WriteString(escapeLine("UID:"+textValue(event.UID).wire()) + "\r\n")
	b.WriteString(escapeLine("SUMMARY:"+textValue(event.Title).wire()) + "\r\n")
	if event.Description != "" {
		b.WriteString(escapeLine("DESCRIPTION:"+textValue(event.Description).wire()) + "\r\n")
	}
	if event.Location != "" {
		b.WriteString(escapeLine("LOCATION:"+textValue(event.Location).wire()) + "\r\n")
	}
	writeDTProps(&b, event.AllDay, event.Timezone, event.Start, event.End)
	if event.Status != "" {
		b.WriteString(fmt.Sprintf("STATUS:%s\r\n", strings.ToUpper(event.Status)))
	}
	// STRUCTURED strategies (RFC 5545 §3.3.10 / §3.3.4-§3.3.5): validated
	// native syntax with literal separators and intact VALUE/TZID parameters;
	// malformed values are rejected instead of serialized.
	if event.RRULE != "" {
		if rule, ok := ruleValue(event.RRULE); ok {
			b.WriteString("RRULE:" + rule.wire() + "\r\n")
		}
	}
	// STRUCTURED strategy (§3.3.4/§3.3.5): the SAME shared serializer as the
	// CalDAV writer (writeVEVENT) emits RDATE/EXDATE — each recurrence date
	// keeps its own DATE (VALUE=DATE) vs timed DATE-TIME (UTC 'Z' or
	// TZID-qualified) form on the iMIP wire too.
	for i, rdate := range event.RDATE {
		b.WriteString(serializeRecurrenceDateLine("RDATE", rdate, recurrenceDateForm(event.RDATEForms, i, event.AllDay)) + "\r\n")
	}
	for i, exdate := range event.EXDATE {
		b.WriteString(serializeRecurrenceDateLine("EXDATE", exdate, recurrenceDateForm(event.EXDATEForms, i, event.AllDay)) + "\r\n")
	}
	if line, ok := serializeRecurrenceIDLine(event); ok {
		// Occurrence-scoped REQUEST/CANCEL (Task 9): identifies which instance
		// of the recipient's existing series this iTIP message applies to.
		b.WriteString(line + "\r\n")
	}
	if event.Organizer.Email != "" {
		if line := formatAttendee("ORGANIZER", event.Organizer); line != "" {
			b.WriteString(line + "\r\n")
		}
	}
	for _, a := range event.Attendees {
		if line := formatAttendee("ATTENDEE", a); line != "" {
			b.WriteString(line + "\r\n")
		}
	}
	b.WriteString("END:VEVENT\r\n")
	b.WriteString("END:VCALENDAR\r\n")
	return b.String()
}

func methodLabel(method ITIPMethod) string {
	switch method {
	case MethodRequest:
		return "Invitation"
	case MethodReply:
		return "Response"
	case MethodCancel:
		return "Cancellation"
	case MethodCounter:
		return "Counter Proposal"
	default:
		return "Notification"
	}
}

func formatDateTime(t time.Time, allDay bool, tz string) string {
	if allDay {
		return t.Format("Monday, January 2, 2006")
	}
	if tz != "" && tz != "UTC" {
		return t.Format("Monday, January 2, 2006 at 3:04 PM") + " (" + tz + ")"
	}
	return t.Format("Monday, January 2, 2006 at 3:04 PM UTC")
}

func recipientList(event CalendarEvent, excludeEmail string) []string {
	var list []string
	if event.Organizer.Email != "" && event.Organizer.Email != excludeEmail {
		list = append(list, fmt.Sprintf("%s <%s>",
			stripHeaderCtrl(event.Organizer.Name),
			stripHeaderCtrl(event.Organizer.Email)))
	}
	for _, a := range event.Attendees {
		if a.Email != excludeEmail {
			list = append(list, fmt.Sprintf("%s <%s>",
				stripHeaderCtrl(a.Name),
				stripHeaderCtrl(a.Email)))
		}
	}
	if len(list) == 0 {
		list = append(list, stripHeaderCtrl(excludeEmail))
	}
	return list
}
