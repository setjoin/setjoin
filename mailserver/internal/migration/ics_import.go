package migration

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/caldav"
)

// ImportICS parses a multi-VEVENT/VTODO ICS string and imports each event
// into the specified calendar.
func ImportICS(ctx context.Context, pool *pgxpool.Pool, data string, calendarID int64, userEmail string, strategy string) (imported int, skipped int, errors []string) {
	events, sharedTZ, errs := SplitAndParseICS(data)
	errors = append(errors, errs...)

	for i := range events {
		select {
		case <-ctx.Done():
			return imported, skipped, errors
		default:
		}
		ev := &events[i]
		if ev.VTIMEZONE == "" && sharedTZ != "" {
			ev.VTIMEZONE = sharedTZ
		}
		if ev.Organizer.Email != "" && !strings.EqualFold(ev.Organizer.Email, userEmail) {
			ev.Organizer.Email = userEmail
		}

		switch strategy {
		case "skip":
			if calendarEventExists(ctx, pool, calendarID, ev.UID) {
				skipped++
				continue
			}
		case "overwrite":
			deleteCalendarEvent(ctx, pool, calendarID, ev.UID)
		case "rename":
			for calendarEventExists(ctx, pool, calendarID, ev.UID) {
				ev.UID = ev.UID + "-migrated"
			}
		}

		if err := insertCalendarEvent(ctx, pool, calendarID, ev); err != nil {
			errors = append(errors, fmt.Sprintf("event %s: %v", ev.UID, err))
			continue
		}
		imported++
	}

	return imported, skipped, errors
}

// SplitAndParseICS splits multi-component ICS data and parses each component with
// the caldav parser. Exported so the JMAP CalendarEvent/import handler reuses the
// same split+parse as the migration path (it only uses the PURE parser — never the
// raw-INSERT insertCalendarEvent/ImportICS side, which bypasses RLS/state/notify).
func SplitAndParseICS(data string) ([]caldav.CalendarEvent, string, []string) {
	sharedTZ := extractVTIMEZONE(data)
	components := splitICS(data)

	var events []caldav.CalendarEvent
	var errs []string

	for _, comp := range components {
		ev, err := caldav.ParseICal(comp)
		if err != nil {
			errs = append(errs, fmt.Sprintf("parse error: %v", err))
			continue
		}
		if ev.VTIMEZONE == "" && sharedTZ != "" {
			ev.VTIMEZONE = sharedTZ
		}
		events = append(events, ev)
	}
	return events, sharedTZ, errs
}

// extractVTIMEZONE extracts the raw VTIMEZONE block from ICS data.
func extractVTIMEZONE(data string) string {
	var lines []string
	inTZ := false

	for _, line := range strings.SplitAfter(data, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "BEGIN:VTIMEZONE") {
			inTZ = true
			lines = nil
			continue
		}
		if strings.HasPrefix(trimmed, "END:VTIMEZONE") {
			inTZ = false
			break
		}
		if inTZ {
			lines = append(lines, line)
		}
	}
	if len(lines) == 0 {
		return ""
	}
	return "BEGIN:VTIMEZONE\r\n" + strings.Join(lines, "") + "END:VTIMEZONE\r\n"
}

// splitICS splits raw ICS data into individual VEVENT/VTODO/VJOURNAL blocks.
// VTIMEZONE blocks are NOT returned as components; they are handled via sharedTZ.
func splitICS(data string) []string {
	var components []string
	var current strings.Builder
	var inTZ bool
	depth := 0

	for _, line := range strings.SplitAfter(data, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// Track VTIMEZONE boundaries — skip them entirely
		if strings.HasPrefix(trimmed, "BEGIN:VTIMEZONE") {
			inTZ = true
			continue
		}
		if strings.HasPrefix(trimmed, "END:VTIMEZONE") {
			inTZ = false
			continue
		}
		if inTZ {
			continue
		}

		// Skip VCALENDAR wrapper and file-level metadata
		if strings.HasPrefix(trimmed, "BEGIN:VCALENDAR") ||
			strings.HasPrefix(trimmed, "END:VCALENDAR") ||
			strings.HasPrefix(trimmed, "VERSION:") ||
			strings.HasPrefix(trimmed, "PRODID:") {
			continue
		}

		// Component boundaries (VEVENT, VTODO, VJOURNAL)
		if strings.HasPrefix(trimmed, "BEGIN:VEVENT") ||
			strings.HasPrefix(trimmed, "BEGIN:VTODO") ||
			strings.HasPrefix(trimmed, "BEGIN:VJOURNAL") {
			depth++
			if depth == 1 {
				current.Reset()
			}
		}

		if depth > 0 {
			current.WriteString(line)
		}

		if strings.HasPrefix(trimmed, "END:VEVENT") ||
			strings.HasPrefix(trimmed, "END:VTODO") ||
			strings.HasPrefix(trimmed, "END:VJOURNAL") {
			if depth == 1 && current.Len() > 0 {
				components = append(components, current.String())
			}
			depth--
		}
	}
	return components
}

func calendarEventExists(ctx context.Context, pool *pgxpool.Pool, calendarID int64, uid string) bool {
	var exists bool
	_ = pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM calendar_events WHERE calendar_id = $1 AND uid = $2)`,
		calendarID, uid,
	).Scan(&exists)
	return exists
}

func deleteCalendarEvent(ctx context.Context, pool *pgxpool.Pool, calendarID int64, uid string) {
	_, _ = pool.Exec(ctx, `DELETE FROM calendar_events WHERE calendar_id = $1 AND uid = $2`, calendarID, uid)
}

func insertCalendarEvent(ctx context.Context, pool *pgxpool.Pool, calendarID int64, ev *caldav.CalendarEvent) error {
	var startAt, endAt, completedAt, dueAt, recurrenceID interface{}
	if !ev.Start.IsZero() {
		startAt = ev.Start
	}
	if !ev.End.IsZero() {
		endAt = ev.End
	}
	if !ev.CompletedAt.IsZero() {
		completedAt = ev.CompletedAt
	}
	if !ev.DueAt.IsZero() {
		dueAt = ev.DueAt
	}
	if ev.RecurrenceID != "" {
		t, err := time.Parse("20060102T150405Z", ev.RecurrenceID)
		if err != nil {
			t, err = time.Parse("20060102", ev.RecurrenceID)
		}
		if err == nil {
			recurrenceID = t
		}
	}

	var orgEmail, orgName interface{}
	if ev.Organizer.Email != "" {
		orgEmail = ev.Organizer.Email
	}
	if ev.Organizer.Name != "" {
		orgName = ev.Organizer.Name
	}

	_, err := pool.Exec(ctx, `
		INSERT INTO calendar_events (
			calendar_id, uid, component_type,
			title, description, location,
			start_at, end_at, all_day, timezone,
			rrule, rdate, exdate,
			status, priority, percent_complete, completed_at, due_at,
			organizer_email, organizer_name, recurrence_id
		) VALUES ($1,$2,$3, $4,$5,$6, $7,$8,$9,$10, $11,$12,$13, $14,$15,$16,$17,$18, $19,$20, $21)`,
		calendarID, ev.UID, ev.Component,
		ev.Title, ev.Description, ev.Location,
		startAt, endAt, ev.AllDay, ev.Timezone,
		ev.RRULE, ev.RDATE, ev.EXDATE,
		ev.Status, nullInt(ev.Priority), ev.PercentComplete, completedAt, dueAt,
		orgEmail, orgName, recurrenceID,
	)
	return err
}

// validEventStatus is the calendar_events.status CHECK set — an iCal STATUS
// token (often upper-case CONFIRMED/TENTATIVE/CANCELLED) must be lower-cased
// and matched against this, else the row's CHECK constraint would reject the
// whole event. Shared by every consumer of EventsToJSON.
var validEventStatus = map[string]bool{
	"confirmed": true, "tentative": true, "cancelled": true,
	"needs-action": true, "in-progress": true, "completed": true,
}

// EventsToJSON converts already-parsed events (SplitAndParseICS's output) into
// the JSON array shape both calendar_import_ics and calendar_subscription_refresh
// consume: {uid, title, description, location, isAllDay, timeZone,
// recurrenceRule, start, end, status}. Extracted so the ICS-file-import JMAP
// handler (jmap/calendar_import.go) and the webcal-subscribe worker
// (internal/calendarsync) share ONE mapping instead of two hand-copies that
// would drift (attendees/valarm are deliberately left out — see the reducers'
// own docs on why a personal-calendar copy must not email attendees).
func EventsToJSON(events []caldav.CalendarEvent) ([]byte, error) {
	arr := make([]map[string]any, 0, len(events))
	for i := range events {
		ev := &events[i]
		m := map[string]any{
			"uid":            ev.UID,
			"title":          ev.Title,
			"description":    ev.Description,
			"location":       ev.Location,
			"isAllDay":       ev.AllDay,
			"timeZone":       ev.Timezone,
			"recurrenceRule": ev.RRULE,
		}
		if !ev.Start.IsZero() {
			m["start"] = ev.Start.UTC().Format(time.RFC3339)
		}
		if !ev.End.IsZero() {
			m["end"] = ev.End.UTC().Format(time.RFC3339)
		}
		if s := strings.ToLower(strings.TrimSpace(ev.Status)); validEventStatus[s] {
			m["status"] = s
		}
		arr = append(arr, m)
	}
	return json.Marshal(arr)
}

func nullInt(n int) interface{} {
	if n == 0 {
		return nil
	}
	return n
}
