# RFC 5545 — iCalendar Critical Sections
> Source: https://www.rfc-editor.org/rfc/rfc5545

## §3.3.11 Property Value Escaping

Characters that MUST be escaped in property values:
- BACKSLASH (`\`) → `\\`  
- SEMICOLON (`;`) → `\;`
- COMMA (`,`) → `\,`
- NEWLINE (`\n`) → `\\n` or `\N`

## §3.6 Calendar Components

Core components:
- `VCALENDAR` (top-level, REQUIRED)
- `VEVENT` (events, REQUIRED for CalDAV)
- `VTODO` (to-dos)
- `VJOURNAL` (journal entries)
- `VFREEBUSY` (free/busy time)
- `VTIMEZONE` (time zone definitions)
- `VALARM` (reminders/alarms)

## §3.8.7 Property Parameters

### §3.8.7.2 DTSTAMP (MANDATORY in VEVENT/VTODO/VJOURNAL/VFREEBUSY)
- Format: `DTSTAMP:19970714T170000Z`
- Value type: DATE-TIME (UTC)
- Created when the iCalendar object was created

### §3.8.7.4 SEQUENCE (REQUIRED per RFC 6638 for scheduling)
- Format: `SEQUENCE:0`
- Value type: INTEGER
- Incremented on each significant revision
- Default: 0

## §3.3.4 DATE-TIME

Complete representation (UTC): `19970714T170000Z`
Complete with offset: `19970714T170000-0700`
Date only: `19970714` (for all-day events)
With fractional seconds: `19970714T170000.5Z`

## §3.3.11 Line Folding

Lines longer than 75 octets MUST be folded:
- After 75 octets, insert CRLF followed by a single SPACE or HTAB
- The folded whitespace is part of the continuation, not the value
- Folding MUST NOT split multi-byte characters
