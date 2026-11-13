## iCalendar & CalDAV Protocol Requirements
> **RFC 5545** (iCalendar), **RFC 4791** (CalDAV), **RFC 6047** (iMIP), **RFC 7986** (Properties)

### iCalendar — RFC 5545
- ALL property values MUST be escaped: `\` → `\\`, `;` → `\;`, `,` → `\,`, `\n` → `\\n` (§3.3.11)
- DTSTAMP is MANDATORY in VEVENT/VTODO/VJOURNAL/VFREEBUSY (§3.8.7.2)
- SEQUENCE MUST be included and incremented on significant updates (§3.8.7.4)
- Line folding MUST NOT split multi-byte UTF-8 characters — use rune-safe boundary detection
- DTSTART/DTEND parsing MUST handle: fractional seconds (`.5Z`), numeric offsets (`+05:30`), date-only
- ✅ BYDAY, BYMONTHDAY, BYYEARDAY in expand_recurrence() PL/pgSQL
- ✅ VTIMEZONE component support — parsing, storage (vt_timezone table), generation from Go tzdata, CalDAV calendar-timezone property

### CalDAV — RFC 4791
- MKCALENDAR MUST create a calendar — it was a no-op returning 201 without action
- All error responses MUST include `DAV:error` XML body with appropriate error element (§6)
- ✅ free-busy-query REPORT MUST be implemented (§7.10)
- calendar-multiget REPORT MUST use correct XML root element + parse hrefs (§7.9)
- Status values MUST use RFC 5545 format: `CANCELLED` (uppercase double-L)

### iMIP — RFC 6047
- `BuildIMip()` MUST be called when creating events with external attendees
- Outbound iMIP MUST include Message-ID header (§5.1)
- Content-Type MUST use `multipart/alternative` with `component=` parameter (§2.4)

### iTIP — RFC 5546
- `processRequest` MUST resolve attendee user ID from email, not use hardcoded `userID=0`

### DO NOT
- Do NOT serialize property values without `escape()` — commas/semicolons/backslashes corrupt output
- Do NOT split lines at byte boundary — use rune-safe splitting
- Do NOT return 201 from MKCALENDAR without creating a calendar
- Do NOT use bare `time.RFC3339` for REV/DTSTAMP — use `20060102T150405Z` (basic format)
- Do NOT hardcode `userID=0` for attendee resolution

### Verification
```bash
go test ./internal/caldav/... -v
```
