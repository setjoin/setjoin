# Conference/Room Booking Calendar UI — Design Spec

> **Roadmap:** Stage 3.4 — Global Platform | **Effort:** ~4 weeks | **Status:** Draft

## Goal

Ship a scheduling-assistant UI in SvelteKit webmail that makes booking rooms and finding attendee availability as fluid as Gmail Calendar or EXO. Users create an event, add attendees, see a side-by-side availability grid, filter rooms by capacity/equipment/location, and pick a slot where everyone (and the room) is free. Builds on the existing CalDAV free/busy backend and `calendars` resource schema.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  SvelteKit Calendar Page (existing +page.svelte)        │
│  ┌──────────────────────┐  ┌──────────────────────────┐│
│  │ AvailabilityGrid     │  │ RoomFinder               ││
│  │ · free slot selection│  │ · capacity filter        ││
│  │ · color-coded busy   │  │ · equipment checklist    ││
│  │ · timeline scrub     │  │ · location/building      ││
│  │ · auto-scroll to 1st │  │ · room detail card       ││
│  │   mutual free slot   │  │ · book room button       ││
│  └──────────┬───────────┘  └───────────┬──────────────┘│
│             │                           │               │
│  ┌──────────┴───────────────────────────┴──────────────┐│
│  │  SchedulingStore ($state)                            ││
│  │  attendees[], timeRange, busyIntervals, selectedRoom ││
│  │  computeMutualFree() → derived slot list             ││
│  └──────────────────────┬──────────────────────────────┘│
└─────────────────────────┼───────────────────────────────┘
                          │ HTTP (JMAP Calendars/get +
                          │  CalDAV free-busy-query)
┌─────────────────────────┼───────────────────────────────┐
│  Go Gateway             │                               │
│  ┌──────────────────────┴──────────────────────────────┐│
│  │  CalDAV Handler (existing)                          ││
│  │  POST /caldav/{id}/ — REPORT free-busy-query        ││
│  │  Returns VFREEBUSY iCalendar per attendee           ││
│  │  → Already wired to calendar_free_busy() reducer    ││
│  │  → Add multi-user batch endpoint for scheduling UI  ││
│  └─────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────┘
```

### Data Flow

1. User opens event composer, types attendee emails. Frontend fires parallel CalDAV free-busy-query requests per attendee (or a single batch POST to a new endpoint: `POST /caldav/freebusy/batch`).
2. Gateway queries `calendar_free_busy(p_user_ids[], p_start, p_end)` for all attendees in one call, plus all room calendars where `resource_type = 'room'`. Returns JSON array of `{email, intervals[]}`.
3. SchedulingStore receives intervals, merges them into a timeline grid. `computeMutualFree()` walks the union of all busy intervals and returns contiguous free slots >= 15 min.
4. RoomFinder queries `JMAP Calendars/get` filtered to `resource_type='room'` with `capacity`, `equipment` (from calendar properties), and `location` (from mailbox metadata). User filters narrow the list; selecting a room adds its busy intervals to the grid.
5. On slot selection, the event form prefills `start`/`end` and the selected room as a resource attendee. Save triggers `JMAP CalendarEvent/set` with the room as an organizer-managed attendee. The room's `booking_policy` (auto-accept, manual, decline-conflict) controls response — same reducer already handles `iTIP REPLY`.

## Files

| Action | File | Purpose |
|--------|------|---------|
| **Create** | `mailserver/webmail/src/lib/components/AvailabilityGrid.svelte` | Timeline grid: rows = attendees + rooms, columns = 30-min buckets; green (free), red (busy), amber (tentative), striped (room occupied) |
| **Create** | `mailserver/webmail/src/lib/components/RoomFinder.svelte` | Filterable room list: capacity slider, equipment checkboxes (projector, VC, whiteboard, phone), building/location dropdown; room card with photo placeholder |
| **Create** | `mailserver/webmail/src/lib/stores/scheduling.ts` | `SchedulingStore` — $state rune: attendees (Set<string>), timeRange (DateRange), busyIntervals (Map<string, BusyInterval[]>), selectedRoom, derived `mutualFreeSlots` |
| **Create** | `mailserver/webmail/src/lib/components/SchedulingAssistant.svelte` | Two-pane glass-sheet: left = event form (title, date, duration), right = AvailabilityGrid + RoomFinder tabs; "Find a time" auto-scroll |
| **Create** | `mailserver/gateway/internal/caldav/freebusy_batch.go` | `POST /caldav/freebusy/batch` — accepts JSON `{user_ids:[], room_ids:[], start, end}`, returns aggregated free/busy intervals per entity |
| **Create** | `mailserver/gateway/internal/caldav/freebusy_batch_test.go` | Unit tests: multi-user query, room-only query, empty result, timezone edge cases |
| **Create** | `mailserver/sql/reducers/calendar_free_busy_multi.sql` | PL/pgSQL reducer: `calendar_free_busy_multi(p_cal_ids int[], p_start timestamptz, p_end timestamptz)` — batch version returning JSONB keyed by calendar ID |
| **Modify** | `mailserver/webmail/src/routes/calendar/+page.svelte` | Add "New event with scheduling" button; open SchedulingAssistant in glass-modal overlay |
| **Modify** | `mailserver/webmail/src/lib/types/jmap.ts` | Extend CalendarEvent type: `resourceAttendees`, `roomId`, `equipmentNeeds` |
| **Modify** | `mailserver/gateway/cmd/gateway/main.go` | Register `/caldav/freebusy/batch` route (RequireAuth middleware) |
| **Create** | `mailserver/webmail/src/lib/components/AvailabilityGrid.test.ts` | Vitest: free-slot computation, interval merging, DST transitions |
| **Total** | **~1,200 LOC** | **11 files** |

## Key Design Decisions

1. **No real-time WebSocket for free/busy in V1.** The scheduling assistant queries free/busy at open time and offers a manual "Refresh" button. CalDAV clients already poll; the JMAP push channel handles event-save notifications. Real-time free/busy via WebSocket subscribe is stage 3.4b.

2. **Batch endpoint, not N individual queries.** A single `POST /caldav/freebusy/batch` accepts arrays of user IDs and room IDs, calls `calendar_free_busy_multi()` once, and returns all intervals in one JSON response. This avoids the N+1 problem when scheduling with 20 attendees.

3. **Room as calendar-resource, not separate table.** Rooms already live in the `calendars` table with `resource_type = 'room'` (schema `025_calendar_resources.sql`). The RoomFinder queries via existing JMAP `Calendars/get` filtered by `resourceType`. No new database tables.

4. **Booking policy respected at save time.** Rooms with `booking_policy = 'auto-accept'` immediately accept; `decline-conflict` rejects if the selected slot conflicts (reducer-level conflict check); `manual` creates a pending iTIP request to the room administrator. All three policies are already modeled in the schema — the UI just surfaces the policy as a badge on the room card.

5. **Attendee resolution via JMAP Identity.** Typing an attendee email triggers a JMAP `Identity/get` suggest lookup against the GAL (existing LDAP + CardDAV backend). Unknown external attendees typed free-form trigger a free/busy probe only if the external domain publishes CalDAV free/busy URL (per RFC 4791 §7.10). Internal attendees always queried.

6. **Mutual free-slot algorithm runs client-side.** The server returns raw busy intervals per attendee. The client computes mutual free slots by building the union of all busy intervals and walking the 30-minute buckets. This keeps the server stateless and lets the UI instantly recalculate when the user changes the time range or adds/removes attendees.

7. **15-minute minimum slot.** Mutual free slots shorter than 15 minutes are discarded. The default meeting duration is 30 minutes; slots shorter than the desired duration are grayed out in the grid.

## Competitive Context

All 7 platforms in our comparison matrix offer scheduling assistants, but execution quality varies significantly:

| Platform | Availability Grid | Room Finder | Filter Depth |
|----------|------------------|-------------|--------------|
| **Gmail** | Side-by-side attendee columns, color-coded | Yes — capacity, building, floor | Equipment tags, "popular times" |
| **EXO** | Horizontal timeline, Room Finder pane | Yes — capacity, location, add-in extensible | AV, accessibility filters |
| **Zimbra** | Basic free/busy overlay only | Manual room entry, no finder | None |
| **NetEase** | Single-user free/busy only | None | None |
| **Tencent** | Basic attendee list | Room booking separate module | Capacity only |
| **DingTalk** | Integrated smart scheduling | Building/floor picker | AI-suggested rooms |
| **Lark** | Side-by-side grid | Capacity + equipment + floor plan | QR code room check-in |

Our implementation targets Gmail/EXO parity: side-by-side attendee columns with color coding, Room Finder with capacity/equipment/location filters. We differentiate with (a) CalDAV-native free/busy — interop with any CalDAV client, not just our webmail; (b) on-premise — no cloud dependency for scheduling data; (c) Liquid Glass design — the scheduling assistant renders as a glass-modal overlay with backdrop blur, consistent with the Prism design system.

## Dependencies

- **Phase 9 (Calendar, complete):** CalDAV bridge, `calendar_free_busy()` reducer, iTIP/iMIP, `calendars` resource schema (`025_calendar_resources.sql`)
- **Phase 3 (JMAP, complete):** `Calendars/get` with property filtering, `CalendarEvent/set` with attendee management
- **Phase 17 (Tag system, complete):** No direct dependency; scheduling does not interact with tags
- **Phase 10 (Contacts & GAL, complete):** JMAP `Identity/get` for attendee auto-complete and LDAP directory lookup
- **Phase 11 (Tasks, complete):** No dependency
- **Phase 7 (Security, complete):** `RequireAuth` middleware on the batch endpoint; calendar ownership enforcement via existing `getCalendar()` ACL check
- **No new Go dependencies** — the batch endpoint uses existing `pgxpool`, `encoding/json`, and the `calendars`/`mailboxes` schema
- **No new NPM dependencies** — the scheduling UI uses Svelte 5 runes ($state, $derived), existing Lucide icons, and existing Prism design tokens (`.glass-modal`, `.glass-pane`, `.btn--primary`)

## Non-Goals

- Real-time WebSocket free/busy push (deferred to 3.4b)
- QR-code room check-in (e.g., DingTalk/Lark style — physical room display integration)
- Room floor-plan viewer or room photo upload
- External attendee free/busy probe (CalDAV cross-domain discovery) — internal attendees only for V1
- Catering/facilities add-on requests bundled with room booking
- Recurring meeting room booking conflict resolution in the grid (single-instance only for V1; recurring inherits the same reducer-level conflict check)
- "Find a time" AI ranking (deferred to Stage 3.3 — AI Features)
- Room booking approval workflow UI for `manual` policy (room admins approve via iTIP email; dedicated admin queue deferred)

## Effort Estimate

**~4 weeks** (1 engineer). Breakdown: batch free/busy endpoint + reducer (0.5w), SchedulingStore + availability algorithm (0.5w), AvailabilityGrid component with color-coded timeline (1w), RoomFinder with filters (0.5w), SchedulingAssistant glass-modal integration into calendar page (0.5w), Vitest unit tests + CalDAV endpoint tests + manual QA (0.5w), polish + accessibility audit (0.5w).
