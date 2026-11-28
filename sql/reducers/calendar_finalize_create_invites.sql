-- calendar_finalize_create_invites: build the iMIP REQUEST payload for each freshly-created
-- CalendarEvent/set event that has invitees, reading the decision from the STORED rows.
--
-- This is the reducer half of the CalendarEvent/set *create* invite side-effect that used
-- to live in the Go gateway (`sendInvitesForCreatedEvents`): the recipient set (the event's
-- attendees) and the event fields are now read from the persisted event/attendee rows
-- instead of re-parsed from the raw client `create` JSON. The Go gateway is left with pure
-- byte-serialization + egress (serializeAndEnqueueInvite: BuildIMip → blob → outbound_queue).
--
-- Per event (in the order given), returns one payload row when the event is owned by
-- p_mailbox_id AND has at least one attendee other than the organizer address; events with
-- no such recipient are SKIPPED (no row), exactly as the old Go path skipped events with
-- len(attendees)==0. NOTE this is the CREATE contract: it does NOT gate on
-- calendar_events.is_meeting (jmap_calendar_event_set_create never sets it — a created
-- event is is_meeting=FALSE — so a calendar_send_invite-style is_meeting gate here would
-- suppress every create-path invite, a regression). is_meeting gating stays the
-- sendUpdate path's behavior (calendar_send_invite, used by jmap_calendar_event_send_update).
--
-- The organizer address is supplied by the caller (p_organizer_email / p_organizer_name) —
-- the SAME value the gateway used before (user.Email, or the delegatedFrom override) —
-- because a normally-created event stores organizer_email = NULL (set only on the delegated
-- path). This preserves the exact organizer the old Go path put on the wire.
--
-- Payload shape (one element per emitted event) — the serializeAndEnqueueInvite worker
-- contract: { uid, title, description, location, start, end, allDay, timezone, status,
-- rrule, organizerEmail, organizerName,
--             attendees:[{email,name,role,participationStatus,expectReply}] }.
-- start/end are emitted as Z-normalized RFC3339 (to_char … AT TIME ZONE 'UTC') so the Go
-- worker's time.Parse yields the same instant/zone the client sent (a raw timestamptz JSON
-- carries the session offset and would shift the rendered wall-clock). attendees are ALL
-- stored attendees in insertion order (id) — including the organizer-role and resource
-- rows — matching the old Go path (which serialized every client attendee and excluded the
-- organizer only from the recipient envelope, done in the worker).
--
-- CREATE-PATH ATTENDEE PARTSTAT/RSVP — carries the STORED participation status (RFC 5546
-- §3.2.2). Each attendee emits the persisted event_attendees.status / .rsvp under the JMAP
-- keys participationStatus / expectReply — the ONE canonical iMIP attendee wire shape that
-- the JSON-tagged caldav.Attendee reads and that calendar_send_invite (sendUpdate) already
-- speaks. A new-meeting REQUEST to a fresh invitee therefore carries
-- ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE (the create reducer's stored default per
-- jmap_calendar.sql:165-166), so the invitee's client knows it must respond. The organizer's
-- own row carries whatever it stored (e.g. accepted) and is included in the VEVENT body
-- (excluded only from the recipient envelope, in the worker). This REVERTS the wave-6
-- byte-preservation blanking (which emitted status=''/rsvp=FALSE to match HEAD's tag-less
-- caldav.Attendee unmarshal that dropped participationStatus/expectReply); both the create
-- and the sendUpdate path now emit PARTSTAT/RSVP — one coherent wire shape, two callers.
CREATE OR REPLACE FUNCTION calendar_finalize_create_invites(
  p_mailbox_id        BIGINT,
  p_created_event_ids BIGINT[],
  p_organizer_email   TEXT,
  p_organizer_name    TEXT DEFAULT ''
) RETURNS SETOF JSONB AS $$
DECLARE
  v_event_id  BIGINT;
  v_event     RECORD;
  v_attendees JSONB;
  v_payload   JSONB;
BEGIN
  IF p_created_event_ids IS NULL OR array_length(p_created_event_ids, 1) IS NULL THEN
    RETURN;
  END IF;

  FOREACH v_event_id IN ARRAY p_created_event_ids
  LOOP
    -- Ownership (R1): only events on a calendar owned by p_mailbox_id are eligible.
    SELECT ce.*, c.mailbox_id AS cal_mailbox_id INTO v_event
    FROM calendar_events ce
    JOIN calendars c ON c.id = ce.calendar_id
    WHERE ce.id = v_event_id AND c.mailbox_id = p_mailbox_id;

    IF NOT FOUND THEN
      CONTINUE;
    END IF;

    -- All stored attendees, in insertion (client array) order, under the canonical JMAP
    -- attendee wire keys (participationStatus/expectReply — what the JSON-tagged
    -- caldav.Attendee reads). Mirrors the old Go path: every attendee is serialized; the
    -- organizer is excluded from the recipient envelope by the worker, not here. The stored
    -- participation status/rsvp ride the wire so the ATTENDEE line carries PARTSTAT/RSVP
    -- (RFC 5546 §3.2.2) — see the CREATE-PATH ATTENDEE note in the header.
    SELECT jsonb_agg(jsonb_build_object(
      'email', ea.email,
      'name',  ea.name,
      'role',  ea.role,
      'participationStatus', ea.status,
      'expectReply',         ea.rsvp
    ) ORDER BY ea.id) INTO v_attendees
    FROM event_attendees ea
    WHERE ea.event_id = v_event_id;

    -- Skip events with no recipient other than the organizer address — the old Go path's
    -- "len(attendees)==0 → continue", generalized to "no non-organizer attendee".
    IF v_attendees IS NULL OR NOT EXISTS (
      SELECT 1 FROM event_attendees ea
      WHERE ea.event_id = v_event_id
        AND ea.email IS NOT NULL
        AND ea.email <> p_organizer_email
    ) THEN
      CONTINUE;
    END IF;

    v_payload := jsonb_build_object(
      'eventId',        v_event_id::TEXT,
      'uid',            v_event.uid,
      'title',          v_event.title,
      'description',    v_event.description,
      'location',       v_event.location,
      'start',          to_char(v_event.start_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
      'end',            to_char(v_event.end_at   AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
      'allDay',         v_event.all_day,
      'timezone',       v_event.timezone,
      'status',         v_event.status,
      'sequence',       v_event.sequence,
      'rrule',          v_event.rrule,
      'organizerEmail', p_organizer_email,
      'organizerName',  COALESCE(p_organizer_name, ''),
      'attendees',      v_attendees
    );

    RETURN NEXT v_payload;
  END LOOP;

  RETURN;
END;
$$ LANGUAGE plpgsql;
