-- JMAP Calendar/* reducers (JMAP Calendars draft)

-- jmap_calendar_get: return Calendar objects.
CREATE OR REPLACE FUNCTION jmap_calendar_get(
  p_mailbox_id BIGINT,
  p_ids        BIGINT[] DEFAULT NULL
) RETURNS JSONB AS $$
DECLARE
  v_result    JSONB := '[]'::JSONB;
  v_row       RECORD;
  v_state     BIGINT;
  v_found     TEXT[] := ARRAY[]::TEXT[];
BEGIN
  v_state := entity_state(p_mailbox_id, 'Calendar');

  FOR v_row IN
    SELECT c.*, (SELECT COUNT(*) FROM calendar_events WHERE calendar_id = c.id) AS event_count
    FROM calendars c
    WHERE c.mailbox_id = p_mailbox_id
      AND (p_ids IS NULL OR c.id = ANY(p_ids))
    ORDER BY c.name
  LOOP
    v_result := v_result || jsonb_build_object(
      'id', v_row.id::TEXT,
      'name', v_row.name,
      'description', v_row.description,
      'color', v_row.color,
      'timeZone', v_row.timezone,
      'isDefault', v_row.is_default,
      'isShared', v_row.is_shared,
      'myRights', jsonb_build_object(
        'mayReadItems', true,
        'mayAddItems', true,
        'mayRemoveItems', true,
        'mayUpdatePrivate', true,
        'mayRSVP', true,
        'mayDelete', NOT v_row.is_default
      )
    );
    v_found := v_found || v_row.id::TEXT;
  END LOOP;

  RETURN build_jmap_get_response(
    p_mailbox_id, v_state, v_result, v_found,
    CASE WHEN p_ids IS NOT NULL
      THEN ARRAY(SELECT x::TEXT FROM unnest(p_ids) AS x) END
  );
END;
$$ LANGUAGE plpgsql;

-- jmap_calendar_event_set_create: insert new events.
CREATE OR REPLACE FUNCTION jmap_calendar_event_set_create(
  p_mailbox_id BIGINT,
  p_actor_id   BIGINT,
  p_actor_email TEXT,
  p_creates    JSONB
) RETURNS JSONB AS $$
DECLARE
  v_key            TEXT;
  v_obj            JSONB;
  v_calendar_id    BIGINT;
  v_event_id       BIGINT;
  v_created        JSONB := '{}'::JSONB;
  v_notCreated     JSONB := '{}'::JSONB;
  v_old_state      BIGINT;
  v_new_state      BIGINT;
  v_attendee       JSONB;
  v_delegated_from TEXT;
  v_delegator_mbox BIGINT;
  v_delegator_user BIGINT;
  v_delegator_name TEXT;
BEGIN
  v_old_state := entity_state(p_mailbox_id, 'CalendarEvent');

  FOR v_key, v_obj IN SELECT * FROM jsonb_each(p_creates)
  LOOP
    BEGIN
      v_calendar_id := COALESCE((v_obj->>'calendarId')::BIGINT,
        (SELECT id FROM calendars WHERE mailbox_id = p_mailbox_id AND is_default = TRUE LIMIT 1));

      IF v_calendar_id IS NULL THEN
        v_notCreated := v_notCreated || jsonb_build_object(v_key,
          jsonb_build_object('type', 'invalidArguments', 'description', 'No default calendar'));
        CONTINUE;
      END IF;

      -- Verify calendar belongs to this account
      IF NOT EXISTS (SELECT 1 FROM calendars WHERE id = v_calendar_id AND mailbox_id = p_mailbox_id) THEN
        v_notCreated := v_notCreated || jsonb_build_object(v_key,
          jsonb_build_object('type', 'invalidArguments', 'description', 'Calendar not found'));
        CONTINUE;
      END IF;

      -- Check calendar delegation when delegatedFrom is set
      v_delegated_from := v_obj->>'delegatedFrom';
      IF v_delegated_from IS NOT NULL AND v_delegated_from != '' THEN
        -- Resolve the delegator by ANY of their addresses (primary ∪ alias ∪ UPN)
        -- through the one address-aware seam (ADR-004) — a delegator addressed by
        -- an alias or UPN previously failed as "Delegator not found". The resolved
        -- person also supplies organizer_name below (no second email-only lookup).
        SELECT ri.primary_mailbox, ri.user_id INTO v_delegator_mbox, v_delegator_user
        FROM resolve_identity(v_delegated_from) ri;

        IF v_delegator_mbox IS NULL THEN
          v_notCreated := v_notCreated || jsonb_build_object(v_key,
            jsonb_build_object('type', 'invalidArguments', 'description', 'Delegator not found'));
          CONTINUE;
        END IF;

        SELECT display_name INTO v_delegator_name FROM users WHERE id = v_delegator_user;

        -- Verify actor has send_as or full_access delegation on delegator's mailbox
        IF NOT EXISTS (
          SELECT 1 FROM mailbox_delegates
          WHERE mailbox_id = v_delegator_mbox
            AND user_id = p_actor_id
            AND permission IN ('send_as', 'full_access')
        ) THEN
          v_notCreated := v_notCreated || jsonb_build_object(v_key,
            jsonb_build_object('type', 'forbidden', 'description', 'Not authorized to send on behalf of ' || v_delegated_from));
          CONTINUE;
        END IF;
      END IF;

      INSERT INTO calendar_events (
        calendar_id, uid, title, description, location, color,
        start_at, end_at, all_day, timezone, status, transp, classification,
        valarm, rrule, organizer_email, organizer_name, etag, jmap_state
      ) VALUES (
        v_calendar_id,
        COALESCE(v_obj->>'uid', gen_random_uuid()::TEXT),
        COALESCE(v_obj->>'title', 'Untitled'),
        v_obj->>'description',
        v_obj->>'location',
        v_obj->>'color',
        COALESCE((v_obj->>'start')::TIMESTAMPTZ, now()),
        COALESCE((v_obj->>'end')::TIMESTAMPTZ, now() + interval '1 hour'),
        COALESCE((v_obj->>'isAllDay')::BOOL, FALSE),
        COALESCE(v_obj->>'timeZone', 'UTC'),
        COALESCE(v_obj->>'status', 'confirmed'),
        -- freeBusyStatus: 'free' → TRANSPARENT; anything else (incl. absent) → OPAQUE/busy.
        CASE WHEN v_obj->>'freeBusyStatus' = 'free' THEN 'TRANSPARENT' ELSE 'OPAQUE' END,
        -- privacy (RFC 8984) → iCal CLASS: private→PRIVATE, secret→CONFIDENTIAL, else PUBLIC.
        CASE v_obj->>'privacy' WHEN 'private' THEN 'PRIVATE' WHEN 'secret' THEN 'CONFIDENTIAL' ELSE 'PUBLIC' END,
        -- valarm (RFC 8984 alerts): the client sends an array of {trigger:<ISO>, action}
        -- with ABSOLUTE trigger instants; scan_due_reminders() enqueues each element whose
        -- trigger has passed. Stored verbatim as jsonb (NULL when absent).
        v_obj->'valarm',
        v_obj->>'recurrenceRule',
        CASE WHEN v_delegated_from IS NOT NULL AND v_delegated_from != '' THEN v_delegated_from ELSE NULL END,
        -- organizer_name from the address-aware-resolved delegator (set above),
        -- not a second users.email-only lookup that would miss an alias/UPN.
        CASE WHEN v_delegated_from IS NOT NULL AND v_delegated_from != '' THEN v_delegator_name ELSE NULL END,
        generate_etag(),
        -- Per-row jmap_state must be monotonic within the mailbox: a literal 1 does
        -- not advance MAX(calendar_events.jmap_state) once the mailbox holds events
        -- past state 1 (event_query/itip read that MAX), so a state-polling reader
        -- would miss the create. Stamp MAX+1 (mirrors the jmap_task create fix).
        (SELECT COALESCE(MAX(ce2.jmap_state), 0) + 1
           FROM calendar_events ce2
           JOIN calendars c2 ON c2.id = ce2.calendar_id
          WHERE c2.mailbox_id = p_mailbox_id)
      )
      RETURNING id INTO v_event_id;

      -- Insert attendees if provided
      IF jsonb_typeof(v_obj->'attendees') = 'array' THEN
        FOR v_attendee IN SELECT * FROM jsonb_array_elements(v_obj->'attendees')
        LOOP
          INSERT INTO event_attendees (event_id, email, name, role, status, rsvp)
          VALUES (
            v_event_id,
            v_attendee->>'email',
            v_attendee->>'name',
            COALESCE(v_attendee->>'role', 'required'),
            COALESCE(v_attendee->>'participationStatus', 'needs-action'),
            COALESCE((v_attendee->>'expectReply')::BOOL, TRUE)
          );
        END LOOP;
      END IF;

      -- Bump calendars.jmap_state + push on 'calendar:{mailbox_id}' through the
      -- calendar seam (the JMAP path owns the calendar, so p_mailbox_id is the
      -- owner mailbox here).
      PERFORM notify_calendar_state(p_mailbox_id, v_event_id, v_calendar_id, 'event_created');

      v_created := v_created || jsonb_build_object(v_key, v_event_id::TEXT);
    EXCEPTION WHEN OTHERS THEN
      v_notCreated := v_notCreated || jsonb_build_object(v_key,
        jsonb_build_object('type', 'invalidArguments', 'description', 'creation failed'));
    END;
  END LOOP;

  v_new_state := entity_state(p_mailbox_id, 'CalendarEvent');

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'oldState', v_old_state::TEXT,
    'newState', v_new_state::TEXT,
    'created', v_created,
    'notCreated', v_notCreated
  );
END;
$$ LANGUAGE plpgsql;


-- jmap_calendar_event_set_destroy: delete events.
CREATE OR REPLACE FUNCTION jmap_calendar_event_set_destroy(
  p_mailbox_id BIGINT,
  p_ids        BIGINT[]
) RETURNS JSONB AS $$
DECLARE
  v_id          BIGINT;
  v_destroyed    JSONB := '[]'::JSONB;
  v_notDestroyed JSONB := '{}'::JSONB;
  v_old_state    BIGINT;
  v_new_state    BIGINT;
  v_cal_id       BIGINT;
BEGIN
  v_old_state := entity_state(p_mailbox_id, 'CalendarEvent');

  FOREACH v_id IN ARRAY p_ids
  LOOP
    BEGIN
      SELECT ce.calendar_id INTO v_cal_id
      FROM calendar_events ce
      JOIN calendars c ON c.id = ce.calendar_id
      WHERE ce.id = v_id AND c.mailbox_id = p_mailbox_id;

      IF v_cal_id IS NULL THEN
        v_notDestroyed := v_notDestroyed || jsonb_build_object(v_id::TEXT,
          jsonb_build_object('type', 'notFound'));
        CONTINUE;
      END IF;

      -- Ownership was already enforced when v_cal_id was resolved above
      -- (c.mailbox_id = p_mailbox_id); scope the delete to that validated calendar.
      -- The previous `mailboxes.user_id = p_mailbox_id` subquery was a type-confusion
      -- bug: p_mailbox_id is a mailbox id, so it matched zero rows and the row persisted
      -- while the client was told it was destroyed.
      --
      -- A recurring master owns its detached occurrences (override rows sharing its
      -- uid); destroying the master without them left orphans that could never be
      -- reached again (no master to enumerate them from). Delete siblings first,
      -- scoped to v_cal_id (already ownership-proven) — only when v_id IS a master
      -- (rrule set, recurrence_override NULL); an override row or non-recurring
      -- event has no siblings to clean up.
      DELETE FROM calendar_events ce
      USING calendar_events master
      WHERE master.id = v_id AND master.calendar_id = v_cal_id
        AND master.rrule IS NOT NULL AND master.recurrence_override IS NULL
        AND ce.calendar_id = v_cal_id AND ce.uid = master.uid
        AND ce.recurrence_override IS NOT NULL;

      DELETE FROM calendar_events WHERE id = v_id AND calendar_id = v_cal_id;

      -- Bump calendars.jmap_state + push on 'calendar:{mailbox_id}' through the
      -- calendar seam (p_mailbox_id owns v_cal_id — verified above).
      PERFORM notify_calendar_state(p_mailbox_id, v_id, v_cal_id, 'event_destroyed');

      v_destroyed := v_destroyed || to_jsonb(v_id);
    EXCEPTION WHEN OTHERS THEN
      v_notDestroyed := v_notDestroyed || jsonb_build_object(v_id::TEXT,
        jsonb_build_object('type', 'invalidArguments', 'description', 'destroy failed'));
    END;
  END LOOP;

  v_new_state := entity_state(p_mailbox_id, 'CalendarEvent');

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'oldState', v_old_state::TEXT,
    'newState', v_new_state::TEXT,
    'destroyed', v_destroyed,
    'notDestroyed', v_notDestroyed
  );
END;
$$ LANGUAGE plpgsql;

-- jmap_calendar_changes: real Calendar/changes deltas (A4). trg_journal_calendar
-- (V097) records created/updated/destroyed into jmap_changes_journal at each bump
-- of the 'Calendar' entity_state counter; this delegates to the shared reader.
CREATE OR REPLACE FUNCTION jmap_calendar_changes(
  p_mailbox_id   BIGINT,
  p_since_state  TEXT
) RETURNS JSONB AS $$
  SELECT jmap_entity_changes(p_mailbox_id, 'Calendar', p_since_state, NULL);
$$ LANGUAGE sql;

-- jmap_calendar_set_update: update calendar properties.
CREATE OR REPLACE FUNCTION jmap_calendar_set_update(
  p_mailbox_id BIGINT,
  p_updates    JSONB
) RETURNS JSONB AS $$
DECLARE
  v_id          BIGINT;
  v_patch       JSONB;
  v_updated     JSONB := '[]'::JSONB;
  v_notUpdated  JSONB := '{}'::JSONB;
  v_new_state   BIGINT;
BEGIN
  FOR v_id, v_patch IN SELECT * FROM jsonb_each(p_updates)
  LOOP
    BEGIN
      UPDATE calendars SET
        name = COALESCE(v_patch->>'name', name),
        description = COALESCE(v_patch->>'description', description),
        color = COALESCE(v_patch->>'color', color),
        timezone = COALESCE(v_patch->>'timeZone', timezone),
        updated_at = now()
      WHERE id = v_id AND mailbox_id = p_mailbox_id;

      IF FOUND THEN
        -- Route the calendar-object bump+push through the calendar seam (no event):
        -- bumps calendars.jmap_state for v_id (scoped to the owner mailbox) and
        -- pushes {event:'calendar_updated', calendar_id} on calendar:{mailbox_id}.
        PERFORM notify_calendar_state(p_mailbox_id, NULL, v_id, 'calendar_updated');
      END IF;

      v_updated := v_updated || to_jsonb(v_id);
    EXCEPTION WHEN OTHERS THEN
      v_notUpdated := v_notUpdated || jsonb_build_object(v_id::TEXT,
        jsonb_build_object('type', 'invalidArguments', 'description', 'update failed'));
    END;
  END LOOP;

  v_new_state := entity_state(p_mailbox_id, 'Calendar');

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'oldState', (v_new_state - 1)::TEXT,
    'newState', v_new_state::TEXT,
    'updated', v_updated,
    'notUpdated', v_notUpdated
  );
END;
$$ LANGUAGE plpgsql;

-- jmap_calendar_event_get: return CalendarEvent objects.
CREATE OR REPLACE FUNCTION jmap_calendar_event_get(
  p_mailbox_id BIGINT,
  p_ids        BIGINT[]
) RETURNS JSONB AS $$
DECLARE
  v_result    JSONB := '[]'::JSONB;
  v_row       RECORD;
  v_attendees JSONB;
  v_state     BIGINT;
  v_found     TEXT[] := ARRAY[]::TEXT[];
BEGIN
  v_state := entity_state(p_mailbox_id, 'CalendarEvent');

  FOR v_row IN
    SELECT ce.*, c.mailbox_id
    FROM calendar_events ce
    JOIN calendars c ON c.id = ce.calendar_id
    WHERE c.mailbox_id = p_mailbox_id
      AND ce.id = ANY(p_ids)
    ORDER BY ce.start_at
  LOOP
    SELECT jsonb_agg(jsonb_build_object(
      'name', ea.name,
      'email', ea.email,
      'role', ea.role,
      'participationStatus', ea.status,
      'expectReply', ea.rsvp
    )) INTO v_attendees
    FROM event_attendees ea
    WHERE ea.event_id = v_row.id;

    v_result := v_result || jsonb_build_object(
      'id', v_row.id::TEXT,
      'calendarId', v_row.calendar_id::TEXT,
      'uid', v_row.uid,
      'title', v_row.title,
      'description', v_row.description,
      'location', v_row.location,
      'color', v_row.color,
      'start', v_row.start_at,
      'end', v_row.end_at,
      'isAllDay', v_row.all_day,
      'timeZone', v_row.timezone,
      'status', v_row.status,
      -- freeBusyStatus (RFC 8984): free ↔ TRANSPARENT, busy ↔ OPAQUE. A
      -- tentative-status event reports 'tentative' regardless of transp
      -- (mirrors calendar_freebusy's status→tentative mapping).
      'freeBusyStatus', CASE
        WHEN v_row.status = 'tentative' THEN 'tentative'
        WHEN v_row.transp = 'TRANSPARENT' THEN 'free'
        ELSE 'busy'
      END,
      -- privacy (RFC 8984 JSCalendar) ← iCal CLASS: PRIVATE→private, CONFIDENTIAL→secret, else public.
      'privacy', CASE v_row.classification
        WHEN 'PRIVATE' THEN 'private' WHEN 'CONFIDENTIAL' THEN 'secret' ELSE 'public' END,
      'recurrenceRule', v_row.rrule,
      -- valarm (alerts): the stored absolute-trigger reminder array; the client reads it
      -- back to prefill the "Remind me" control when editing.
      'valarm', v_row.valarm,
      -- recurrenceId (RFC 8984): this row IS a detached occurrence of another series —
      -- carried on the OVERRIDE row, not the master.
      'recurrenceId', CASE WHEN v_row.recurrence_override IS NOT NULL
        THEN to_char(v_row.recurrence_override AT TIME ZONE COALESCE(v_row.timezone, 'UTC'),
                     'YYYY-MM-DD"T"HH24:MI:SS') END,
      -- recurrenceOverrides (RFC 8984): carried on the MASTER only — one entry per
      -- detached occurrence (the override row's patch vs. the master, keyed by the
      -- occurrence's LocalDateTime) plus one {"excluded":true} entry per pure EXDATE
      -- that has no backing override row (deleted, not edited).
      'recurrenceOverrides', CASE
        WHEN v_row.rrule IS NOT NULL AND v_row.recurrence_override IS NULL THEN
          COALESCE((
            SELECT jsonb_object_agg(
              to_char(o.recurrence_override AT TIME ZONE COALESCE(v_row.timezone, 'UTC'),
                      'YYYY-MM-DD"T"HH24:MI:SS'),
              jsonb_strip_nulls(jsonb_build_object(
                'title',       NULLIF(o.title, v_row.title),
                'start',       o.start_at,
                'end',         o.end_at,
                'location',    NULLIF(o.location, v_row.location),
                'description', NULLIF(o.description, v_row.description),
                'status',      NULLIF(o.status, v_row.status))))
            FROM calendar_events o
            WHERE o.calendar_id = v_row.calendar_id AND o.uid = v_row.uid   -- R1: same owner-scoped calendar
              AND o.recurrence_override IS NOT NULL
          ), '{}'::jsonb)
          ||
          COALESCE((
            SELECT jsonb_object_agg(
              to_char(x AT TIME ZONE COALESCE(v_row.timezone, 'UTC'), 'YYYY-MM-DD"T"HH24:MI:SS'),
              '{"excluded": true}'::jsonb)
            FROM unnest(v_row.exdate) x
            WHERE NOT EXISTS (SELECT 1 FROM calendar_events o2
              WHERE o2.calendar_id = v_row.calendar_id AND o2.uid = v_row.uid
                AND o2.recurrence_override = x)   -- exdate backing an override != excluded
          ), '{}'::jsonb)
        END,
      'attendees', COALESCE(v_attendees, '[]'::JSONB),
      'organizer', CASE WHEN v_row.organizer_email IS NOT NULL
        THEN jsonb_build_object('name', v_row.organizer_name, 'email', v_row.organizer_email) END,
      -- Meet B1 Task 16 calendar hook (spec §3.2): meeting_create.sql
      -- stamps both columns on the event's row when a setjoin Meet is
      -- attached; jmap_calendar_event_set_update's isMeeting:false patch
      -- (below) is the only client-reachable way to clear them (no delete
      -- route on the meeting itself — the meeting row survives).
      'isMeeting', v_row.is_meeting,
      'meetingUrl', v_row.meeting_url
    );
    v_found := v_found || v_row.id::TEXT;
  END LOOP;

  RETURN build_jmap_get_response(
    p_mailbox_id, v_state, v_result, v_found,
    CASE WHEN p_ids IS NOT NULL
      THEN ARRAY(SELECT x::TEXT FROM unnest(p_ids) AS x) END
  );
END;
$$ LANGUAGE plpgsql;

-- jmap_calendar_event_query: search events by time range and calendar.
CREATE OR REPLACE FUNCTION jmap_calendar_event_query(
  p_mailbox_id  BIGINT,
  p_filter      JSONB DEFAULT NULL,
  p_sort        JSONB DEFAULT NULL,
  p_position    INT   DEFAULT 0,
  p_limit       INT   DEFAULT 50
) RETURNS JSONB AS $$
DECLARE
  v_state       BIGINT;
  v_ids         TEXT[];  -- JMAP Id[] is strings; numeric ids 400 in CalendarEvent/get ([]string)
  v_total       INT;
  v_where       TEXT := 'c.mailbox_id = $1';
  v_order       TEXT := 'ce.start_at DESC';
BEGIN
  v_state := entity_state(p_mailbox_id, 'CalendarEvent');

  -- Parse sort (simplified: only property + isAscending)
  IF p_sort IS NOT NULL AND jsonb_array_length(p_sort) > 0 THEN
    v_order := CASE p_sort->0->>'property'
      WHEN 'startAt'  THEN 'ce.start_at ' || CASE WHEN COALESCE((p_sort->0->>'isAscending')::BOOL, true) THEN 'ASC' ELSE 'DESC' END
      WHEN 'endAt'    THEN 'ce.end_at '   || CASE WHEN COALESCE((p_sort->0->>'isAscending')::BOOL, true) THEN 'ASC' ELSE 'DESC' END
      WHEN 'title'    THEN 'ce.title '    || CASE WHEN COALESCE((p_sort->0->>'isAscending')::BOOL, true) THEN 'ASC' ELSE 'DESC' END
      WHEN 'created'  THEN 'ce.created_at ' || CASE WHEN COALESCE((p_sort->0->>'isAscending')::BOOL, true) THEN 'ASC' ELSE 'DESC' END
      ELSE 'ce.start_at DESC'
    END;
  END IF;

  IF p_filter IS NOT NULL THEN
    IF p_filter ? 'inCalendar' THEN
      v_where := v_where || format(' AND ce.calendar_id = %s', (p_filter->>'inCalendar')::BIGINT);
    END IF;
    IF p_filter ? 'before' THEN
      v_where := v_where || format(' AND ce.start_at < %L', p_filter->>'before');
    END IF;
    IF p_filter ? 'after' THEN
      v_where := v_where || format(' AND ce.end_at > %L', p_filter->>'after');
    END IF;
    IF p_filter ? 'text' THEN
      v_where := v_where || format(' AND (ce.title ILIKE %L OR ce.description ILIKE %L)',
        '%' || p_filter->>'text' || '%', '%' || p_filter->>'text' || '%');
    END IF;
  END IF;

  EXECUTE format('SELECT COUNT(*) FROM calendar_events ce JOIN calendars c ON c.id = ce.calendar_id WHERE %s', v_where)
    INTO v_total USING p_mailbox_id;

  EXECUTE format(
    'SELECT array_agg(id::TEXT) FROM (
      SELECT ce.id FROM calendar_events ce JOIN calendars c ON c.id = ce.calendar_id WHERE %s ORDER BY %s LIMIT %s OFFSET %s
    ) sub',
    v_where, v_order, p_limit, p_position
  ) INTO v_ids USING p_mailbox_id;

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'state', v_state::TEXT,
    'canCalculateChanges', false,
    'position', p_position,
    'total', v_total,
    'ids', COALESCE(to_jsonb(v_ids), '[]'::JSONB)
  );
END;
$$ LANGUAGE plpgsql;

-- jmap_calendar_event_changes: real CalendarEvent/changes deltas (A4).
-- trg_journal_calendar_event (V097) records created/updated/destroyed at each bump
-- of the 'CalendarEvent' entity_state counter (incl. RSVP/iTIP-cancel UPDATEs and
-- resource bookings, attributed to the event's OWNER mailbox); this delegates to
-- the shared reader. Coarse bulk paths (ICS import, subscription refresh, calendar
-- delete) emit a resync sentinel → BZ011 for a client spanning them.
CREATE OR REPLACE FUNCTION jmap_calendar_event_changes(
  p_mailbox_id   BIGINT,
  p_since_state  TEXT
) RETURNS JSONB AS $$
  SELECT jmap_entity_changes(p_mailbox_id, 'CalendarEvent', p_since_state, NULL);
$$ LANGUAGE sql;

-- jmap_calendar_event_set_update: update events.
CREATE OR REPLACE FUNCTION jmap_calendar_event_set_update(
  p_mailbox_id BIGINT,
  p_updates    JSONB
) RETURNS JSONB AS $$
DECLARE
  v_id          BIGINT;
  v_patch       JSONB;
  v_updated     JSONB := '[]'::JSONB;
  v_notUpdated  JSONB := '{}'::JSONB;
  v_old_state   BIGINT;
  v_new_state   BIGINT;
  v_event_cal_id BIGINT;
BEGIN
  v_old_state := entity_state(p_mailbox_id, 'CalendarEvent');

  FOR v_id, v_patch IN SELECT * FROM jsonb_each(p_updates)
  LOOP
    BEGIN
      UPDATE calendar_events ce SET
        title = COALESCE(v_patch->>'title', ce.title),
        description = COALESCE(v_patch->>'description', ce.description),
        location = COALESCE(v_patch->>'location', ce.location),
        color = COALESCE(v_patch->>'color', ce.color),
        start_at = COALESCE((v_patch->>'start')::TIMESTAMPTZ, ce.start_at),
        end_at = COALESCE((v_patch->>'end')::TIMESTAMPTZ, ce.end_at),
        all_day = COALESCE((v_patch->>'isAllDay')::BOOL, ce.all_day),
        timezone = COALESCE(v_patch->>'timeZone', ce.timezone),
        status = COALESCE(v_patch->>'status', ce.status),
        -- freeBusyStatus patch-present guard: only touch transp when the key is
        -- present (an unrelated update keeps the existing value). 'tentative' is
        -- driven by status, not transp, so it maps to OPAQUE here.
        transp = CASE WHEN v_patch ? 'freeBusyStatus'
          THEN (CASE WHEN v_patch->>'freeBusyStatus' = 'free' THEN 'TRANSPARENT' ELSE 'OPAQUE' END)
          ELSE ce.transp END,
        -- privacy patch-present guard: only touch classification when the key is present.
        classification = CASE WHEN v_patch ? 'privacy'
          THEN (CASE v_patch->>'privacy' WHEN 'private' THEN 'PRIVATE' WHEN 'secret' THEN 'CONFIDENTIAL' ELSE 'PUBLIC' END)
          ELSE ce.classification END,
        -- valarm patch-present guard: the client recomputes the absolute trigger on every
        -- edit (a start-time change must move the reminder), so an event edit always resends
        -- valarm; an unrelated patch (no 'valarm' key) keeps the existing reminder.
        valarm = CASE WHEN v_patch ? 'valarm' THEN v_patch->'valarm' ELSE ce.valarm END,
        -- Meet B1 Task 16 calendar hook: the ONLY client-reachable write to
        -- is_meeting/meeting_url is a {"isMeeting":false} patch, clearing
        -- both — design #15's "unchecking the toggle clears the event's
        -- is_meeting/meeting_url only; the meeting row survives (no delete
        -- route exists)". The client never sends isMeeting:true — that flag
        -- is set exclusively by meeting_create.sql's own stamp, never by
        -- this generic patch route, so a client can't spoof is_meeting=true
        -- for an event with no backing meeting.
        is_meeting = CASE WHEN v_patch ? 'isMeeting' AND NOT (v_patch->>'isMeeting')::bool
          THEN false ELSE ce.is_meeting END,
        meeting_url = CASE WHEN v_patch ? 'isMeeting' AND NOT (v_patch->>'isMeeting')::bool
          THEN NULL ELSE ce.meeting_url END,
        updated_at = now(),
        jmap_state = ce.jmap_state + 1,
        etag = generate_etag()
      FROM calendars c
      WHERE ce.id = v_id AND ce.calendar_id = c.id AND c.mailbox_id = p_mailbox_id;

      IF FOUND THEN
        -- The main UPDATE above already enforced ownership (c.mailbox_id = p_mailbox_id).
        -- Resolve the event's calendar id, then bump calendars.jmap_state + push on
        -- 'calendar:{mailbox_id}' through the calendar seam (scoped to p_mailbox_id,
        -- the owner mailbox). The seam's mailbox_id filter keeps the previous
        -- ownership scope; a foreign calendar id bumps nothing.
        SELECT DISTINCT calendar_id INTO v_event_cal_id
        FROM calendar_events WHERE id = v_id;

        PERFORM notify_calendar_state(p_mailbox_id, v_id, v_event_cal_id, 'event_updated');
      END IF;

      v_updated := v_updated || to_jsonb(v_id);
    EXCEPTION WHEN OTHERS THEN
      v_notUpdated := v_notUpdated || jsonb_build_object(v_id::TEXT,
        jsonb_build_object('type', 'invalidArguments', 'description', 'update failed'));
    END;
  END LOOP;

  v_new_state := entity_state(p_mailbox_id, 'CalendarEvent');

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'oldState', (v_new_state - 1)::TEXT,
    'newState', v_new_state::TEXT,
    'updated', v_updated,
    'notUpdated', v_notUpdated
  );
END;
$$ LANGUAGE plpgsql;
