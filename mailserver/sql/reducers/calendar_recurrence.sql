-- calendar_recurrence.sql — occurrence/following/series edit of a recurring event.

-- jmap_calendar_event_set_occurrence: edit OR delete one occurrence, this-and-following,
-- or the whole series of a recurring (master) event, using the existing exception model
-- (recurrence_override + exdate on the master). Atomic; bumps the calendar jmap_state
-- and pushes on calendar:{mailbox_id}.
--
--   p_scope = 'this'      → upsert (ON CONFLICT against the pre-existing
--                           calendar_events_calendar_id_uid_recurrence_key unique
--                           constraint) an override event for p_recurrence_id, append
--                           the occurrence to the master exdate. Master unchanged
--                           otherwise. p_patch = {"excluded":true} deletes the
--                           occurrence instead: exdate still gains the slot, but no
--                           override row is created/kept.
--   p_scope = 'following' → UNTIL-split the master at (p_recurrence_id - 1s) and create a
--                           new master starting at p_recurrence_id carrying the patch.
--                           {"excluded":true} truncates the master's rrule the same way
--                           but creates no tail master, and drops any detached
--                           occurrences/exdates at or after the cut (they no longer
--                           belong to any recurrence).
--   p_scope = 'series'    → patch the master row in place. {"excluded":true} destroys
--                           the whole series (master + all override siblings) — the
--                           same orphan-free cleanup jmap_calendar_event_set_destroy
--                           performs for a direct destroy of a recurring master.
--
-- Ownership (R1/R3): the master must belong to p_mailbox_id (= the calendar's mailbox_id);
-- otherwise BZ001. Every statement filters by the master id resolved under that join.
CREATE OR REPLACE FUNCTION jmap_calendar_event_set_occurrence(
  p_mailbox_id     BIGINT,
  p_master_id      BIGINT,
  p_recurrence_id  TIMESTAMPTZ,
  p_scope          TEXT,
  p_patch          JSONB DEFAULT '{}'::JSONB
) RETURNS JSONB AS $$
DECLARE
  v_master      RECORD;
  v_calendar_id BIGINT;
  v_new_id      BIGINT;
  v_new_rrule   TEXT;
  v_new_state   BIGINT;
  v_excluded    BOOLEAN;
  v_event_name  TEXT := 'event_updated';
  v_new_uid     TEXT;
  v_attendees   JSONB;
  v_invite_payload JSONB;
BEGIN
  IF p_scope NOT IN ('this', 'following', 'series') THEN
    RETURN jsonb_build_object('type', 'invalidArguments',
      'description', 'scope must be this, following, or series');
  END IF;

  -- Ownership: master must belong to this account's calendar.
  SELECT ce.*, c.mailbox_id AS cal_mailbox_id INTO v_master
  FROM calendar_events ce
  JOIN calendars c ON c.id = ce.calendar_id
  WHERE ce.id = p_master_id
    AND c.mailbox_id = p_mailbox_id
    AND ce.recurrence_override IS NULL;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Recurring master event not found in this account'
      USING ERRCODE = 'BZ001',
            HINT = '{"type":"forbidden","master_id":"' || p_master_id || '"}';
  END IF;

  v_calendar_id := v_master.calendar_id;
  v_excluded := COALESCE((p_patch->>'excluded')::BOOLEAN, FALSE);

  -- BZ123: reject a recurrence id that is not a real occurrence of this series —
  -- a typo or a timezone-shifted instant from the client would otherwise silently
  -- create/exclude a phantom slot. Valid when it's an RDATE, an EXDATE already
  -- recorded, an existing detached override, or a real expand_recurrence slot.
  -- BYSETPOS rules go through the wrapper (same call shape).
  IF NOT (
    p_recurrence_id = ANY(COALESCE(v_master.rdate,  ARRAY[]::TIMESTAMPTZ[]))
    OR p_recurrence_id = ANY(COALESCE(v_master.exdate, ARRAY[]::TIMESTAMPTZ[]))
    OR EXISTS (SELECT 1 FROM calendar_events WHERE calendar_id = v_calendar_id
               AND uid = v_master.uid AND recurrence_override = p_recurrence_id)
    OR (v_master.rrule IS NOT NULL AND CASE WHEN v_master.rrule LIKE '%BYSETPOS%' THEN
          EXISTS (SELECT 1 FROM expand_recurrence_bysetpos(v_master.start_at, v_master.end_at,
            v_master.rrule, p_recurrence_id, p_recurrence_id + INTERVAL '1 second')
            WHERE occ_start = p_recurrence_id)
        ELSE
          EXISTS (SELECT 1 FROM expand_recurrence(v_master.start_at, v_master.end_at,
            v_master.rrule, p_recurrence_id, p_recurrence_id + INTERVAL '1 second')
            WHERE occ_start = p_recurrence_id)
        END)
  ) THEN
    RAISE EXCEPTION 'recurrenceId % is not an occurrence of event %', p_recurrence_id, p_master_id
      USING ERRCODE = 'BZ123',
            HINT = '{"type":"invalidArguments"}';
  END IF;

  IF p_scope = 'this' THEN
    -- Edit AND delete both detach the slot: always append the occurrence to
    -- the master exdate (de-duplicated).
    UPDATE calendar_events
    SET exdate = (
          SELECT array_agg(DISTINCT d)
          FROM unnest(COALESCE(exdate, ARRAY[]::TIMESTAMPTZ[]) || ARRAY[p_recurrence_id]) AS d
        ),
        updated_at = now(),
        etag = generate_etag()
    WHERE id = p_master_id AND calendar_id = v_calendar_id;

    IF v_excluded THEN
      -- Delete: remove the override row too if this occurrence was already
      -- detached by a prior edit (re-delete of a detached occurrence).
      DELETE FROM calendar_events
      WHERE calendar_id = v_calendar_id AND uid = v_master.uid
        AND recurrence_override = p_recurrence_id;
      v_new_id := p_master_id;
      v_event_name := 'event_destroyed';
    ELSE
      -- Upsert the override event: a copy of the master at the occurrence instant,
      -- sharing the master uid, with recurrence_override set and the patch applied.
      -- ON CONFLICT targets the pre-existing
      -- calendar_events_calendar_id_uid_recurrence_key unique constraint — a repeat
      -- edit of the same occurrence updates the row instead of raising a
      -- unique_violation (the crash this used to be).
      INSERT INTO calendar_events (
        calendar_id, uid, component_type, title, description, location, url,
        start_at, end_at, all_day, timezone, status, transp,
        is_meeting, meeting_url, organizer_email, organizer_name,
        color, classification, valarm,
        recurrence_override, parent_event_uid, etag, jmap_state
      ) VALUES (
        v_calendar_id,
        v_master.uid,
        v_master.component_type,
        COALESCE(p_patch->>'title', v_master.title),
        COALESCE(p_patch->>'description', v_master.description),
        COALESCE(p_patch->>'location', v_master.location),
        v_master.url,
        COALESCE((p_patch->>'start')::TIMESTAMPTZ, p_recurrence_id),
        COALESCE((p_patch->>'end')::TIMESTAMPTZ,
                 p_recurrence_id + (v_master.end_at - v_master.start_at)),
        COALESCE((p_patch->>'isAllDay')::BOOL, v_master.all_day),
        COALESCE(p_patch->>'timeZone', v_master.timezone),
        COALESCE(p_patch->>'status', v_master.status),
        v_master.transp,
        v_master.is_meeting,
        v_master.meeting_url,
        v_master.organizer_email,
        v_master.organizer_name,
        COALESCE(p_patch->>'color', v_master.color),
        -- privacy patch-present guard, mirrors jmap_calendar_event_set_update.
        CASE WHEN p_patch ? 'privacy'
          THEN (CASE p_patch->>'privacy' WHEN 'private' THEN 'PRIVATE' WHEN 'secret' THEN 'CONFIDENTIAL' ELSE 'PUBLIC' END)
          ELSE v_master.classification END,
        -- valarm patch-present guard: an unrelated patch keeps the master's reminder.
        CASE WHEN p_patch ? 'valarm' THEN p_patch->'valarm' ELSE v_master.valarm END,
        p_recurrence_id,
        v_master.uid,
        generate_etag(),
        1
      )
      ON CONFLICT (calendar_id, uid, recurrence_override) DO UPDATE SET
        title          = EXCLUDED.title,
        description    = EXCLUDED.description,
        location       = EXCLUDED.location,
        start_at       = EXCLUDED.start_at,
        end_at         = EXCLUDED.end_at,
        all_day        = EXCLUDED.all_day,
        timezone       = EXCLUDED.timezone,
        status         = EXCLUDED.status,
        color          = EXCLUDED.color,
        classification = EXCLUDED.classification,
        valarm         = EXCLUDED.valarm,
        updated_at     = now(),
        etag           = generate_etag(),
        sequence       = calendar_events.sequence + 1
      RETURNING id INTO v_new_id;

      -- Copy attendees onto the override row (once — ON CONFLICT DO NOTHING
      -- against event_attendees_event_email_uniq means a second 'this' edit of
      -- the same occurrence does not clobber an attendee's RSVP already recorded
      -- against the override).
      INSERT INTO event_attendees (event_id, email, name, role, status, rsvp)
      SELECT v_new_id, ea.email, ea.name, ea.role, ea.status, ea.rsvp
      FROM event_attendees ea WHERE ea.event_id = p_master_id
      ON CONFLICT DO NOTHING;
    END IF;

  ELSIF p_scope = 'following' THEN
    -- UNTIL-split the master one second before the chosen occurrence. Strip any
    -- existing UNTIL/COUNT first — appending onto a master that was already split
    -- (or created with COUNT=) would otherwise yield an invalid RRULE carrying
    -- both COUNT and UNTIL.
    v_new_rrule := regexp_replace(v_master.rrule, ';?(UNTIL|COUNT)=[^;]*', '', 'g');
    v_new_rrule := trim(both ';' from v_new_rrule) || ';UNTIL=' ||
      to_char((p_recurrence_id - INTERVAL '1 second') AT TIME ZONE 'UTC', 'YYYYMMDD"T"HH24MISS"Z"');

    UPDATE calendar_events
    SET rrule = v_new_rrule,
        updated_at = now(),
        etag = generate_etag()
    WHERE id = p_master_id AND calendar_id = v_calendar_id;

    IF v_excluded THEN
      -- Delete-following: truncate the rrule (above) and drop everything at/after
      -- the cut — a detached occurrence or exdate past the cut no longer belongs
      -- to any recurrence, so there is nothing to re-parent onto (contrast the
      -- non-excluded split, which creates a tail master to carry them).
      DELETE FROM calendar_events
      WHERE calendar_id = v_calendar_id AND uid = v_master.uid
        AND recurrence_override >= p_recurrence_id;

      UPDATE calendar_events
      SET exdate = (SELECT array_agg(d) FROM unnest(exdate) d WHERE d < p_recurrence_id)
      WHERE id = p_master_id AND calendar_id = v_calendar_id;

      v_new_id := p_master_id;
      v_event_name := 'event_destroyed';
    ELSE
      -- New (tail) master from the split point with the original recurrence rule +
      -- patch. Strip any stale UNTIL/COUNT the OLD master's rrule already carried
      -- (e.g. a previous split) rather than copying it verbatim onto the tail —
      -- ponytail: COUNT-remainder recomputation is deliberately not attempted
      -- (Open Decision 9); the tail master runs unbounded (no COUNT/UNTIL) until a
      -- later edit sets one explicitly.
      v_new_uid := gen_random_uuid()::TEXT;

      INSERT INTO calendar_events (
        calendar_id, uid, component_type, title, description, location, url,
        start_at, end_at, all_day, timezone, status, transp,
        is_meeting, meeting_url, organizer_email, organizer_name,
        rrule, recurrence_override, etag, jmap_state
      ) VALUES (
        v_calendar_id,
        v_new_uid,
        v_master.component_type,
        COALESCE(p_patch->>'title', v_master.title),
        COALESCE(p_patch->>'description', v_master.description),
        COALESCE(p_patch->>'location', v_master.location),
        v_master.url,
        COALESCE((p_patch->>'start')::TIMESTAMPTZ, p_recurrence_id),
        COALESCE((p_patch->>'end')::TIMESTAMPTZ,
                 p_recurrence_id + (v_master.end_at - v_master.start_at)),
        COALESCE((p_patch->>'isAllDay')::BOOL, v_master.all_day),
        COALESCE(p_patch->>'timeZone', v_master.timezone),
        COALESCE(p_patch->>'status', v_master.status),
        v_master.transp,
        v_master.is_meeting,
        v_master.meeting_url,
        v_master.organizer_email,
        v_master.organizer_name,
        trim(both ';' from regexp_replace(v_master.rrule, ';?(UNTIL|COUNT)=[^;]*', '', 'g')),
        NULL,
        generate_etag(),
        1
      ) RETURNING id INTO v_new_id;

      -- Re-parent tail overrides (>= cut) onto the new master's series — they no
      -- longer belong to the old (now UNTIL-truncated) master's recurrence.
      UPDATE calendar_events
      SET uid = v_new_uid, parent_event_uid = v_new_uid, updated_at = now(), etag = generate_etag()
      WHERE calendar_id = v_calendar_id AND uid = v_master.uid
        AND recurrence_override >= p_recurrence_id;

      -- Move tail exdates: trim on the old master, install on the new.
      UPDATE calendar_events
      SET exdate = (SELECT array_agg(d) FROM unnest(exdate) d WHERE d < p_recurrence_id)
      WHERE id = p_master_id AND calendar_id = v_calendar_id;

      UPDATE calendar_events
      SET exdate = (SELECT array_agg(d) FROM unnest(COALESCE(v_master.exdate, ARRAY[]::TIMESTAMPTZ[])) d
                    WHERE d >= p_recurrence_id)
      WHERE id = v_new_id AND calendar_id = v_calendar_id;
    END IF;

  ELSE  -- 'series'
    IF v_excluded THEN
      -- Delete the whole series: master + every detached override sibling
      -- (the same orphan-free cleanup jmap_calendar_event_set_destroy performs).
      DELETE FROM calendar_events WHERE calendar_id = v_calendar_id AND uid = v_master.uid;
      v_new_id := p_master_id;
      v_event_name := 'event_destroyed';
    ELSE
      UPDATE calendar_events ce SET
        title       = COALESCE(p_patch->>'title', ce.title),
        description = COALESCE(p_patch->>'description', ce.description),
        location    = COALESCE(p_patch->>'location', ce.location),
        start_at    = COALESCE((p_patch->>'start')::TIMESTAMPTZ, ce.start_at),
        end_at      = COALESCE((p_patch->>'end')::TIMESTAMPTZ, ce.end_at),
        all_day     = COALESCE((p_patch->>'isAllDay')::BOOL, ce.all_day),
        timezone    = COALESCE(p_patch->>'timeZone', ce.timezone),
        status      = COALESCE(p_patch->>'status', ce.status),
        rrule       = COALESCE(p_patch->>'recurrenceRule', ce.rrule),
        updated_at  = now(),
        etag        = generate_etag()
      WHERE ce.id = p_master_id AND ce.calendar_id = v_calendar_id;
      v_new_id := p_master_id;
    END IF;
  END IF;

  -- Occurrence-scoped iTIP outbound (Task 9): scope='this' on a meeting with
  -- attendees enqueues a REQUEST (edit) or CANCEL (excluded:true) scoped to
  -- JUST this occurrence — reusing the send-update shape (calendar_send_invite)
  -- + queue (outbound_queue via the Go gateway's serializeAndEnqueueInvite), not
  -- a new table (queue-contract F1). Attendees come from the MASTER row: the
  -- excluded/delete branch already deleted the override row (event_attendees
  -- cascades with it), so reading v_new_id's attendees post-delete would find
  -- none — the series' attendee roster is the correct/only list to notify either way.
  IF p_scope = 'this' AND v_master.is_meeting THEN
    SELECT jsonb_agg(jsonb_build_object(
      'email', ea.email, 'name', ea.name, 'role', ea.role,
      'participationStatus', ea.status, 'expectReply', ea.rsvp
    )) INTO v_attendees
    FROM event_attendees ea
    WHERE ea.event_id = v_master.id AND ea.role != 'resource'
      AND ea.email != v_master.organizer_email;

    IF v_attendees IS NOT NULL AND jsonb_array_length(v_attendees) > 0 THEN
      v_invite_payload := jsonb_build_object(
        'eventId', v_new_id::TEXT,
        'uid', v_master.uid,
        'organizerEmail', v_master.organizer_email,
        'organizerName', v_master.organizer_name,
        'title', COALESCE(p_patch->>'title', v_master.title),
        'description', COALESCE(p_patch->>'description', v_master.description),
        'location', COALESCE(p_patch->>'location', v_master.location),
        'start', COALESCE((p_patch->>'start')::TIMESTAMPTZ, p_recurrence_id),
        'end', COALESCE((p_patch->>'end')::TIMESTAMPTZ,
                         p_recurrence_id + (v_master.end_at - v_master.start_at)),
        'allDay', v_master.all_day,
        'timezone', v_master.timezone,
        'status', v_master.status,
        'sequence', v_master.sequence,
        'rrule', NULL,
        'attendees', v_attendees,
        'recurrenceId', to_char(p_recurrence_id AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
        'method', CASE WHEN v_excluded THEN 'CANCEL' ELSE 'REQUEST' END
      );
    END IF;
  END IF;

  -- Bump calendars.jmap_state + push through the calendar seam (returns the new
  -- state). Owner mailbox is v_master.cal_mailbox_id (the calendar's mailbox); on
  -- the JMAP path it equals p_mailbox_id, but the owner local is always correct.
  -- The former bespoke 'scope' payload key is dropped: the WS consumer keys only
  -- on event/event_id/calendar_id (classifyBatch), so it carried no behavior.
  v_new_state := notify_calendar_state(v_master.cal_mailbox_id, v_new_id,
                                       v_calendar_id, v_event_name);

  RETURN jsonb_build_object(
    'ok', TRUE,
    'eventId', v_new_id::TEXT,
    'scope', p_scope,
    'newState', v_new_state::TEXT,
    'invitePayload', v_invite_payload
  );
END;
$$ LANGUAGE plpgsql;
