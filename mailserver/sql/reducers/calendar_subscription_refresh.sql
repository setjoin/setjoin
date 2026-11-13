-- calendar_subscription_refresh.sql: sync ONE webcal/ICS subscription's
-- dedicated calendar against the feed's freshly-parsed events (WAVE-5 #10).
--
-- The calendarsync Go worker fetches the feed, parses it with
-- migration.SplitAndParseICS (the shared caldav parser — the pure split+parse,
-- same as calendar_import_ics), and hands the successfully-parsed events in as
-- a JSON array here.
--
-- DIFF-BY-UID (the whole point): a uid already present keeps its row's id and
-- gets its columns UPDATEd; a new uid gets INSERTed; a uid no longer in the
-- feed gets DELETEd. This is DELIBERATELY NOT calendar_import_ics's
-- delete-recreate 'overwrite' strategy — recreating every surviving event on
-- every ~15-minute tick would churn every event id (a JMAP state/sync-token
-- storm on the client for a calendar that hasn't actually changed).
--
-- ONE state bump per call (not one per event): notify_calendar_state runs
-- exactly once at the end when anything changed, unlike
-- jmap_calendar_event_set_create/update/destroy which the JMAP path calls once
-- per event (bumping once per event is right for a live user edit; wrong for a
-- background sync of a dozen unread events since the last tick).
--
-- OWNERSHIP: p_calendar_id must be the SAME calendar the subscription (looked
-- up by p_subscription_id) actually owns — checked BEFORE any write, mirroring
-- calendar_import_ics's up-front ownership check. This is defense-in-depth: the
-- calendarsync worker's own due-poll query already pairs (subscription_id,
-- calendar_id) correctly, but the reducer never trusts that pairing as given.
--
-- ponytail: a uid whose component failed to parse THIS cycle (partial-parse
-- feed) is simply absent from p_events, so it is deleted like any genuinely
-- removed event — it reappears on the next cycle if the transient parse error
-- clears. Accepted trade for a read-only mirrored calendar; the worker records
-- last_status='partial' + an N-of-M message so the UI shows the degraded sync,
-- but does not attempt to protect a partially-failed event from this diff.
--
-- Errors: BZ118 = p_events not an array, or p_calendar_id is not the
-- subscription's own calendar (notFound-shaped — no ownership oracle, same
-- posture as calendar_import_ics's BZ113 / sharing's BZ114).
CREATE OR REPLACE FUNCTION calendar_subscription_refresh(
  p_subscription_id BIGINT,
  p_calendar_id     BIGINT,
  p_events          JSONB
) RETURNS JSONB AS $$
DECLARE
  v_mailbox_id  BIGINT;
  v_elem        JSONB;
  v_uid         TEXT;
  v_existing_id BIGINT;
  v_seen_uids   TEXT[] := ARRAY[]::TEXT[];
  v_added       INT := 0;
  v_updated     INT := 0;
  v_deleted     INT := 0;
BEGIN
  IF jsonb_typeof(p_events) <> 'array' THEN
    RAISE EXCEPTION 'events must be a JSON array'
      USING ERRCODE = 'BZ118', HINT = '{"type":"invalidArguments"}';
  END IF;

  -- R3 ownership: p_calendar_id MUST be the calendar this subscription owns.
  -- Checked up front, before any row is written — a mismatched/foreign
  -- calendar id is rejected, never diffed against.
  SELECT c.mailbox_id INTO v_mailbox_id
    FROM calendars c
    JOIN calendar_subscriptions s ON s.calendar_id = c.id
   WHERE s.id = p_subscription_id AND c.id = p_calendar_id;

  IF v_mailbox_id IS NULL THEN
    RAISE EXCEPTION 'Subscription not found or calendar_id does not belong to it'
      USING ERRCODE = 'BZ118',
            HINT = jsonb_build_object(
              'type', 'notFound',
              'subscription_id', p_subscription_id,
              'calendar_id', p_calendar_id
            )::TEXT;
  END IF;

  FOR v_elem IN SELECT * FROM jsonb_array_elements(p_events)
  LOOP
    v_uid := NULLIF(v_elem->>'uid', '');
    IF v_uid IS NULL THEN
      CONTINUE; -- an unnamed component cannot be diffed by uid; skip it
    END IF;
    v_seen_uids := v_seen_uids || v_uid;

    SELECT id INTO v_existing_id
      FROM calendar_events WHERE calendar_id = p_calendar_id AND uid = v_uid;

    IF v_existing_id IS NOT NULL THEN
      UPDATE calendar_events SET
        title       = COALESCE(NULLIF(v_elem->>'title', ''), title),
        description = v_elem->>'description',
        location    = v_elem->>'location',
        all_day     = COALESCE((v_elem->>'isAllDay')::boolean, all_day),
        timezone    = v_elem->>'timeZone',
        rrule       = v_elem->>'recurrenceRule',
        start_at    = COALESCE((v_elem->>'start')::timestamptz, start_at),
        end_at      = COALESCE((v_elem->>'end')::timestamptz, end_at),
        status      = COALESCE(NULLIF(lower(v_elem->>'status'), ''), status),
        updated_at  = now()
      WHERE id = v_existing_id;
      v_updated := v_updated + 1;
    ELSE
      INSERT INTO calendar_events (
        calendar_id, uid, title, description, location, all_day, timezone,
        rrule, start_at, end_at, status
      ) VALUES (
        p_calendar_id, v_uid,
        COALESCE(NULLIF(v_elem->>'title', ''), '(untitled)'),
        v_elem->>'description', v_elem->>'location',
        COALESCE((v_elem->>'isAllDay')::boolean, FALSE),
        v_elem->>'timeZone', v_elem->>'recurrenceRule',
        (v_elem->>'start')::timestamptz, (v_elem->>'end')::timestamptz,
        COALESCE(NULLIF(lower(v_elem->>'status'), ''), 'confirmed')
      );
      v_added := v_added + 1;
    END IF;
  END LOOP;

  -- Delete-absent: any uid this calendar still has that the feed no longer
  -- carries. One statement — ids of every uid still present are untouched (no
  -- delete-recreate churn); an empty p_events legitimately deletes everything
  -- (the feed really is now empty).
  WITH gone AS (
    DELETE FROM calendar_events
     WHERE calendar_id = p_calendar_id
       AND NOT (uid = ANY(v_seen_uids))
     RETURNING id
  )
  SELECT count(*) INTO v_deleted FROM gone;

  IF v_added > 0 OR v_updated > 0 OR v_deleted > 0 THEN
    PERFORM notify_calendar_state(v_mailbox_id, NULL, p_calendar_id, 'events_synced');
    -- A4/F4 coarse-path sentinel: a background feed sync diffs many rows in one tick
    -- against a single state bump. The per-row triggers journal precise deltas, but
    -- this one in-window resync sentinel wins in jmap_entity_changes → BZ011,
    -- degrading a client spanning the sync to a full CalendarEvent resync (the safe
    -- behaviour for a coarse mirror-refresh). Runs on the calendarsync workerPool
    -- (BYPASSRLS), so the write to v_mailbox_id succeeds without an app.current_mailbox_id GUC.
    PERFORM journal_resync(v_mailbox_id, 'CalendarEvent');
  END IF;

  RETURN jsonb_build_object(
    'calendarId', p_calendar_id::TEXT,
    'added',   v_added,
    'updated', v_updated,
    'deleted', v_deleted
  );
END;
$$ LANGUAGE plpgsql;
