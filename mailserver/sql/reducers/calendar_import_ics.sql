-- calendar_import_ics.sql: import a batch of already-parsed iCal events (the Go
-- gateway parses the uploaded .ics bytes with the caldav parser and hands the
-- events in as a JSON array) into ONE calendar the caller owns.
--
-- OWNERSHIP (the whole point of this reducer): the target calendar is verified to
-- belong to the caller BEFORE any insert, and EACH event is routed through the
-- existing jmap_calendar_event_set_create path — so RLS scope, the
-- jmap_calendar_state bump, and notify_calendar_state all come for free. This is
-- deliberately NOT a raw INSERT (the migration.insertCalendarEvent path bypasses
-- all three and takes a calendarId with no ownership check — an import endpoint
-- must never expose that).
--
-- Conflict strategy (per UID, within the target calendar):
--   * skip      — a UID that already exists is left untouched (counted skipped).
--   * overwrite — delete-then-recreate the existing UID (opt-in; destructive).
--   * rename    — suffix the incoming UID until unique (keeps both copies).
--
-- Errors: BZ113 = the target calendar is missing / not owned, or the request is
-- malformed (bad strategy / p_events not an array). Never a raw ownership bypass.
CREATE OR REPLACE FUNCTION calendar_import_ics(
  p_mailbox_id  BIGINT,
  p_actor_id    BIGINT,
  p_actor_email TEXT,
  p_calendar_id BIGINT,
  p_events      JSONB,
  p_strategy    TEXT DEFAULT 'skip'
) RETURNS JSONB AS $$
DECLARE
  v_strategy  TEXT := lower(COALESCE(p_strategy, 'skip'));
  v_elem      JSONB;
  v_uid       TEXT;
  v_creates   JSONB := '{}'::JSONB;
  v_idx       INT   := 0;
  v_skipped   INT   := 0;
  v_imported  INT   := 0;
  v_res       JSONB;
  v_errors    JSONB := '{}'::JSONB;
BEGIN
  IF v_strategy NOT IN ('skip', 'overwrite', 'rename') THEN
    RAISE EXCEPTION 'Invalid conflict strategy: %', p_strategy
      USING ERRCODE = 'BZ113', HINT = '{"type":"invalidArguments"}';
  END IF;

  -- R3 ownership: the target calendar MUST belong to the caller. Checked up front,
  -- before any row is written — a foreign calendar id is rejected, never inserted.
  IF NOT EXISTS (SELECT 1 FROM calendars WHERE id = p_calendar_id AND mailbox_id = p_mailbox_id) THEN
    RAISE EXCEPTION 'Calendar not found or not owned'
      USING ERRCODE = 'BZ113',
            HINT = jsonb_build_object('type','notFound','calendar_id',p_calendar_id)::TEXT;
  END IF;

  IF jsonb_typeof(p_events) <> 'array' THEN
    RAISE EXCEPTION 'events must be a JSON array'
      USING ERRCODE = 'BZ113', HINT = '{"type":"invalidArguments"}';
  END IF;

  FOR v_elem IN SELECT * FROM jsonb_array_elements(p_events)
  LOOP
    v_uid := COALESCE(NULLIF(v_elem->>'uid', ''), gen_random_uuid()::TEXT);

    IF EXISTS (SELECT 1 FROM calendar_events WHERE calendar_id = p_calendar_id AND uid = v_uid) THEN
      IF v_strategy = 'skip' THEN
        v_skipped := v_skipped + 1;
        CONTINUE;
      ELSIF v_strategy = 'overwrite' THEN
        -- Opt-in destructive replace. Scoped to the verified-owned calendar.
        DELETE FROM calendar_events WHERE calendar_id = p_calendar_id AND uid = v_uid;
      ELSE  -- rename: keep both — suffix until unique
        WHILE EXISTS (SELECT 1 FROM calendar_events WHERE calendar_id = p_calendar_id AND uid = v_uid) LOOP
          v_uid := v_uid || '-imported';
        END LOOP;
      END IF;
    END IF;

    -- Force the target calendar id + resolved uid onto the event object (never trust a
    -- client-supplied calendarId), then stage it for the set_create loop.
    v_creates := v_creates || jsonb_build_object(
      v_idx::TEXT,
      v_elem || jsonb_build_object('calendarId', p_calendar_id, 'uid', v_uid));
    v_idx := v_idx + 1;
  END LOOP;

  IF v_creates <> '{}'::JSONB THEN
    -- Route every staged event through the ownership+state+notify create path.
    v_res := jmap_calendar_event_set_create(p_mailbox_id, p_actor_id, p_actor_email, v_creates);
    v_imported := (SELECT count(*)::INT FROM jsonb_object_keys(COALESCE(v_res->'created', '{}'::JSONB)));
    v_errors   := COALESCE(v_res->'notCreated', '{}'::JSONB);

    -- A4/F4 coarse-path sentinel: a bulk import (esp. 'overwrite', which
    -- delete-recreates UIDs → old ids destroyed under new ids) is a coarse replace.
    -- The per-row triggers DO journal precise created/destroyed, but the one
    -- in-window resync sentinel wins in jmap_entity_changes (it checks for any
    -- resync row before collapse → BZ011), degrading a client spanning the import to
    -- a full CalendarEvent resync rather than streaming a churn of id changes. Same
    -- mailbox as the acting CallScoped GUC (p_mailbox_id = owner), so no BYPASS needed.
    PERFORM journal_resync(p_mailbox_id, 'CalendarEvent');
  END IF;

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'imported',  v_imported,
    'skipped',   v_skipped,
    'errors',    v_errors
  );
END;
$$ LANGUAGE plpgsql;
