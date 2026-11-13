-- notify_calendar_state.sql: the single owner of "a calendar event changed →
-- bump the owning calendar's jmap_state → push on calendar:{owner_mailbox_id}".
-- The calendar secondary seam (mirrors bump_reminder_state / notify_state_change):
-- static SQL, one bump + one channel + one payload. Every calendar reducer that
-- mutates an event routes its bump+push here instead of open-coding
-- UPDATE calendars SET jmap_state + pg_notify('calendar:'||…).
--
-- Contract:
--   * Bumps calendars.jmap_state for p_calendar_id (the event's calendar),
--     scoped to p_owner_mailbox_id so a foreign calendar id bumps nothing.
--   * Pushes on the canonical 'calendar:{owner_mailbox_id}' channel — the channel
--     the WS consumer subscribes to (ws/handler.go) — with {event,event_id,
--     calendar_id}. classifyBatch keys on the 'event'/'event_id'/'calendar_id'
--     substrings, so the payload shape is preserved exactly.
--   * Returns the new calendars.jmap_state.
--
-- p_owner_mailbox_id — the CALENDAR-OWNER mailbox id (NOT necessarily the caller).
--   On the JMAP path this is p_mailbox_id; on the iMIP SMTP path p_mailbox_id is
--   NULL, so the caller passes the resolved owner (v_event.cal_mailbox_id /
--   v_master.cal_mailbox_id). Do NOT hardcode p_mailbox_id at the call sites.
-- p_event_id    — the changed event id (carried in the payload). NULL for a
--   calendar-OBJECT bump (the calendar's own metadata/sharing changed, no event:
--   jmap_calendar_set_update 'calendar_updated', jmap_calendar_share_set
--   'calendar_shared'); the payload then carries event_id:null and the
--   channel/key are unchanged. jsonb_build_object handles the NULL cleanly.
-- p_calendar_id — the event's calendar id (the bump target).
-- p_event       — the event name ('event_created' | 'event_destroyed' |
--   'event_updated' | 'calendar_updated' | 'calendar_shared' | …), preserved
--   verbatim in the payload.
CREATE OR REPLACE FUNCTION notify_calendar_state(
  p_owner_mailbox_id BIGINT,
  p_event_id         BIGINT,
  p_calendar_id      BIGINT,
  p_event            TEXT
) RETURNS BIGINT AS $$
DECLARE
  v_state BIGINT;
BEGIN
  IF p_owner_mailbox_id IS NULL THEN
    RAISE EXCEPTION 'notify_calendar_state requires an owner mailbox'
      USING ERRCODE = 'BZ034',
            HINT = jsonb_build_object('type', 'missing_mailbox')::TEXT;
  END IF;

  UPDATE calendars SET jmap_state = jmap_state + 1, updated_at = now()
  WHERE id = p_calendar_id AND mailbox_id = p_owner_mailbox_id
  RETURNING jmap_state INTO v_state;

  PERFORM app_notify(
    'calendar:' || p_owner_mailbox_id,
    jsonb_build_object(
      'event',       p_event,
      'event_id',    p_event_id,
      'calendar_id', p_calendar_id
    )::TEXT
  );

  RETURN v_state;
END;
$$ LANGUAGE plpgsql;
