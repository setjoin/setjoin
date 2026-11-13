-- Frozen Go's webcal subscribe transaction (`user.CalendarSubscriptionsHandler.Subscribe`):
-- the mirrored `calendars` row, then its `calendar_subscriptions` row with
-- last_fetch_at = now() so the periodic sync tick does not claim it before the
-- caller's immediate first fetch. Ownership comes from the caller (auth
-- context), never from a request field. Follow-up: fold into a canonical
-- calendar reducer when the calendar family owns subscription writes.
CREATE OR REPLACE FUNCTION rust_calendar_subscribe(
 p_mailbox bigint, p_user bigint, p_name text, p_url text
) RETURNS TABLE (sub_id bigint, calendar_id bigint) LANGUAGE plpgsql VOLATILE AS $$
DECLARE
 v_calendar bigint;
 v_sub bigint;
BEGIN
 INSERT INTO calendars (mailbox_id, name, color)
  VALUES (p_mailbox, p_name, '#6366f1') RETURNING id INTO v_calendar;
 INSERT INTO calendar_subscriptions (user_id, calendar_id, url, last_fetch_at, last_status)
  VALUES (p_user, v_calendar, p_url, now(), 'pending') RETURNING id INTO v_sub;
 RETURN QUERY SELECT v_sub, v_calendar;
END;
$$;
