-- Frozen Go's webcal unsubscribe transaction (`DELETE /calendar/subscriptions/{id}`):
-- locks mailbox -> calendar in canonical lock order before deleting the
-- calendar (which cascades through calendar_subscriptions and calendar_events).
-- Ownership (s.user_id = p_user) is re-checked in the DELETE statement (R3).
CREATE OR REPLACE FUNCTION rust_calendar_unsubscribe(
 p_mailbox bigint, p_user bigint, p_sub_id bigint
) RETURNS bigint LANGUAGE plpgsql VOLATILE AS $$
DECLARE
 v_cal_id bigint;
 v_cal_mailbox bigint;
 v_rows bigint := 0;
BEGIN
 IF COALESCE(p_mailbox, -1) < 0 THEN
  RETURN 0;
 END IF;
 SELECT c.id, c.mailbox_id INTO v_cal_id, v_cal_mailbox
  FROM calendar_subscriptions s
  JOIN calendars c ON c.id = s.calendar_id
  WHERE s.id = p_sub_id AND s.user_id = p_user;
 IF v_cal_id IS NULL THEN
  RETURN 0;
 END IF;
 PERFORM 1 FROM mailboxes WHERE id IN (p_mailbox, v_cal_mailbox) ORDER BY id FOR KEY SHARE;
 PERFORM 1 FROM calendars WHERE id = v_cal_id AND mailbox_id = v_cal_mailbox FOR UPDATE;
 IF NOT FOUND THEN
  RETURN 0;
 END IF;
 DELETE FROM calendars c
  USING calendar_subscriptions s
  WHERE c.id = v_cal_id
    AND c.mailbox_id = v_cal_mailbox
    AND s.calendar_id = c.id
    AND s.id = p_sub_id
    AND s.user_id = p_user;
 GET DIAGNOSTICS v_rows = ROW_COUNT;
 RETURN v_rows;
END;
$$;
