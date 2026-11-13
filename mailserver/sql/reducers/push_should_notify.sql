-- push_should_notify.sql (QoL #9, H3): the notification-policy gate the pushjobs
-- worker consults before dispatching a mail push. Pure read (no state bump).
--
-- Decision order (first FALSE wins):
--   1. message/mailbox/user must resolve            → else FALSE
--   2. user_notification_prefs.push_enabled = FALSE → FALSE
--   3. the thread is Muted (Muted tag)              → FALSE
--   4. mail_notifications = 'off'                    → FALSE
--   5. mail_notifications = 'important' AND sender not VIP → FALSE
--                          (VIP sender notifies even in 'important')
--   6. inside the DND window (timezone-aware)        → FALSE
--   7. otherwise                                     → TRUE
--
-- vip_senders is V106 (QoL #10a, sibling unit) — referenced, not created. The
-- worker runs BYPASSRLS so the vip_senders FORCE-RLS policy does not hide rows.
CREATE OR REPLACE FUNCTION push_should_notify(
  p_mailbox_id  BIGINT,
  p_message_id  BIGINT,
  p_received_at TIMESTAMPTZ
) RETURNS BOOLEAN AS $$
DECLARE
  v_from        TEXT;
  v_thread      TEXT;
  v_user_id     BIGINT;
  v_push_on     BOOLEAN;
  v_mail_notif  TEXT;
  v_dnd_start   TIME;
  v_dnd_end     TIME;
  v_dnd_days    SMALLINT;
  v_is_vip      BOOLEAN;
  v_tz          TEXT;
  v_local       TIMESTAMP;
  v_time        TIME;
  v_dow         INT;
  v_in_dnd      BOOLEAN;
BEGIN
  -- 1. Resolve the delivered message (partition key is (id, received_at)).
  SELECT from_addr, thread_id INTO v_from, v_thread
  FROM messages
  WHERE id = p_message_id AND received_at = p_received_at AND mailbox_id = p_mailbox_id;
  IF NOT FOUND THEN
    RETURN FALSE;
  END IF;

  SELECT user_id INTO v_user_id FROM mailboxes WHERE id = p_mailbox_id;
  IF v_user_id IS NULL THEN
    RETURN FALSE;
  END IF;

  -- 2. Notification prefs. Prefer the account-level row (device_fingerprint NULL);
  -- absent entirely ⇒ column defaults (push on, 'all', no DND).
  SELECT push_enabled, mail_notifications, dnd_start, dnd_end, dnd_days
    INTO v_push_on, v_mail_notif, v_dnd_start, v_dnd_end, v_dnd_days
  FROM user_notification_prefs
  WHERE user_id = v_user_id
  ORDER BY (device_fingerprint IS NULL) DESC, id
  LIMIT 1;

  IF NOT FOUND THEN
    v_push_on := TRUE; v_mail_notif := 'all'; v_dnd_days := 127;
  END IF;

  IF NOT COALESCE(v_push_on, TRUE) THEN
    RETURN FALSE;
  END IF;

  -- 3. Muted thread (Gmail "Mute") — the Muted tag on any message in the thread.
  IF v_thread IS NOT NULL AND EXISTS (
        SELECT 1 FROM message_tags mt
        JOIN tags t ON t.id = mt.tag_id
        JOIN messages m ON m.id = mt.message_id AND m.received_at = mt.received_at
        WHERE m.thread_id = v_thread AND m.mailbox_id = p_mailbox_id AND t.name = 'Muted'
     ) THEN
    RETURN FALSE;
  END IF;

  -- 4/5. mail_notifications tier + VIP.
  v_is_vip := EXISTS (
    SELECT 1 FROM vip_senders
    WHERE user_id = v_user_id AND sender_email = lower(v_from)
  );

  IF v_mail_notif = 'off' THEN
    RETURN FALSE;
  ELSIF v_mail_notif = 'important' AND NOT v_is_vip THEN
    RETURN FALSE;
  END IF;

  -- 6. DND window (timezone-aware). The user's timezone is their default calendar's
  -- (user_notification_prefs carries no tz column); fall back to UTC. A wrap window
  -- (start > end) spans midnight. dnd_days is a 7-bit mask, bit N = DOW N (0=Sun).
  IF v_dnd_start IS NOT NULL AND v_dnd_end IS NOT NULL THEN
    v_tz := COALESCE((SELECT timezone FROM calendars
                      WHERE mailbox_id = p_mailbox_id AND is_default
                      ORDER BY id LIMIT 1), 'UTC');
    v_local := now() AT TIME ZONE v_tz;
    v_time  := v_local::time;
    v_dow   := EXTRACT(DOW FROM v_local)::int;

    IF (COALESCE(v_dnd_days, 127) >> v_dow) & 1 = 1 THEN
      IF v_dnd_start <= v_dnd_end THEN
        v_in_dnd := v_time >= v_dnd_start AND v_time < v_dnd_end;
      ELSE
        -- overnight window, e.g. 22:00 → 07:00
        v_in_dnd := v_time >= v_dnd_start OR v_time < v_dnd_end;
      END IF;
      IF v_in_dnd THEN
        RETURN FALSE;
      END IF;
    END IF;
  END IF;

  RETURN TRUE;
END;
$$ LANGUAGE plpgsql;
