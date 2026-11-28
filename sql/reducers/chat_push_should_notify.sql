-- chat_push_should_notify.sql: Chat A3.5 mobile-push rider, Task 2 — the
-- chat sibling of push_should_notify.sql (mail). Pure read (no state bump),
-- called by the pushjobs worker's chat drain leg ONCE PER MEMBER at drain
-- time — never at enqueue time and never by filtering the WS relay (the A3
-- Global Constraint: notify_chat_state/forwardRawEvents stay verbatim).
--
-- chat_mentions, user_notification_prefs, mailboxes, calendars — no reducer
-- function calls, so no topo-sort dependency)
--
-- Decision order (first FALSE wins), mirroring push_should_notify.sql's
-- structure:
--   1. sender never pushes to self (chat_messages.author_id — NOT
--      p_user_id's own row; the worker ALSO excludes the sender via the
--      intent's sender_user_id at member-load — a deliberate cheap belt,
--      noted in both places).
--   2. In-meeting suppression (A/B leftover item 4, TODOS.md "UX #20"): the
--      recipient is PRESENTLY a participant (joined_at set, left_at NULL)
--      of a LIVE meeting bridged to this channel (meetings.chat_channel_id)
--      → FALSE. Scoped to the recipient's OWN live participation, never
--      "a meeting exists for this channel" — a channel member who never
--      joined the huddle, already left, or whose meeting has ended still
--      gets pushed normally (mind chat_channel_provisioned: a meeting can
--      bridge a PRE-EXISTING channel, where channel membership never
--      implies meeting participation — this checks meeting_participants,
--      never bare chat_channel_members).
--   3. Member's chat_channel_members.notif_level: 'none' → FALSE;
--      'mentions' → FALSE unless the message qualifies (mentioned in
--      chat_mentions, OR the message is broadcast, OR the channel kind
--      != 'channel' — DMs/group-DMs always qualify).
--   4. Global user_notification_prefs.chat_notifications: 'off' → FALSE;
--      'mentions' → the SAME qualifier as #3 ('all' passes).
--   5. user_notification_prefs.push_enabled FALSE → FALSE.
--   6. DND window → FALSE while inside it — copied verbatim from
--      push_should_notify.sql's tz/overnight-wrap/day-mask logic, adapted
--      on ONE point: the timezone lookup is keyed off the caller's PRIMARY
--      mailbox (mailboxes.user_id = p_user_id AND is_primary), not a bare
--      user_id join — a user can own additional shared mailboxes, and a
--      bare join could read the wrong calendar's tz. NULL degrades to
--      'UTC' through the same COALESCE.
--   7. Soft-deleted message (deleted_at IS NOT NULL) → FALSE — the message
--      was deleted between enqueue and drain.
--
-- Reads the GLOBAL prefs row (device_fingerprint IS NULL), like mail.
CREATE OR REPLACE FUNCTION chat_push_should_notify(
  p_user_id    BIGINT,
  p_channel_id BIGINT,
  p_message_id BIGINT
) RETURNS BOOLEAN AS $$
DECLARE
  v_author_id    BIGINT;
  v_broadcast    TEXT;
  v_deleted      TIMESTAMPTZ;
  v_channel_kind TEXT;
  v_notif_level  TEXT;
  v_chat_notif   TEXT;
  v_push_on      BOOLEAN;
  v_dnd_start    TIME;
  v_dnd_end      TIME;
  v_dnd_days     SMALLINT;
  v_qualifies    BOOLEAN;
  v_mailbox_id   BIGINT;
  v_tz           TEXT;
  v_local        TIMESTAMP;
  v_time         TIME;
  v_dow          INT;
  v_in_dnd       BOOLEAN;
BEGIN
  SELECT author_id, broadcast, deleted_at INTO v_author_id, v_broadcast, v_deleted
    FROM chat_messages WHERE id = p_message_id AND channel_id = p_channel_id;
  IF NOT FOUND THEN
    RETURN FALSE;
  END IF;

  -- 1. Sender never pushes to self.
  IF v_author_id = p_user_id THEN
    RETURN FALSE;
  END IF;

  -- 2. In-meeting suppression: a LIVE meeting bridged to this channel with
  -- the recipient PRESENTLY a participant means an OS push here would just
  -- storm someone already looking at the screen.
  IF EXISTS (
    SELECT 1 FROM meetings mt
      JOIN meeting_participants mp ON mp.meeting_id = mt.id
     WHERE mt.chat_channel_id = p_channel_id
       AND mt.state = 'live'
       AND mp.user_id = p_user_id
       AND mp.left_at IS NULL
  ) THEN
    RETURN FALSE;
  END IF;

  SELECT notif_level INTO v_notif_level
    FROM chat_channel_members WHERE channel_id = p_channel_id AND user_id = p_user_id;
  IF v_notif_level IS NULL THEN
    -- not a (current) member — e.g. left the channel between enqueue and drain.
    RETURN FALSE;
  END IF;

  SELECT kind INTO v_channel_kind FROM chat_channels WHERE id = p_channel_id;

  -- The shared "qualifier" both the per-channel and the global 'mentions'
  -- tier use: a personal @mention, an @channel/@all broadcast, or any
  -- non-'channel' kind (dm/group_dm — every message there is 1:1/small-group
  -- relevant, so 'mentions' degrades to 'all' in practice).
  v_qualifies := EXISTS (SELECT 1 FROM chat_mentions
                          WHERE message_id = p_message_id AND mentioned_user_id = p_user_id)
              OR v_broadcast IS NOT NULL
              OR v_channel_kind <> 'channel';

  -- 3. Per-channel notif_level.
  IF v_notif_level = 'none' THEN
    RETURN FALSE;
  ELSIF v_notif_level = 'mentions' AND NOT v_qualifies THEN
    RETURN FALSE;
  END IF;

  SELECT push_enabled, chat_notifications, dnd_start, dnd_end, dnd_days
    INTO v_push_on, v_chat_notif, v_dnd_start, v_dnd_end, v_dnd_days
    FROM user_notification_prefs
   WHERE user_id = p_user_id AND device_fingerprint IS NULL;

  IF NOT FOUND THEN
    v_push_on := TRUE; v_chat_notif := 'all'; v_dnd_days := 127;
  END IF;

  -- 4. Global chat_notifications tier.
  IF v_chat_notif = 'off' THEN
    RETURN FALSE;
  ELSIF v_chat_notif = 'mentions' AND NOT v_qualifies THEN
    RETURN FALSE;
  END IF;

  -- 5. push_enabled.
  IF NOT COALESCE(v_push_on, TRUE) THEN
    RETURN FALSE;
  END IF;

  -- 6. DND window (timezone-aware, copied verbatim from push_should_notify.sql
  -- except the tz lookup is keyed off the caller's PRIMARY mailbox).
  IF v_dnd_start IS NOT NULL AND v_dnd_end IS NOT NULL THEN
    SELECT id INTO v_mailbox_id FROM mailboxes WHERE user_id = p_user_id AND is_primary LIMIT 1;
    v_tz := COALESCE((SELECT timezone FROM calendars
                      WHERE mailbox_id = v_mailbox_id AND is_default
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

  -- 7. Soft-deleted message.
  IF v_deleted IS NOT NULL THEN
    RETURN FALSE;
  END IF;

  RETURN TRUE;
END;
$$ LANGUAGE plpgsql;
