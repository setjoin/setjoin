-- meeting_create.sql: Meet B1 Task 3 — the meeting-create reducer +
-- spec §3.3's Meet↔Chat bridge (a meeting's chat IS a chat_channels row,
-- always bound: the origin channel for a huddle, a fresh private channel
-- otherwise).
--
--
-- BZ block (meet = BZ185-190, this file's slice): BZ186 host/cohost-or-
-- membership-required action — here, launching a huddle in a chat channel
-- the caller does not belong to; BZ188 invalid arguments (empty title,
-- end <= start, a calendar event the caller does not own).
--
-- R1-R3: the calendar-event ownership check reads AND the later stamping
-- UPDATE both filter by mailboxes.user_id = p_user_id in the same
-- statement — no TOCTOU window between "verified owned" and "mutated".
CREATE OR REPLACE FUNCTION meeting_create(
    p_user_id bigint, p_title text,
    p_scheduled_start timestamptz DEFAULT NULL,
    p_scheduled_end   timestamptz DEFAULT NULL,
    p_chat_channel_id bigint DEFAULT NULL,
    p_calendar_event_id bigint DEFAULT NULL,
    p_guest_allowed boolean DEFAULT false
) RETURNS jsonb AS $$
DECLARE
    v_title      text;
    v_meeting_id bigint;
    v_room_name  uuid;
    v_slug       text;
    v_channel_id bigint;
    v_member     record;
BEGIN
    -- Guest G3: meeting creation is a dedicated profile authority. A creator
    -- is necessarily host of the meeting; allow_meet_host separately governs
    -- promotion to cohost in somebody else's meeting.
    IF is_guest_account(p_user_id) THEN
        PERFORM guest_require_active(p_user_id);
        IF NOT check_user_app_entitlement(p_user_id, 'meet')
           OR NOT guest_profile_flag(p_user_id, 'allow_meet_create') THEN
            RAISE EXCEPTION 'not available to guest accounts'
                USING ERRCODE='BZ215', HINT='{"type":"forbidden","detail":"not available to guest accounts"}';
        END IF;
    END IF;

    v_title := btrim(COALESCE(p_title, ''));
    IF v_title = '' THEN
        RAISE EXCEPTION 'meeting title required'
            USING ERRCODE='BZ188', HINT='{"type":"invalidArguments","detail":"title required"}';
    END IF;
    IF p_scheduled_start IS NOT NULL AND p_scheduled_end IS NOT NULL
       AND p_scheduled_end <= p_scheduled_start THEN
        RAISE EXCEPTION 'scheduled_end must be after scheduled_start'
            USING ERRCODE='BZ188', HINT='{"type":"invalidArguments","detail":"end must be after start"}';
    END IF;
    -- calendar-event ownership: verified here (read) AND re-verified in the
    -- stamping UPDATE below (mutation) — R3, no TOCTOU between the two.
    IF p_calendar_event_id IS NOT NULL AND NOT EXISTS (
         SELECT 1 FROM calendar_events e
           JOIN calendars c ON c.id = e.calendar_id
           JOIN mailboxes m ON m.id = c.mailbox_id
          WHERE e.id = p_calendar_event_id AND m.user_id = p_user_id) THEN
        RAISE EXCEPTION 'calendar event not found or not owned by caller'
            USING ERRCODE='BZ188', HINT='{"type":"invalidArguments","detail":"calendar event not owned"}';
    END IF;
    -- huddle launch: caller must already belong to the channel being bound
    -- (BZ186) — a huddle is "start a call in a channel I'm in", not an
    -- invitation to bind a stranger's channel.
    IF p_chat_channel_id IS NOT NULL AND NOT EXISTS (
         SELECT 1 FROM chat_channel_members
          WHERE channel_id = p_chat_channel_id AND user_id = p_user_id) THEN
        RAISE EXCEPTION 'caller is not a member of the chat channel to launch a huddle in'
            USING ERRCODE='BZ186', HINT='{"type":"forbidden","detail":"caller must be a member of the chat channel"}';
    END IF;

    INSERT INTO meetings (title, owner_user_id, scheduled_start, scheduled_end, settings)
      VALUES (v_title, p_user_id, p_scheduled_start, p_scheduled_end,
              jsonb_build_object('guestAllowed', COALESCE(p_guest_allowed, false)))
      RETURNING id, room_name, slug INTO v_meeting_id, v_room_name, v_slug;

    -- §3.3 bridge: bind the origin channel for a huddle (and post the
    -- call-started system message into it, no-ring launch), else provision a
    -- fresh private channel. p_system=true: chat.channel_creation OFF must
    -- never break meeting_create (CEO deviation (d) REJECTED).
    IF p_chat_channel_id IS NOT NULL THEN
        v_channel_id := p_chat_channel_id;
        PERFORM chat_call_started(p_user_id, v_channel_id, v_meeting_id, v_slug, v_title);
    ELSE
        v_channel_id := chat_channel_create(p_user_id, v_title, NULL, 'private', true);
    END IF;
    -- Huddle Slack semantics (pipeline review fix, V131): a huddle bound to a
    -- PRE-EXISTING channel (p_chat_channel_id passed) must never auto-add a
    -- meeting joiner to that channel's history (meeting_join.sql/
    -- meeting_lobby.sql gate on this) — chat_channel_provisioned=false. The
    -- fresh channel this reducer just created for an ad-hoc meeting keeps
    -- today's auto-membership behavior — chat_channel_provisioned=true.
    UPDATE meetings SET chat_channel_id = v_channel_id,
           chat_channel_provisioned = (p_chat_channel_id IS NULL)
     WHERE id = v_meeting_id;

    -- Guest G1 digest intent: the enqueue helper filters non-guests and the
    -- feature toggle, keeping the meeting reducer's loop intentionally thin.
    FOR v_member IN
        SELECT user_id FROM chat_channel_members WHERE channel_id = v_channel_id
    LOOP
        PERFORM guest_notification_intent_enqueue(
            v_member.user_id, 'meeting_invite', v_meeting_id::text);
    END LOOP;

    -- the owner's own participant row: host, not yet joined (joined_at is
    -- webhook-fed attendance, stamped only on an actual LiveKit connection).
    INSERT INTO meeting_participants (meeting_id, user_id, identity, role, joined_at)
      VALUES (v_meeting_id, p_user_id, 'u:' || p_user_id, 'host', NULL);

    IF p_calendar_event_id IS NOT NULL THEN
        UPDATE calendar_events SET is_meeting = true,
               meeting_url = '/meet/join/' || v_slug
          WHERE id = p_calendar_event_id
            AND EXISTS (SELECT 1 FROM calendars c JOIN mailboxes m ON m.id = c.mailbox_id
                         WHERE c.id = calendar_events.calendar_id AND m.user_id = p_user_id);
    END IF;

    PERFORM notify_meet_state(v_meeting_id, 'meeting_created');
    RETURN jsonb_build_object('meetingId', v_meeting_id, 'slug', v_slug,
                              'roomName', v_room_name, 'chatChannelId', v_channel_id);
END;
$$ LANGUAGE plpgsql;
