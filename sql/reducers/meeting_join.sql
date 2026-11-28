-- meeting_join.sql: Meet B1 Task 4 — the member join reducer (the grant-spec
-- composer). Org-open for ordinary members (gate-ratified, user 2026-07-12):
-- authenticated guest accounts are the G3 exception and require current
-- channel membership, ownership, or an admitted authenticated knock. The
-- reducer COMPOSES the
-- LiveKit grant spec; Go only translates it into a JWT (R2 spirit — grant
-- content never derives from request input).
--
--
-- BZ block (meet = BZ185-190, this file's slice): BZ185 meeting not found;
-- BZ186 caller is banned (kicked, awaiting host re-admit); BZ187 meeting
-- locked and caller has no existing participant row; BZ190 meeting ended.
CREATE OR REPLACE FUNCTION meeting_join(
    p_user_id bigint, p_meeting_id bigint
) RETURNS jsonb AS $$
DECLARE
    v_meeting  RECORD;
    v_identity text := 'u:' || p_user_id;
    v_role     text;
    v_name     text;
    v_ttl      int;
    v_redirect_room uuid;
    v_external boolean := is_guest_account(p_user_id);
    v_channel_change_seq bigint;
    v_guest_can_post boolean;
    v_guest_history_from_join boolean;
BEGIN
    -- Guest G3: members keep the gate-ratified org-open posture; authenticated
    -- guest accounts must be active, entitled, and scoped by current channel
    -- membership, ownership, or a host-admitted authenticated knock.
    IF v_external THEN
        -- Token mint must serialize with guest_set_status. After this reducer
        -- commits Go may still be signing the JWT while disable runs; the
        -- retained participant row lets G5 snapshot every possible room and
        -- retry eviction through the token horizon.
        PERFORM guest_require_grantable(p_user_id);
        PERFORM guest_require_meet_ready(p_user_id);
        IF NOT check_user_app_entitlement(p_user_id, 'meet') THEN
            RAISE EXCEPTION 'not available to guest accounts'
                USING ERRCODE='BZ215', HINT='{"type":"forbidden","detail":"not available to guest accounts"}';
        END IF;
    END IF;

    SELECT id, room_name, state, locked, scheduled_end, chat_channel_id, owner_user_id,
           chat_channel_provisioned
      INTO v_meeting
      FROM meetings WHERE id = p_meeting_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'meeting % not found', p_meeting_id
            USING ERRCODE='BZ185', HINT='{"type":"notFound"}';
    END IF;
    IF v_meeting.state = 'ended' THEN
        RAISE EXCEPTION 'meeting % has ended', p_meeting_id
            USING ERRCODE='BZ190', HINT='{"type":"conflict","detail":"meeting has ended"}';
    END IF;

    IF v_external AND NOT meeting_guest_join_allowed(p_user_id, p_meeting_id) THEN
        RAISE EXCEPTION 'not available to guest accounts'
            USING ERRCODE='BZ215', HINT='{"type":"forbidden","detail":"not available to guest accounts"}';
    END IF;

    -- Ban check BEFORE the lock check (gate-ratified): a banned member must
    -- not even knock-bypass a locked meeting via a stale existing row.
    IF EXISTS (
      SELECT 1 FROM meeting_participants
       WHERE meeting_id = p_meeting_id AND identity = v_identity AND banned_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'participant % is banned from meeting %', v_identity, p_meeting_id
            USING ERRCODE='BZ186', HINT='{"type":"forbidden","detail":"kicked; awaiting host re-admit"}';
    END IF;

    IF v_meeting.locked AND NOT EXISTS (
      SELECT 1 FROM meeting_participants WHERE meeting_id = p_meeting_id AND identity = v_identity
    ) THEN
        RAISE EXCEPTION 'meeting % is locked', p_meeting_id
            USING ERRCODE='BZ187', HINT='{"type":"forbidden","detail":"meeting is locked; knock instead"}';
    END IF;

    -- Org-open upsert: role assigned once on first join (owner -> host, else
    -- member); a rejoin only clears left_at, never touching an established
    -- role (a demoted/promoted member's role survives a leave/rejoin cycle).
    -- joined_at is deliberately left untouched here — it is webhook-fed
    -- attendance (meeting_participant_event), not a reducer-stamped field.
    INSERT INTO meeting_participants (meeting_id, user_id, identity, role)
      VALUES (p_meeting_id, p_user_id, v_identity,
              CASE WHEN v_meeting.owner_user_id = p_user_id THEN 'host' ELSE 'member' END)
      ON CONFLICT (meeting_id, identity) DO UPDATE SET left_at = NULL
      RETURNING role INTO v_role;

    -- Huddle Slack semantics (V131, pipeline review fix): only auto-add to a
    -- MEETING-PROVISIONED channel. A huddle bound to a pre-existing channel/
    -- DM leaves a non-member joiner OUT of the channel — they get the
    -- meeting, never the channel's history (an already-member joiner is
    -- untouched either way, ON CONFLICT DO NOTHING). Audit-chain coverage:
    -- an actual insert on the provisioned path is a member.join act, the
    -- exact shape chat_channel_join's self-join act uses.
    IF v_meeting.chat_channel_id IS NOT NULL AND v_meeting.chat_channel_provisioned THEN
        SELECT change_seq INTO v_channel_change_seq
          FROM chat_channels WHERE id = v_meeting.chat_channel_id FOR UPDATE;
        IF v_external THEN
            -- A guest rejoining through an admitted knock may have had the
            -- provisioned membership removed. Re-grant it with the SAME live
            -- policy snapshot/history boundary as every other guest add;
            -- NULL defaults would both disable chat and expose old history.
            PERFORM guest_require_grantable(p_user_id);
            SELECT s.can_post, s.history_from_join
              INTO v_guest_can_post, v_guest_history_from_join
              FROM guest_chat_policy_snapshot(p_user_id) s;
        END IF;
        INSERT INTO chat_channel_members
            (channel_id, user_id, can_post, history_floor_seq)
          VALUES (
            v_meeting.chat_channel_id, p_user_id,
            CASE WHEN v_external THEN v_guest_can_post ELSE NULL END,
            CASE WHEN v_external AND v_guest_history_from_join
                 THEN v_channel_change_seq ELSE NULL END
          )
          ON CONFLICT DO NOTHING;
        IF FOUND AND COALESCE((SELECT enabled FROM feature_toggles
                                WHERE key = 'feature.chat_compliance'), FALSE) THEN
            PERFORM chat_access_audit(p_user_id, v_meeting.chat_channel_id, 'member.join',
              'member', p_user_id, NULL, jsonb_build_object('userId', p_user_id, 'role', 'member'), NULL, NULL);
        END IF;
    END IF;

    SELECT display_name INTO v_name FROM users WHERE id = p_user_id;

    v_ttl := LEAST(14400, extract(epoch from (
        COALESCE(v_meeting.scheduled_end, now() + interval '4 hours')
        + interval '1 hour' - now()))::int);
    IF v_ttl < 900 THEN
        v_ttl := 900;
    END IF;

    -- D10 (B3): assigned to an OPEN breakout ⇒ the grant names the CHILD
    -- room — a member cannot mint a main-room token around an assignment.
    -- Return-to-main is the host's act (assign NULL) or close-all, never a
    -- rejoin side effect. Envelope shape otherwise unchanged.
    SELECT b.room_name INTO v_redirect_room
      FROM meeting_participants p JOIN meeting_breakouts b ON b.id = p.breakout_id
     WHERE p.meeting_id = p_meeting_id AND p.identity = v_identity AND b.state = 'open';
    v_ttl := identity_media_mint_fence(
        p_user_id,
        COALESCE(v_redirect_room,v_meeting.room_name)::text,
        v_identity,
        v_ttl
    );

    RETURN jsonb_build_object(
        'room', COALESCE(v_redirect_room, v_meeting.room_name),
        'identity', v_identity,
        'name', COALESCE(v_name, 'User'),
        'role', v_role,
        'canPublish', true,
        'canSubscribe', true,
        'canPublishData', true,
        'roomAdmin', v_role IN ('host', 'cohost'),
        'hidden', false,
        -- Guest G3: Go translates this reducer-authored fact into a signed
        -- LiveKit participant attribute; identity prefixes are not authority.
        'external', v_external,
        'ttlSeconds', v_ttl,
        -- D5 "rides EVERY admission envelope" — member join included (E-F3):
        -- Task 10's RecordingBanner seeds off this key, never local state.
        -- A breakout is never recorded (DN4): redirected into a child room,
        -- the flag is hard false regardless of the parent's live recording.
        'recordingActive', CASE WHEN v_redirect_room IS NOT NULL THEN false
                                 ELSE meeting_recording_active(p_meeting_id) END
    );
END;
$$ LANGUAGE plpgsql;
