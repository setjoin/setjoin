-- meeting_breakout.sql: Meet B3 — reducer-owned breakout rooms (spec §4.1).
-- The SFU has NO breakout/move concept (D1 — MoveParticipant is Cloud-only,
-- re-verified live by TestLiveSFUSmoke's F14 arm): assignment
-- (meeting_participants.breakout_id) is the single source of truth for where
-- a participant BELONGS; Go only reflects it (RemoveParticipant + client
-- re-mint). Guests are never assignable (D7); a move is NOT a kick (D2 —
-- banned_at untouched).
--
--
-- BZ block (meet B3 = BZ201, this file's slice): BZ201 breakout invalid —
-- the anti-oracle lump (F13: EVERY raise below uses raise_breakout_invalid()
-- so the message+HINT are byte-identical by construction). BZ186/188/190
-- reused from the B1 block.

-- The ONE raise site (F13 mechanized, not asserted-by-hand).
CREATE OR REPLACE FUNCTION raise_breakout_invalid() RETURNS void AS $$
BEGIN
    RAISE EXCEPTION 'breakout invalid'
        USING ERRCODE='BZ201', HINT='{"type":"unprocessable","detail":"breakout invalid"}';
END;
$$ LANGUAGE plpgsql;

-- meeting_breakout_open: host/cohost only. Opens p_count (1..20) new rooms;
-- only one open SET may exist per meeting at a time (meeting_breakouts_open_idx,
-- F3). Optionally round-robins current live, non-banned MEMBERS across the
-- new rooms (host/cohost roam — D7 — and guests are unassignable, both
-- excluded by the role='member' filter).
CREATE OR REPLACE FUNCTION meeting_breakout_open(
    p_user_id bigint, p_meeting_id bigint, p_count int,
    p_titles text[] DEFAULT NULL, p_auto_assign boolean DEFAULT false
) RETURNS jsonb AS $$
DECLARE
    v_state text; v_i int; v_row RECORD; v_out jsonb := '[]'::jsonb;
    v_member RECORD; v_slot int := 0; v_ids bigint[] := '{}';
BEGIN
    PERFORM meeting_require_authority(p_meeting_id, p_user_id);
    -- E5: the meetings-row lock (B2 genre) — serializes open/assign/close per
    -- meeting. Without it two concurrent opens race the partial unique index
    -- (loser = 23505 → 500, not BZ201) and close-all ∥ assign can commit an
    -- assignment onto a just-closed row. Do not "simplify" this away.
    SELECT state INTO v_state FROM meetings WHERE id = p_meeting_id FOR UPDATE;
    IF v_state = 'ended' THEN
        RAISE EXCEPTION 'meeting % has ended', p_meeting_id
            USING ERRCODE='BZ190', HINT='{"type":"conflict","detail":"meeting has ended"}';
    END IF;
    IF p_count IS NULL OR p_count < 1 OR p_count > 20 THEN
        RAISE EXCEPTION 'breakout count must be 1..20'
            USING ERRCODE='BZ188', HINT='{"type":"invalidArguments"}';
    END IF;
    IF EXISTS (SELECT 1 FROM meeting_breakouts WHERE meeting_id = p_meeting_id AND state = 'open') THEN
        PERFORM raise_breakout_invalid();
    END IF;
    FOR v_i IN 1..p_count LOOP
        INSERT INTO meeting_breakouts (meeting_id, idx, title)
        VALUES (p_meeting_id, v_i,
                NULLIF(trim(p_titles[v_i]), ''))  -- D5: NULL = client-rendered i18n default (meet.breakouts.defaultName)
        RETURNING id, idx, title, room_name INTO v_row;
        v_out := v_out || jsonb_build_object('breakoutId', v_row.id, 'idx', v_row.idx,
                                             'title', v_row.title, 'roomName', v_row.room_name);
        v_ids := v_ids || v_row.id;
    END LOOP;
    PERFORM notify_meet_state(p_meeting_id, 'breakout_opened',
                               jsonb_build_object('count', p_count));
    IF p_auto_assign THEN
        -- round-robin over current live, non-banned MEMBERS only (D7:
        -- host/cohost roam; guests are unassignable by construction here —
        -- role='member' excludes them).
        FOR v_member IN
            SELECT user_id, identity FROM meeting_participants
             WHERE meeting_id = p_meeting_id AND role = 'member'
               AND banned_at IS NULL AND left_at IS NULL AND user_id IS NOT NULL
             ORDER BY id
        LOOP
            UPDATE meeting_participants SET breakout_id = v_ids[(v_slot % p_count) + 1]
             WHERE meeting_id = p_meeting_id AND user_id = v_member.user_id;
            PERFORM notify_meet_state(p_meeting_id, 'breakout_assigned',
                jsonb_build_object('identity', v_member.identity,
                                   'breakoutId', v_ids[(v_slot % p_count) + 1]));
            v_slot := v_slot + 1;
        END LOOP;
    END IF;
    RETURN v_out;
END;
$$ LANGUAGE plpgsql;

-- meeting_breakout_assign: host/cohost only. Moves a target member into
-- p_breakout_id (NULL = main room). Returns the target's CURRENT (pre-move)
-- room name — the F1 contract: Go evicts from where the target actually is,
-- so their client re-runs the join choreography and lands where assigned.
-- Anti-oracle (F13): every failure to resolve a valid target/breakout is the
-- SAME BZ201 — a guest, a banned identity, a departed (left_at) identity, a
-- non-participant, a foreign-meeting breakout, and a closed breakout all
-- raise identically; a probe cannot distinguish which condition failed.
CREATE OR REPLACE FUNCTION meeting_breakout_assign(
    p_user_id bigint, p_meeting_id bigint, p_target_user_id bigint, p_breakout_id bigint
) RETURNS text AS $$
DECLARE
    v_target RECORD; v_current_room text; v_parent uuid;
BEGIN
    PERFORM meeting_require_authority(p_meeting_id, p_user_id);
    -- E5: same meetings-row FOR UPDATE as open/close — the three serialize.
    SELECT room_name INTO v_parent FROM meetings WHERE id = p_meeting_id AND state <> 'ended'
       FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'meeting % has ended', p_meeting_id
            USING ERRCODE='BZ190', HINT='{"type":"conflict","detail":"meeting has ended"}';
    END IF;
    -- target: a live, non-banned, PRESENT MEMBER-kind participant (u:-identity
    -- ⇒ never a guest; left_at IS NULL matches the auto-assign arm — E6a:
    -- assigning a departed participant is deliberately not allowed).
    -- Anti-oracle: every failure is the same BZ201.
    SELECT p.id, p.identity, p.breakout_id INTO v_target
      FROM meeting_participants p
     WHERE p.meeting_id = p_meeting_id AND p.user_id = p_target_user_id
       AND p.banned_at IS NULL AND p.left_at IS NULL AND p.identity LIKE 'u:%';
    IF NOT FOUND THEN PERFORM raise_breakout_invalid(); END IF;
    IF p_breakout_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM meeting_breakouts
         WHERE id = p_breakout_id AND meeting_id = p_meeting_id AND state = 'open'
    ) THEN PERFORM raise_breakout_invalid(); END IF;

    -- CURRENT room (pre-move): the F1 contract — Go evicts from where the
    -- target actually is, so their client re-runs the join choreography.
    SELECT COALESCE(
        (SELECT b.room_name::text FROM meeting_breakouts b
          WHERE b.id = v_target.breakout_id AND b.state = 'open'),
        v_parent::text) INTO v_current_room;

    UPDATE meeting_participants SET breakout_id = p_breakout_id WHERE id = v_target.id;
    PERFORM notify_meet_state(p_meeting_id, 'breakout_assigned',
        jsonb_build_object('identity', v_target.identity, 'breakoutId', p_breakout_id));
    RETURN v_current_room;
END;
$$ LANGUAGE plpgsql;

-- meeting_breakout_close: host/cohost only. Closes every open breakout row
-- for the meeting (idempotent — '[]' when nothing is open) and clears every
-- assignee back to main. Returns the closed child room names (Go's
-- DeleteRoom loop). F3: the partial-unique index means a later open(...)
-- reuses the same idx values without conflict.
CREATE OR REPLACE FUNCTION meeting_breakout_close(
    p_user_id bigint, p_meeting_id bigint
) RETURNS jsonb AS $$
DECLARE
    v_out jsonb;
BEGIN
    PERFORM meeting_require_authority(p_meeting_id, p_user_id);
    -- E5: same meetings-row lock as open/assign — a close-all cannot race an
    -- in-flight assign for this meeting (close-all ∥ assign cannot commit an
    -- assignment onto a just-closed row).
    PERFORM 1 FROM meetings WHERE id = p_meeting_id FOR UPDATE;

    SELECT COALESCE(jsonb_agg(room_name), '[]'::jsonb) INTO v_out
      FROM meeting_breakouts WHERE meeting_id = p_meeting_id AND state = 'open';

    UPDATE meeting_breakouts SET state = 'closed', closed_at = now()
     WHERE meeting_id = p_meeting_id AND state = 'open';
    IF v_out <> '[]'::jsonb THEN
        UPDATE meeting_participants SET breakout_id = NULL
         WHERE meeting_id = p_meeting_id AND breakout_id IS NOT NULL;
        PERFORM notify_meet_state(p_meeting_id, 'breakout_closed', NULL);
    END IF;
    RETURN v_out;
END;
$$ LANGUAGE plpgsql;

-- meeting_breakout_join: the grant-spec composer for a breakout room — the
-- meeting_join.sql shape, verbatim TTL formula. A member may only ever join
-- their OWN assignment (NULL arg + NULL assignment = main room); host/cohost
-- roam any open breakout or NULL. Child grants NEVER carry a live recording
-- (DN4 — breakouts are never recorded); the main-room grant carries the real
-- meeting_recording_active fact (F9).
CREATE OR REPLACE FUNCTION meeting_breakout_join(
    p_user_id bigint, p_meeting_id bigint, p_breakout_id bigint DEFAULT NULL
) RETURNS jsonb AS $$
DECLARE
    v_meeting   RECORD;
    v_identity  text := 'u:' || p_user_id;
    v_part      RECORD;
    v_name      text;
    v_ttl       int;
    v_room      uuid;
    v_recording boolean;
BEGIN
    IF is_guest_account(p_user_id) THEN
        -- A breakout JWT can outlive this transaction, so share-lock the guest
        -- lifecycle row exactly like meeting_join before returning a grant.
        PERFORM guest_require_grantable(p_user_id);
        PERFORM guest_require_meet_ready(p_user_id);
        IF NOT check_user_app_entitlement(p_user_id, 'meet') THEN
            RAISE EXCEPTION 'not available to guest accounts'
                USING ERRCODE='BZ215', HINT='{"type":"forbidden","detail":"not available to guest accounts"}';
        END IF;
    END IF;

    SELECT id, room_name, state, scheduled_end INTO v_meeting
      FROM meetings WHERE id = p_meeting_id;
    IF NOT FOUND OR v_meeting.state = 'ended' THEN
        RAISE EXCEPTION 'meeting % has ended', p_meeting_id
            USING ERRCODE='BZ190', HINT='{"type":"conflict","detail":"meeting has ended"}';
    END IF;

    -- A historical participant row is not durable guest authority. Breakout
    -- re-mints (including p_breakout_id=NULL for the main room) must use the
    -- same live scope as meeting_join: current channel membership, ownership,
    -- or an admitted authenticated knock.
    IF is_guest_account(p_user_id)
       AND NOT meeting_guest_join_allowed(p_user_id, p_meeting_id) THEN
        RAISE EXCEPTION 'not available to guest accounts'
            USING ERRCODE='BZ215', HINT='{"type":"forbidden","detail":"not available to guest accounts"}';
    END IF;

    SELECT role, banned_at, breakout_id INTO v_part
      FROM meeting_participants WHERE meeting_id = p_meeting_id AND identity = v_identity;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'participant % not found in meeting %', v_identity, p_meeting_id
            USING ERRCODE='BZ186', HINT='{"type":"forbidden"}';
    END IF;
    IF v_part.banned_at IS NOT NULL THEN
        RAISE EXCEPTION 'participant % is banned from meeting %', v_identity, p_meeting_id
            USING ERRCODE='BZ186', HINT='{"type":"forbidden","detail":"kicked; awaiting host re-admit"}';
    END IF;

    IF v_part.role IN ('host', 'cohost') THEN
        -- roams: any open breakout (validated) or NULL (main).
        IF p_breakout_id IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM meeting_breakouts
             WHERE id = p_breakout_id AND meeting_id = p_meeting_id AND state = 'open'
        ) THEN PERFORM raise_breakout_invalid(); END IF;
    ELSE
        -- member: only their OWN assignment is joinable (anti-oracle, F13).
        IF p_breakout_id IS DISTINCT FROM v_part.breakout_id THEN
            PERFORM raise_breakout_invalid();
        END IF;
    END IF;

    IF p_breakout_id IS NOT NULL THEN
        SELECT room_name INTO v_room FROM meeting_breakouts
         WHERE id = p_breakout_id AND meeting_id = p_meeting_id AND state = 'open';
        IF NOT FOUND THEN PERFORM raise_breakout_invalid(); END IF;
        v_recording := false; -- DN4: breakouts are never recorded
    ELSE
        v_room := v_meeting.room_name;
        v_recording := meeting_recording_active(p_meeting_id);
    END IF;

    SELECT display_name INTO v_name FROM users WHERE id = p_user_id;
    v_ttl := LEAST(14400, extract(epoch from (
        COALESCE(v_meeting.scheduled_end, now() + interval '4 hours')
        + interval '1 hour' - now()))::int);
    IF v_ttl < 900 THEN
        v_ttl := 900;
    END IF;
    v_ttl := identity_media_mint_fence(
        p_user_id,v_room::text,v_identity,v_ttl
    );

    RETURN jsonb_build_object(
        'room', v_room,
        'identity', v_identity,
        'name', COALESCE(v_name, 'User'),
        'role', v_part.role,
        'canPublish', true,
        'canSubscribe', true,
        'canPublishData', true,
        'roomAdmin', v_part.role IN ('host', 'cohost'),
        'hidden', false,
        'external', is_guest_account(p_user_id),
        'ttlSeconds', v_ttl,
        'recordingActive', v_recording
    );
END;
$$ LANGUAGE plpgsql;
