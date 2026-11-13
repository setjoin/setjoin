-- meeting_control.sql: Meet B1 Task 4 — the host/cohost control surface:
-- lock, set_guest_allowed, set_role (also the re-admit path), kick (= ban
-- until re-admit, gate-ratified user 2026-07-12), end. One concern, five
-- small functions in one file per the plan's explicit allowance.
--
--
-- BZ block (meet = BZ185-190, this file's slice): BZ186 host/cohost-only
-- action by a lesser role; BZ188 invalid role/identity/target.
--
-- App-level-primary (ARCH-006): authority checked via the meeting_member_role
-- DEFINER scope helper (a live read: only a participant row with
-- left_at IS NULL counts as currently holding that role).

-- meeting_lock: host/cohost only. Locking evicts nobody — it blocks NEW
-- joins; present participants are unaffected (documented posture).
CREATE OR REPLACE FUNCTION meeting_lock(
    p_user_id bigint, p_meeting_id bigint, p_locked boolean
) RETURNS void AS $$
BEGIN
    PERFORM meeting_require_authority(p_meeting_id, p_user_id);
    UPDATE meetings SET locked = p_locked WHERE id = p_meeting_id;
    PERFORM notify_meet_state(p_meeting_id, 'meeting_state', jsonb_build_object('locked', p_locked));
END;
$$ LANGUAGE plpgsql;

-- meeting_set_guest_allowed: host/cohost only (CEO #4 — flip guests on/off
-- mid-meeting). Affects FUTURE join-requests only; already-admitted guests
-- stay (kick is the eviction tool, not this).
CREATE OR REPLACE FUNCTION meeting_set_guest_allowed(
    p_user_id bigint, p_meeting_id bigint, p_guest_allowed boolean
) RETURNS void AS $$
BEGIN
    PERFORM meeting_require_authority(p_meeting_id, p_user_id);
    UPDATE meetings
       SET settings = jsonb_set(settings, '{guestAllowed}', to_jsonb(COALESCE(p_guest_allowed, false)))
     WHERE id = p_meeting_id;
    PERFORM notify_meet_state(p_meeting_id, 'meeting_state',
                               jsonb_build_object('guestAllowed', p_guest_allowed));
END;
$$ LANGUAGE plpgsql;

-- meeting_captions_set: B3 Task 13 (spec §4.3 D6/D8, F5's durable start-grace
-- stamp). host/cohost only (BZ186); a caller on an ended meeting gets BZ190
-- (the meeting_recording_start error-order genre: role check before the
-- ended check). IDEMPOTENT (D8): already in the requested state is a silent
-- no-op — no error, no push, RETURNS NULL, so a flip-flop double-click never
-- double-pushes or re-stamps captionsSince.
--
-- OFF->ON: jsonb_set BOTH captionsOn=true AND captionsSince=now() in the
-- SAME statement (F5 — the durable grace stamp Task 14's bidirectional
-- reconcile arm reads so a worker restart can never forget a Start still in
-- flight), push captions_state{on:true,botIdentity}, and RETURN the bot's
-- LiveKit grant spec — the grant-composition monopoly stays reducer-side
-- (D6, the same law meeting_join.sql/meeting_recording.sql follow): maximally
-- stripped short of hidden (canPublish:false, roomAdmin:false — the bot can
-- never publish video/audio, only data + listen).
--
-- 2026-07-16 delta (B3b live-gate P0 1b, reverses the B3 plan's ratified
-- hidden:true): livekit-server v1.13.3 forwards a HIDDEN participant's data
-- packets with an EMPTY participant_identity (A/B-proven live against the
-- real pinned SFU), so webmail's F8 fail-closed attestation
-- (room.svelte.ts's attestedCcIdentity check) dropped EVERY cc: frame and
-- captions never rendered anywhere. `hidden` is now `false` — the bot joins
-- UNHIDDEN so its data-packet sender identity actually arrives; webmail
-- filters `cc:`-prefixed identities out of the roster/gallery/participant
-- count client-side instead (room.svelte.ts's #syncParticipants), so users
-- still never see a bot row. The `cc:{meetingId}` identity shape stays the
-- reducer/MintToken monopoly (D6 unchanged) — unhiding does not weaken F8
-- attestation, it only makes the identity livekit forwards. Watch-item: if
-- a future LiveKit upstream ever forwards a hidden participant's data-packet
-- identity correctly, hidden:true + a server-side roster filter could be
-- restored instead of the client-side one.
--
-- ON->OFF: clear captionsOn only; captionsSince is deliberately left as-is
-- (never read while captionsOn=false, and the NEXT OFF->ON flip overwrites it
-- fresh anyway — clearing it here would be a no-op with extra bytes).
--
-- E5 (eng retro finding #3): the meetings-row FOR UPDATE lock, the SAME
-- pattern the three breakout mutators in THIS FILE's sibling
-- meeting_breakout.sql already use — without it, two concurrent starts both
-- read captionsOn=false BEFORE either writes, so both return a non-NULL
-- grant and the caller Starts the sidecar twice. The lock serializes the
-- second caller behind the first's commit, so it re-reads captionsOn=true
-- and takes the idempotent-204/NULL-grant path instead.
CREATE OR REPLACE FUNCTION meeting_captions_set(
    p_user_id bigint, p_meeting_id bigint, p_on boolean
) RETURNS jsonb AS $$
DECLARE
    v_room_name uuid;
    v_state     text;
    v_settings  jsonb;
    v_was_on    boolean;
BEGIN
    PERFORM meeting_require_authority(p_meeting_id, p_user_id);

    SELECT room_name, state, settings INTO v_room_name, v_state, v_settings
      FROM meetings WHERE id = p_meeting_id FOR UPDATE;
    IF v_state = 'ended' THEN
        RAISE EXCEPTION 'meeting % has ended', p_meeting_id
            USING ERRCODE='BZ190', HINT='{"type":"conflict","detail":"meeting has ended"}';
    END IF;

    v_was_on := COALESCE((v_settings ->> 'captionsOn')::boolean, false);
    IF v_was_on = COALESCE(p_on, false) THEN
        RETURN NULL;
    END IF;

    IF p_on THEN
        UPDATE meetings
           SET settings = jsonb_set(
                 jsonb_set(settings, '{captionsOn}', 'true'),
                 '{captionsSince}', to_jsonb(now()))
         WHERE id = p_meeting_id;
        PERFORM notify_meet_state(p_meeting_id, 'captions_state',
            jsonb_build_object('on', true, 'botIdentity', 'cc:' || p_meeting_id));
        RETURN jsonb_build_object(
            'room', v_room_name,
            'identity', 'cc:' || p_meeting_id,
            'name', 'Captions',
            'role', 'bot',
            'canPublish', false,
            'canSubscribe', true,
            'canPublishData', true,
            'roomAdmin', false,
            'hidden', false,
            'ttlSeconds', 14400,
            'recordingActive', false
        );
    ELSE
        UPDATE meetings
           SET settings = jsonb_set(settings, '{captionsOn}', 'false')
         WHERE id = p_meeting_id;
        PERFORM notify_meet_state(p_meeting_id, 'captions_state',
            jsonb_build_object('on', false, 'botIdentity', 'cc:' || p_meeting_id));
        RETURN NULL;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- meeting_set_role: host only. Only cohost|member assignable (host transfer
-- is not in B1); target must be a u:-identity. Authenticated guest-account
-- cohost promotion is G3 profile-gated; anonymous g: identities stay invalid.
-- Assigning a role to a banned identity ALSO clears banned_at — this IS the
-- re-admit path (gate-ratified): no separate route needed.
CREATE OR REPLACE FUNCTION meeting_set_role(
    p_user_id bigint, p_meeting_id bigint, p_identity text, p_role text
) RETURNS void AS $$
DECLARE
    v_role           text;
    v_target_user_id bigint;
BEGIN
    -- floor (host or cohost) via the shared authorize-preamble, then the
    -- STRICTER host-only requirement this action needs (role transfer is
    -- host-exclusive, unlike lock/guest-access/captions/kick above).
    v_role := meeting_require_authority(p_meeting_id, p_user_id);
    IF v_role <> 'host' THEN
        RAISE EXCEPTION 'host authority required to set participant role in meeting %', p_meeting_id
            USING ERRCODE='BZ186', HINT='{"type":"forbidden"}';
    END IF;
    IF p_role NOT IN ('cohost', 'member') THEN
        RAISE EXCEPTION 'invalid role %', p_role
            USING ERRCODE='BZ188', HINT='{"type":"invalidArguments","detail":"role must be cohost or member"}';
    END IF;
    IF p_identity !~ '^u:[0-9]+$' THEN
        RAISE EXCEPTION 'guests cannot be promoted (identity %)', p_identity
            USING ERRCODE='BZ188', HINT='{"type":"invalidArguments","detail":"target must be a member identity"}';
    END IF;

    BEGIN
        v_target_user_id := substring(p_identity from 3)::bigint;
    EXCEPTION WHEN numeric_value_out_of_range THEN
        RAISE EXCEPTION 'invalid member identity %', p_identity
            USING ERRCODE='BZ188', HINT='{"type":"invalidArguments","detail":"target must be a member identity"}';
    END;
    -- Guest G3: every role mutation can clear banned_at, so every guest target
    -- must still be active and Meet-entitled. allow_meet_host is narrower: it
    -- gates promotion to cohost in somebody else's meeting, while member
    -- demotion/re-admit remains available without that profile permission.
    IF is_guest_account(v_target_user_id) THEN
        PERFORM guest_require_grantable(v_target_user_id);
        IF NOT check_user_app_entitlement(v_target_user_id, 'meet') THEN
            RAISE EXCEPTION 'not available to guest accounts'
                USING ERRCODE='BZ215', HINT='{"type":"forbidden","detail":"not available to guest accounts"}';
        END IF;
        IF p_role = 'cohost'
           AND NOT guest_profile_flag(v_target_user_id, 'allow_meet_host') THEN
            RAISE EXCEPTION 'not available to guest accounts'
                USING ERRCODE='BZ215', HINT='{"type":"forbidden","detail":"not available to guest accounts"}';
        END IF;
    END IF;

    UPDATE meeting_participants
       SET role = p_role, banned_at = NULL
     WHERE meeting_id = p_meeting_id AND identity = p_identity;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'participant % not found in meeting %', p_identity, p_meeting_id
            USING ERRCODE='BZ188', HINT='{"type":"invalidArguments","detail":"participant not found"}';
    END IF;

    PERFORM notify_meet_state(p_meeting_id, 'participant_role',
                               jsonb_build_object('identity', p_identity, 'role', p_role));
END;
$$ LANGUAGE plpgsql;

-- meeting_kick: host/cohost only. Stamps left_at AND banned_at for EVERY
-- identity kind — banned_at is the single marker a kick leaves behind, and
-- the webhook-fact ingest reads it to refuse resurrecting a kicked
-- participant from a replayed (unordered) LiveKit retry. A
-- g:{join_request_id}-identity ADDITIONALLY flips its join_request row to
-- 'denied' in the same statement flow, otherwise the public poll would
-- re-mint a token after the kick (the two re-mint holes, symmetric closure).
-- The member ban is cleared by meeting_set_role; a guest's by meeting_admit's
-- ON CONFLICT re-admit arm.
--
-- B3 (delta 2): RETURNS text now — the target's CURRENT room name (parent OR
-- an open child breakout, the meeting_breakout_assign COALESCE shape) — so
-- Go can evict from where the target ACTUALLY is (F1: a kick against a
-- mid-breakout target must NOT only evict them from the parent room).
-- CREATE OR REPLACE cannot change a return type — DROP FUNCTION first (the
-- chat_message.sql:86 precedent). Callers (Go's kick route + every pgTAP
-- `SELECT meeting_kick(...)` call site) keep working unchanged; only the Go
-- route starts Scanning the result.
DROP FUNCTION IF EXISTS meeting_kick(bigint, bigint, text);
CREATE OR REPLACE FUNCTION meeting_kick(
    p_user_id bigint, p_meeting_id bigint, p_identity text
) RETURNS text AS $$
DECLARE
    v_target_breakout bigint; v_current_room text; v_parent uuid;
    v_removed_channel bigint; v_removed_user bigint; v_removed_role text;
BEGIN
    PERFORM meeting_require_authority(p_meeting_id, p_user_id);

    SELECT room_name INTO v_parent FROM meetings WHERE id = p_meeting_id;

    -- resolve the target's CURRENT (pre-move) room BEFORE the UPDATE below
    -- clears breakout_id — the meeting_breakout_assign COALESCE shape (F1:
    -- Go must evict from where the target actually is, main or a child).
    SELECT breakout_id INTO v_target_breakout
      FROM meeting_participants WHERE meeting_id = p_meeting_id AND identity = p_identity;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'participant % not found in meeting %', p_identity, p_meeting_id
            USING ERRCODE='BZ188', HINT='{"type":"invalidArguments","detail":"participant not found"}';
    END IF;
    SELECT COALESCE(
        (SELECT b.room_name::text FROM meeting_breakouts b
          WHERE b.id = v_target_breakout AND b.state = 'open'),
        v_parent::text) INTO v_current_room;

    -- banned_at is stamped for EVERY identity kind, member and guest alike: it is
    -- the single marker a kick leaves behind, and meeting_participant_event's
    -- participant_joined guard reads it to refuse resurrecting a kicked
    -- participant from a replayed (unordered) LiveKit webhook. Scoping it to u:
    -- left the guest half of that hole open — a kicked guest's revocation lived
    -- only in join_requests.state, which the webhook ingest does not consult.
    -- Every other banned_at consumer (meeting_join, the meeting_set_role and
    -- meeting_admit re-admit clears, meeting_lobby's member arm) is u:-scoped, so
    -- stamping guests here is inert everywhere except closing that hole.
    -- breakout_id is ALSO cleared here (B3): a kick is a full eviction, not a
    -- move — the target must land back at "main" bookkeeping-wise even
    -- though they never rejoin without re-admit.
    UPDATE meeting_participants
       SET left_at = now(),
           banned_at = now(),
           breakout_id = NULL
     WHERE meeting_id = p_meeting_id AND identity = p_identity;

    IF p_identity LIKE 'g:%' THEN
        UPDATE meeting_join_requests
           SET state = 'denied', decided_by = p_user_id, decided_at = now()
         WHERE meeting_id = p_meeting_id
           AND id = substring(p_identity FROM 3)::bigint
           AND state <> 'denied';
    END IF;

    -- D13: a kicked participant must not keep posting into the meeting's
    -- bridged chat/polls/Q&A. meeting_join re-inserts membership on re-admit
    -- + rejoin (meeting_join.sql's ON CONFLICT upsert).
    --
    -- V131-gated (pipeline-review confirmation fix): ONLY for a channel
    -- meeting_create provisioned FOR the meeting (chat_channel_provisioned).
    -- A huddle bound to a PRE-EXISTING channel/DM (provisioned=false) never
    -- reaches this DELETE — per V131's invariant, every member of a
    -- provisioned=false channel is a member who pre-dates the meeting, so
    -- clearing their membership on kick would strip legitimate access they
    -- held before the meeting ever existed, permanently (the re-INSERT paths
    -- in meeting_join/meeting_admit are ALSO provisioned-gated, so nothing
    -- ever restores it). meeting_join's/meeting_admit's re-insert gate and
    -- this DELETE's gate must stay symmetric.
    IF p_identity LIKE 'u:%' THEN
        WITH removed AS (
            DELETE FROM chat_channel_members cm
             USING meetings m
             WHERE m.id = p_meeting_id AND m.chat_channel_id IS NOT NULL
               AND m.chat_channel_provisioned
               AND cm.channel_id = m.chat_channel_id
               AND cm.user_id = substring(p_identity FROM 3)::bigint
            RETURNING cm.channel_id, cm.user_id, cm.role
        )
        SELECT channel_id, user_id, role INTO v_removed_channel, v_removed_user, v_removed_role FROM removed;

        -- Audit-chain coverage (pipeline review fix): a kick removes chat
        -- membership straight from chat_channel_members (never routing
        -- through chat_member_remove), so it bypassed the A4a chain
        -- entirely. Mirror chat_member_remove's member.remove act shape —
        -- only when a row was actually removed (a kick on a channel the
        -- target was never a member of, or a huddle-bound channel they
        -- never joined per V131, writes nothing).
        IF v_removed_channel IS NOT NULL
           AND COALESCE((SELECT enabled FROM feature_toggles
                         WHERE key = 'feature.chat_compliance'), FALSE) THEN
            PERFORM chat_access_audit(p_user_id, v_removed_channel, 'member.remove',
              'member', v_removed_user, NULL,
              jsonb_build_object('userId', v_removed_user, 'role', v_removed_role), NULL, NULL);
        END IF;
    END IF;

    PERFORM notify_meet_state(p_meeting_id, 'participant_kicked', jsonb_build_object('identity', p_identity));
    RETURN v_current_room;
END;
$$ LANGUAGE plpgsql;

-- meeting_end: host only. Terminal transition — expires pending join
-- requests and stamps every still-open participant. Returns room_name (Go
-- needs it to DeleteRoom, the eviction choke point).
CREATE OR REPLACE FUNCTION meeting_end(
    p_user_id bigint, p_meeting_id bigint
) RETURNS text AS $$
DECLARE
    v_room_name  uuid;
    v_rec_flip   RECORD;
    v_role       text;
BEGIN
    -- floor (host or cohost) via the shared authorize-preamble, then the
    -- STRICTER host-only requirement this action needs (only the host may
    -- end the meeting, unlike lock/guest-access/captions/kick above).
    v_role := meeting_require_authority(p_meeting_id, p_user_id);
    IF v_role <> 'host' THEN
        RAISE EXCEPTION 'host authority required to end meeting %', p_meeting_id
            USING ERRCODE='BZ186', HINT='{"type":"forbidden"}';
    END IF;

    UPDATE meetings SET state = 'ended', ended_at = now()
     WHERE id = p_meeting_id
    RETURNING room_name INTO v_room_name;

    -- B2 law 1: any in-flight recording flips in the SAME txn — but ONLY a
    -- row with an egress binding may enter 'stopping' (every convergence leg
    -- keys on egress_id; an unbound row parked in 'stopping' is a permanent
    -- wedge — eng E-F2 / plan delta 11). An unbound 'requested' row (Go never
    -- got as far as StartRoomComposite) goes straight to 'failed', with the
    -- banner-off push. The end route then calls StopEgress per bound egress
    -- BEFORE DeleteRoom, and the worker's stop leg sweeps any residue.
    FOR v_rec_flip IN
        WITH flipped AS (
            UPDATE meeting_recordings
               SET state = CASE WHEN state = 'active' OR egress_id IS NOT NULL
                                THEN 'stopping' ELSE 'failed' END,
                   stopped_at = CASE WHEN state = 'requested' AND egress_id IS NULL
                                     THEN now() ELSE stopped_at END,
                   error = CASE WHEN state = 'requested' AND egress_id IS NULL
                                THEN 'meeting ended before egress bind' ELSE error END
             WHERE meeting_id = p_meeting_id AND state IN ('requested', 'active')
             RETURNING id, state
        )
        SELECT id FROM flipped WHERE state = 'failed'
    LOOP
        PERFORM notify_meet_state(p_meeting_id, 'recording_state',
            jsonb_build_object('recordingId', v_rec_flip.id, 'state', 'failed'));
    END LOOP;

    -- B3: close any open breakouts in the SAME txn (law 1: end drops
    -- everyone — Go's end handler DeleteRooms every child after this commits;
    -- the worker's child-GC arm is the belt).
    UPDATE meeting_breakouts SET state = 'closed', closed_at = now()
     WHERE meeting_id = p_meeting_id AND state = 'open';
    IF FOUND THEN
        UPDATE meeting_participants SET breakout_id = NULL
         WHERE meeting_id = p_meeting_id AND breakout_id IS NOT NULL;
        PERFORM notify_meet_state(p_meeting_id, 'breakout_closed', NULL);
    END IF;

    -- M2 (V265): a live presentation session cannot outlive its meeting —
    -- the same law-1 same-txn flip the recording arm above makes. CANCELLED
    -- (not ENDED): the actor is the meeting ending, never a presenter hand
    -- back, and PREPARING/READY are the cancel arm of the M0 state machine.
    -- The push rides BEFORE the left_at mass-stamp below (notify_meet_state
    -- fans out to left_at IS NULL rows — the third end-path ordering bug
    -- class this file already documents twice).
    UPDATE meeting_presentations
       SET status = 'CANCELLED', ended_at = now(), updated_at = now()
     WHERE meeting_id = p_meeting_id
       AND status IN ('PREPARING','READY','ACTIVE','DEGRADED');
    IF FOUND THEN
        PERFORM notify_meet_state(p_meeting_id, 'presentation_state',
            jsonb_build_object('status', 'CANCELLED'));
    END IF;

    -- M4 (V266): an in-flight semantic recording cannot outlive its meeting
    -- either — the same law-1 same-txn flip, the recording arm's shape. The
    -- segments it never closed stay whatever they truthfully are; the worker
    -- plane marks them interrupted against the now-terminal recording. The
    -- push rides before the left_at mass-stamp (the ordering rule above).
    FOR v_rec_flip IN
        SELECT id FROM meeting_semantic_recordings
         WHERE meeting_id = p_meeting_id AND rec_state = 'active'
    LOOP
        UPDATE meeting_semantic_recordings
           SET rec_state = 'stopped', stopped_at = now(), updated_at = now()
         WHERE id = v_rec_flip.id;
        PERFORM notify_meet_state(p_meeting_id, 'recording_state',
            jsonb_build_object('recordingId', v_rec_flip.id, 'state', 'stopped',
                               'mode', 'semantic'));
    END LOOP;

    -- M5 (V268): a live local-capture lease cannot outlive its meeting —
    -- the same law-1 same-txn flip, the revocation/meeting-end stop the
    -- plan names. The recording stop rode the M4 arm above (same txn); the
    -- lease flip records WHY it stopped so the capturing device's next
    -- heartbeat meets the stop fact, never a refreshed deadline.
    UPDATE meeting_local_capture_leases
       SET lease_state = 'stopped', stop_reason = 'meeting_ended',
           stopped_at = now(), updated_at = now()
     WHERE meeting_id = p_meeting_id AND lease_state = 'live';

    -- Emit BEFORE stamping left_at below: notify_meet_state's fan-out
    -- filters WHERE left_at IS NULL, so firing after the mass-stamp reaches
    -- zero recipients by construction (the identical ordering bug fixed in
    -- meeting_participant_event's room_finished arm) — the terminal push
    -- must go out while the recipient set is still live.
    PERFORM notify_meet_state(p_meeting_id, 'meeting_state', jsonb_build_object('state', 'ended'));

    -- Expire pending knocks BEFORE the left_at mass-stamp below: the V134
    -- meeting_join_requests UPDATE policy authorizes via meeting_member_role,
    -- which filters left_at IS NULL — after the stamp the ending host's own
    -- row no longer counts, the policy USING goes false, and this UPDATE
    -- silently hits 0 rows under the constrained setjoin_app role (a pending
    -- knock then outlives the meeting, polling forever). The third instance
    -- of this end-path ordering bug class (notify fan-out, room_finished) —
    -- found live by the 2026-07-16 fresh-VM gate's guest leg.
    UPDATE meeting_join_requests SET state = 'expired'
     WHERE meeting_id = p_meeting_id AND state = 'pending';
    UPDATE meeting_participants SET left_at = now()
     WHERE meeting_id = p_meeting_id AND left_at IS NULL;

    RETURN v_room_name::text;
END;
$$ LANGUAGE plpgsql;
