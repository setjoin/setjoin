--
-- meeting_lobby.sql: Meet B1 Task 5 — the guest lobby reducer trio (create/
-- poll/admit/deny) + the expiry sweep. `meeting_join_request_create` and
-- `meeting_join_request_poll` are the ONLY functions reachable from the
-- unauthenticated public surface (spec HTTP surface, /public/meet/*), so
-- BOTH are SECURITY DEFINER + apply_worker_ownership (the chat_space_ensure
-- pattern): there is no caller GUC on that surface, so they must survive the
-- native-RLS flip without one. Both carry SET search_path = pg_catalog,
-- public — the exact pin chat_space_ensure.sql:25 carries; a DEFINER
-- function without a pinned search_path is the classic PG
-- privilege-escalation foot-gun.
--
-- meeting_admit/meeting_deny/meeting_requests_expire run on the authed
-- app pool (host/cohost claims, or the maintenance worker) like every other
-- meeting_control.sql reducer — no DEFINER needed while that pool stays
-- BYPASSRLS (ARCH-006).
--
-- BZ block (meet = BZ185-190, this file's slice): BZ185 meeting/slug not
-- found — the anti-oracle also covers guestAllowed-off / meet.guest_access-
-- off / an admitted guest re-polling after the org kill switch flips OFF;
-- BZ186 admit/deny by a non-host/cohost; BZ188 invalid display name / flood
-- cap; BZ189 admit/deny of a request that is not pending-and-unexpired
-- (covers nonexistent too — one code, no oracle on which). BZ329 (V270, the
-- durable admitted re-mint fence) is this file's window-closed code: the
-- admitted mint capability is past its 15-minute horizon. It never reaches
-- the wire from the poll — meeting_join_request_poll catches it and
-- synthesizes the reducer's own {"state":"expired"} shape (see the fence
-- call site below).
--
-- B3 Task 13: meeting_join_request_poll's BOTH admitted-grant returns
-- (guest g: and authenticated-knock u:) carry captionsOn — the recordingActive D5
-- rider shape, DN3: the captions indicator is visible to guests too.

-- meeting_join_request_create: resolve by slug ONLY. An authenticated user
-- knocking on a locked meeting (p_user_id set, from claims via the authed route)
-- bypasses the guestAllowed/guest_access anti-oracle arm entirely — that arm
-- is scoped to guest rows (p_user_id IS NULL) on purpose: a member knock is
-- legitimate even with the org guest kill switch OFF (Task 11's contract).
CREATE OR REPLACE FUNCTION meeting_join_request_create(
    p_slug text, p_display_name text, p_user_id bigint DEFAULT NULL
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    v_meeting       RECORD;
    v_name          text;
    v_request_id    bigint;
    v_secret        text;
    v_pending_count int;
BEGIN
    -- Guest G3: authenticated guest accounts use this same secret-bound knock
    -- rail, but must pass the lifecycle + Meet entitlement belts before a
    -- request exists. Anonymous model-3 callers remain p_user_id IS NULL and
    -- continue through the guestAllowed/meet.guest_access anti-oracle below.
    IF p_user_id IS NOT NULL AND is_guest_account(p_user_id) THEN
        PERFORM guest_require_active(p_user_id);
        IF NOT check_user_app_entitlement(p_user_id, 'meet') THEN
            RAISE EXCEPTION 'not available to guest accounts'
                USING ERRCODE='BZ215', HINT='{"type":"forbidden","detail":"not available to guest accounts"}';
        END IF;
    END IF;

    SELECT id, state, settings INTO v_meeting
      FROM meetings WHERE slug = p_slug;

    IF NOT FOUND OR v_meeting.state = 'ended' THEN
        RAISE EXCEPTION 'meeting not found'
            USING ERRCODE='BZ185', HINT='{"type":"notFound"}';
    END IF;

    -- guest-only anti-oracle arm (Task 5 scoping note): unscoped, this would
    -- also 404 a legitimate member knock with guest_access OFF.
    IF p_user_id IS NULL THEN
        IF COALESCE((v_meeting.settings ->> 'guestAllowed')::boolean, false) IS NOT TRUE
           OR NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key = 'meet.guest_access'), false)
        THEN
            RAISE EXCEPTION 'meeting not found'
                USING ERRCODE='BZ185', HINT='{"type":"notFound"}';
        END IF;
    END IF;

    v_name := btrim(COALESCE(p_display_name, ''));
    IF length(v_name) < 1 OR length(v_name) > 80 THEN
        RAISE EXCEPTION 'display name must be 1-80 characters'
            USING ERRCODE='BZ188', HINT='{"type":"invalidArguments","detail":"display name must be 1-80 characters"}';
    END IF;

    SELECT count(*) INTO v_pending_count
      FROM meeting_join_requests WHERE meeting_id = v_meeting.id AND state = 'pending';
    IF v_pending_count >= 100 THEN
        RAISE EXCEPTION 'too many pending join requests for meeting %', v_meeting.id
            USING ERRCODE='BZ188', HINT='{"type":"invalidArguments","detail":"join-request flood cap reached"}';
    END IF;

    INSERT INTO meeting_join_requests (meeting_id, display_name, user_id)
      VALUES (v_meeting.id, v_name, p_user_id)
      RETURNING id, secret INTO v_request_id, v_secret;

    PERFORM notify_meet_state(v_meeting.id, 'join_request_created', NULL, ARRAY['host', 'cohost']);

    RETURN jsonb_build_object('requestId', v_request_id, 'secret', v_secret);
END;
$$;
SELECT apply_worker_ownership('meeting_join_request_create(text,text,bigint)'::regprocedure);

-- meeting_join_request_poll: slug + request id + secret must all match, else
-- the identical BZ185 (constant-shape anti-oracle — no distinguishing which
-- part was wrong). Serves both waiting guests and knocking members; the
-- grant shape differs by row kind (guest vs member-knock), never guessed
-- from the request — read straight off the row.
CREATE OR REPLACE FUNCTION meeting_join_request_poll(
    p_slug text, p_request_id bigint, p_secret text
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    v_req       RECORD;
    v_meeting   RECORD;
    v_name      text;
    v_role      text;
    v_banned_at timestamptz;
    v_ttl       int;
BEGIN
    SELECT r.id, r.meeting_id, r.display_name, r.user_id, r.state, r.expires_at
      INTO v_req
      FROM meeting_join_requests r
      JOIN meetings m ON m.id = r.meeting_id AND m.slug = p_slug
     WHERE r.id = p_request_id AND r.secret = p_secret;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'join request not found'
            USING ERRCODE='BZ185', HINT='{"type":"notFound"}';
    END IF;

    -- lazy clock-expiry: a poll landing after expires_at settles the row
    -- instead of waiting on the worker sweep.
    IF v_req.state = 'pending' AND v_req.expires_at < now() THEN
        UPDATE meeting_join_requests SET state = 'expired' WHERE id = v_req.id;
        v_req.state := 'expired';
    END IF;

    -- the guest re-mint kill (Task 5): an admitted guest must not keep
    -- re-minting a token after the org flips meet.guest_access OFF — keeps
    -- the V125 toggle description ("the public surface 404s everywhere")
    -- literally true. Member-knock rows (user_id NOT NULL) are unaffected.
    IF v_req.user_id IS NULL
       AND NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key = 'meet.guest_access'), false)
    THEN
        RAISE EXCEPTION 'meeting not found'
            USING ERRCODE='BZ185', HINT='{"type":"notFound"}';
    END IF;

    -- An authenticated guest knock completes on this public, secret-bound
    -- poll route, outside the JWT/RequireApp middleware. Re-apply both belts
    -- before every grant re-mint so disable/profile entitlement changes cannot
    -- be bypassed with a previously-issued poll secret.
    IF v_req.user_id IS NOT NULL AND is_guest_account(v_req.user_id) THEN
        -- Poll can re-mint an admitted guest token. Serialize that grant with
        -- disable/expiry so G5's room snapshot cannot miss an in-flight mint.
        PERFORM guest_require_grantable(v_req.user_id);
        IF NOT check_user_app_entitlement(v_req.user_id, 'meet') THEN
            RAISE EXCEPTION 'not available to guest accounts'
                USING ERRCODE='BZ215', HINT='{"type":"forbidden","detail":"not available to guest accounts"}';
        END IF;
    END IF;

    -- D5: the pending return carries recordingActive (the poll→admit
    -- flicker-window belt — with the D4 arms a guest can never be admitted
    -- WHILE recording, but the guest UI treats this as a belt, not the
    -- primary guarantee). denied/expired carry no flag: D-7 — no consent
    -- decision remains on a dead request.
    IF v_req.state = 'pending' THEN
        RETURN jsonb_build_object('state', v_req.state,
                                   'recordingActive', meeting_recording_active(v_req.meeting_id));
    ELSIF v_req.state IN ('denied', 'expired') THEN
        RETURN jsonb_build_object('state', v_req.state);
    END IF;

    -- admitted: compose the grant by row kind. A poll must never hand a
    -- knocking member a guest identity, nor vice versa.
    SELECT room_name, scheduled_end, state, settings INTO v_meeting FROM meetings WHERE id = v_req.meeting_id;

    -- the DES-011 authority check (Task 5 blocker fix): an admitted row
    -- outlives meeting_end (meeting_control.sql only expires 'pending' rows
    -- at end), so without this the poll would keep re-minting a live grant
    -- for a room that no longer exists — the exact re-mint window the kick
    -- path (above) deliberately slams shut. Synthesize 'expired' on the wire
    -- without touching the persisted row: 'admitted' stays the true historical
    -- decision record: the host really did admit this request.
    IF v_meeting.state NOT IN ('scheduled', 'live') THEN
        RETURN jsonb_build_object('state', 'expired');
    END IF;

    v_ttl := LEAST(14400, extract(epoch from (
        COALESCE(v_meeting.scheduled_end, now() + interval '4 hours')
        + interval '1 hour' - now()))::int);
    IF v_ttl < 900 THEN
        v_ttl := 900;
    END IF;

    -- The durable admitted re-mint window (occ_bcdf321's reducer half): the
    -- mint capability is fenced per join request at 15 minutes past the FIRST
    -- admitted mint (meeting_lobby_mint_fence, V270 — the reducer owns the
    -- truth, lobby.go's per-process admittedMintFence is the second layer).
    -- The fence consults sit immediately before each RETURN that would mint —
    -- after every shape-deciding arm above (toggle-off BZ185, meeting-ended
    -- expired, banned denied, the identity_media_mint_fence admission gate on
    -- the member arm), so the wire-shape priority is exactly what the Go
    -- fence produced when it was the only time bound. A past-window mint
    -- raises BZ329; the handler maps it to the SAME wire shape the
    -- meeting-ended arm just above synthesizes — {"state":"expired"}, bare,
    -- no riders, the persisted row untouched — so a fenced poll is
    -- indistinguishable from that arm on the wire, and a WITHIN-window poll
    -- is byte-identical to the pre-fence behavior. (The member arm's fence
    -- runs after identity_media_mint_fence so a mint that the identity
    -- transition gate refuses never burns window; conversely a BZ329 refusal
    -- here rolls the whole nested block back — the identity admission lease
    -- that arm just refreshed dies with it, truthful for a poll that minted
    -- nothing.)
    BEGIN
        IF v_req.user_id IS NULL THEN
            PERFORM meeting_lobby_mint_fence(v_req.id);
            RETURN jsonb_build_object('state', 'admitted', 'recordingActive',
                meeting_recording_active(v_req.meeting_id),
                -- B3 Task 13, DN3: the captions indicator is visible to guests
                -- too — the recordingActive shape, same envelope, same rider.
                'captionsOn', COALESCE((v_meeting.settings ->> 'captionsOn')::boolean, false),
                -- B3 Task 18 retro fix (design finding #4, the guest-captions
                -- ceiling): the bot's OWN attested identity, unconditional on
                -- captionsOn — wave B's guest page needs it to pre-attest cc
                -- frames whether or not captions happen to be on at admit time.
                'ccIdentity', 'cc:' || v_req.meeting_id,
                'grant', jsonb_build_object(
                'room', v_meeting.room_name,
                'identity', 'g:' || v_req.id,
                'name', v_req.display_name,
                'role', 'guest',
                'canPublish', true, 'canSubscribe', true, 'canPublishData', true,
                'roomAdmin', false, 'hidden', false, 'external', false,
                'ttlSeconds', v_ttl
            ));
        ELSE
            IF is_guest_account(v_req.user_id) THEN
                PERFORM guest_require_meet_ready(v_req.user_id);
            END IF;
            SELECT role, banned_at INTO v_role, v_banned_at FROM meeting_participants
              WHERE meeting_id = v_req.meeting_id AND identity = 'u:' || v_req.user_id;

            -- the banned-member re-mint kill (Task 5 blocker fix, live-reproduced
            -- 2026-07-12): meeting_kick stamps banned_at on the participant row
            -- but — unlike the g:-identity arm, where the join_request IS the
            -- guest's only identity record — a member-knock's join_request row
            -- and the participant row it created are two records of the SAME
            -- ban decision. banned_at on meeting_participants is the single
            -- source of truth every other authority check already reads
            -- (meeting_join.sql:40, meeting_set_role's re-admit clear); teaching
            -- meeting_kick to ALSO flip this join_request to 'denied' would just
            -- create a second copy of the same fact to keep in sync. Read the
            -- one source instead: a banned identity's knock reports 'denied' on
            -- the wire (mirroring the guest kick shape) without rewriting the
            -- persisted 'admitted' history, exactly like the meeting_end arm
            -- above. Cleared the moment a host re-admits (meeting_set_role),
            -- same as meeting_join.
            IF v_banned_at IS NOT NULL THEN
                RETURN jsonb_build_object('state', 'denied');
            END IF;

            SELECT display_name INTO v_name FROM users WHERE id = v_req.user_id;
            v_ttl := identity_media_mint_fence(
                v_req.user_id,v_meeting.room_name::text,
                'u:'||v_req.user_id::text,v_ttl
            );
            PERFORM meeting_lobby_mint_fence(v_req.id);
            RETURN jsonb_build_object('state', 'admitted', 'recordingActive',
                meeting_recording_active(v_req.meeting_id),
                -- B3 Task 13, DN3: the same captions rider, both admitted arms.
                'captionsOn', COALESCE((v_meeting.settings ->> 'captionsOn')::boolean, false),
                -- B3 Task 18 retro fix (design finding #4): the same ccIdentity
                -- rider, both admitted arms.
                'ccIdentity', 'cc:' || v_req.meeting_id,
                'grant', jsonb_build_object(
                'room', v_meeting.room_name,
                'identity', 'u:' || v_req.user_id,
                'name', COALESCE(v_name, 'User'),
                'role', COALESCE(v_role, 'member'),
                'canPublish', true, 'canSubscribe', true, 'canPublishData', true,
                'roomAdmin', false, 'hidden', false,
                'external', is_guest_account(v_req.user_id), 'ttlSeconds', v_ttl
            ));
        END IF;
    EXCEPTION
        WHEN SQLSTATE 'BZ329' THEN
            -- the fence's past-window shape IS the meeting-ended shape above
            -- (bare expired, no riders); the persisted 'admitted' row stays
            -- the true historical decision, exactly like that arm.
            RETURN jsonb_build_object('state', 'expired');
    END;
END;
$$;
SELECT apply_worker_ownership('meeting_join_request_poll(text,bigint,text)'::regprocedure);

-- meeting_lobby_mint_fence: the DURABLE admitted re-mint window
-- (occ_bcdf321b15332f109a69e653's reducer half, V270). lobby.go's
-- admittedMintFence bounds the public poll's admitted-leg mint capability to
-- 15 minutes past the FIRST admitted mint — but that fence is a per-process
-- map: a gateway restart or a second replica starts its own clock and reopens
-- the window (its own doc says so). This fence is the same bound at the
-- reducer layer, where the admit decision itself lives: ONE immutable
-- meeting_lobby_mint_fences row per join request records the first admitted
-- mint's wall-clock anchor with the SAME 15-minute horizon (the V125
-- pending-expiry interval the Go fence reuses), and every past-window mint
-- fails closed with BZ329. The Go fence stays as the second layer (belt and
-- braces); THIS row is the truth the wire now inherits — identity_media_
-- mint_fence's genre, applied to the g:/u: knock-admission capability.
--
-- Contract split (deliberate): the poll's own state machine stays the
-- authority for the wire SHAPE (pending/denied/meeting-ended/banned/toggle
-- arms all decide before this fence is consulted — the call site below sits
-- immediately before each RETURN that would mint, exactly where lobby.go's
-- fence.allow used to sit on the wire); THIS function owns only the TIME
-- bound. It derives meeting_id and identity from the join_requests row itself
-- (never from the caller — the fence cannot be pointed at a foreign meeting),
-- never extends an existing window (INSERT ... ON CONFLICT DO NOTHING + a
-- re-read: the FIRST mint wins, a fast poller only accelerates the close for
-- everyone), and returns the window's close time for testability. Deliberately
-- NO lazy GC (identity_media_mint_fence sweeps expired admission leases — that
-- fence re-anchors every mint, ours must not): an expired window row is the
-- DURABLE CLOSED marker, and sweeping it would let the next poll's INSERT
-- re-anchor a fresh window — the exact reopen this fence exists to kill. A
-- closed window stays closed for the lifetime of its join request; the tiny
-- tombstone cascades away with the request (ON DELETE CASCADE, V270).
CREATE OR REPLACE FUNCTION meeting_lobby_mint_fence(
    p_request_id BIGINT
) RETURNS TIMESTAMPTZ
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_req      RECORD;
    v_fence    RECORD;
    v_identity text;
BEGIN
    -- A nonexistent (or NULL) request has no mint window to open: fail
    -- closed with the same code as a closed one (the poll only ever calls
    -- this for a row it just read, so this arm is direct-misuse armor).
    IF p_request_id IS NULL THEN
        RAISE EXCEPTION 'admitted re-mint window is closed'
            USING ERRCODE='BZ329',
                  HINT='{"type":"stateMismatch"}';
    END IF;

    SELECT id, meeting_id, user_id INTO v_req
      FROM meeting_join_requests WHERE id = p_request_id FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'admitted re-mint window is closed'
            USING ERRCODE='BZ329',
                  HINT='{"type":"stateMismatch"}';
    END IF;

    -- The identity genre the poll would mint right now, derived from the row
    -- (guest rows mint g:{request_id}; member knocks mint u:{user_id}).
    v_identity := CASE WHEN v_req.user_id IS NULL
                       THEN 'g:' || v_req.id::text
                       ELSE 'u:' || v_req.user_id::text END;

    -- First mint WINS, never extends: on a concurrent first mint the loser's
    -- INSERT no-ops against the winner's committed row and re-reads it, so
    -- both mints anchor to ONE window (no explicit lock needed — the PK
    -- conflict IS the serialization point). An EXPIRED row is never swept:
    -- it is the durable CLOSED marker (sweeping it would let this very
    -- INSERT re-anchor a fresh window — the reopen this fence kills).
    INSERT INTO meeting_lobby_mint_fences
        (join_request_id, meeting_id, identity, first_mint_at, expires_at)
    VALUES
        (v_req.id, v_req.meeting_id, v_identity,
         statement_timestamp(), statement_timestamp() + interval '15 minutes')
    ON CONFLICT (join_request_id) DO NOTHING;

    SELECT * INTO v_fence
      FROM meeting_lobby_mint_fences WHERE join_request_id = v_req.id;

    -- Past the window (or an incoherent row — FKs make drift impossible
    -- today, the belt costs one comparison): fail closed. The poll catches
    -- this exact code and synthesizes the meeting-ended wire shape.
    IF v_fence.meeting_id IS DISTINCT FROM v_req.meeting_id
       OR v_fence.identity IS DISTINCT FROM v_identity
       OR v_fence.expires_at <= statement_timestamp() THEN
        RAISE EXCEPTION 'admitted re-mint window is closed for join request %', v_req.id
            USING ERRCODE='BZ329',
                  HINT='{"type":"stateMismatch"}';
    END IF;

    RETURN v_fence.expires_at;
END;
$$;
SELECT apply_worker_ownership('meeting_lobby_mint_fence(bigint)'::regprocedure);

-- meeting_admit: host/cohost of the request's meeting (BZ186); row pending
-- and unexpired (BZ189 — covers nonexistent too, no oracle on which).
-- Creates the meeting_participants row (guest g:{id}, or an ordinary
-- u:{user_id} member row for a member-knock — that path bypasses
-- meeting_join entirely, so it also mirrors meeting_join's chat-channel
-- bind here: without it a knock-admitted member's chat post fails the
-- membership gate). ON CONFLICT clears left_at AND banned_at — a host
-- admitting a knock from a previously-banned identity IS the re-admit; a
-- knock-then-admit must never leave the contradictory banned-but-admitted
-- state.
CREATE OR REPLACE FUNCTION meeting_admit(
    p_user_id bigint, p_request_id bigint
) RETURNS jsonb AS $$
DECLARE
    v_req                     RECORD;
    v_identity                text;
    v_channel_id              bigint;
    v_channel_change_seq      bigint;
    v_guest_can_post          boolean;
    v_guest_history_from_join boolean;
    v_is_guest_account        boolean := false;
BEGIN
    SELECT id, meeting_id, display_name, user_id, state, expires_at
      INTO v_req FROM meeting_join_requests WHERE id = p_request_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'join request % is not decidable', p_request_id
            USING ERRCODE='BZ189', HINT='{"type":"unprocessable","detail":"join request not decidable"}';
    END IF;

    PERFORM meeting_require_authority(v_req.meeting_id, p_user_id);

    IF v_req.state <> 'pending' OR v_req.expires_at < now() THEN
        RAISE EXCEPTION 'join request % is not decidable', p_request_id
            USING ERRCODE='BZ189', HINT='{"type":"unprocessable","detail":"join request not decidable"}';
    END IF;

    -- B2 §8.2 arm 2 (D4): a GUEST admission is blocked while a recording is
    -- in flight — same row lock as meeting_recording_start's arm 1, so the
    -- two arms serialize instead of racing (an explicit FOR UPDATE, not
    -- look-then-act). Member-knock admits are NOT guests and pass.
    IF v_req.user_id IS NULL THEN
        PERFORM 1 FROM meetings WHERE id = v_req.meeting_id FOR UPDATE;
        IF meeting_recording_active(v_req.meeting_id) THEN
            RAISE EXCEPTION 'meeting % is being recorded; stop the recording to admit guests', v_req.meeting_id
                USING ERRCODE='BZ199',
                      HINT='{"type":"forbidden","detail":"stop the recording to admit guests"}';
        END IF;
    END IF;

    -- Resolve and lock the provisioned channel before taking a guest-satellite
    -- lock, matching chat_member_add's channel -> guest lock order. The lock
    -- also makes history_floor_seq an atomic boundary against a concurrent
    -- change_seq bump. A huddle bound to a pre-existing channel deliberately
    -- finds no row here and never auto-grants its chat history.
    SELECT c.id, c.change_seq
      INTO v_channel_id, v_channel_change_seq
      FROM meetings m
      JOIN chat_channels c ON c.id = m.chat_channel_id
     WHERE m.id = v_req.meeting_id AND m.chat_channel_provisioned
     FOR UPDATE OF c;

    IF v_req.user_id IS NOT NULL THEN
        v_is_guest_account := is_guest_account(v_req.user_id);
        IF v_is_guest_account THEN
            PERFORM guest_require_grantable(v_req.user_id);
            IF NOT check_user_app_entitlement(v_req.user_id, 'meet') THEN
                RAISE EXCEPTION 'not available to guest accounts'
                    USING ERRCODE='BZ215', HINT='{"type":"forbidden","detail":"not available to guest accounts"}';
            END IF;
            SELECT s.can_post, s.history_from_join
              INTO v_guest_can_post, v_guest_history_from_join
              FROM guest_chat_policy_snapshot(v_req.user_id) s;
        END IF;
    END IF;

    v_identity := CASE WHEN v_req.user_id IS NULL THEN 'g:' || v_req.id
                       ELSE 'u:' || v_req.user_id END;

    INSERT INTO meeting_participants (meeting_id, user_id, guest_display_name, identity, role)
      VALUES (v_req.meeting_id, v_req.user_id,
              CASE WHEN v_req.user_id IS NULL THEN v_req.display_name ELSE NULL END,
              v_identity,
              CASE WHEN v_req.user_id IS NULL THEN 'guest' ELSE 'member' END)
      ON CONFLICT (meeting_id, identity) DO UPDATE SET left_at = NULL, banned_at = NULL;

    -- Huddle Slack semantics (V131, pipeline review fix): mirrors
    -- meeting_join.sql's gate — a member-knock admit only auto-adds the
    -- caller to a MEETING-PROVISIONED channel, never a huddle bound to a
    -- pre-existing channel/DM. Audit-chain coverage (pipeline review fix,
    -- F2 completion): an actual insert on the provisioned path is a
    -- member.join act, meeting_join.sql's exact shape — the admitter
    -- (p_user_id) is the actor, the admitted knocker (v_req.user_id) is the
    -- target, the chat_org_default_set genre for an actor-acts-for-another
    -- membership grant.
    IF v_req.user_id IS NOT NULL AND v_channel_id IS NOT NULL THEN
        INSERT INTO chat_channel_members
            (channel_id, user_id, can_post, history_floor_seq)
          VALUES (
            v_channel_id, v_req.user_id,
            CASE WHEN v_is_guest_account THEN v_guest_can_post ELSE NULL END,
            CASE WHEN v_is_guest_account AND v_guest_history_from_join
                 THEN v_channel_change_seq ELSE NULL END
          )
          ON CONFLICT DO NOTHING;

        IF FOUND AND COALESCE((SELECT enabled FROM feature_toggles
                                WHERE key = 'feature.chat_compliance'), FALSE) THEN
            PERFORM chat_access_audit(p_user_id, v_channel_id, 'member.join',
              'member', v_req.user_id, NULL,
              jsonb_build_object('userId', v_req.user_id, 'role', 'member'), NULL, NULL);
        END IF;
    END IF;

    UPDATE meeting_join_requests SET state = 'admitted', decided_by = p_user_id, decided_at = now()
     WHERE id = p_request_id;

    -- ordering contract (eng #5): the participant row above already ran
    -- before this call, so an admitted member-knocker is a fan-out target
    -- for this very event. A denied/expired row never reaches this line —
    -- the poll is their sole completion contract.
    PERFORM notify_meet_state(v_req.meeting_id, 'join_request_decided',
                               jsonb_build_object('requestId', p_request_id, 'state', 'admitted'));

    RETURN jsonb_build_object('identity', v_identity);
END;
$$ LANGUAGE plpgsql;

-- meeting_deny: same gates as admit; no participant row, no push (the poll
-- is the sole completion contract for the denied arm).
CREATE OR REPLACE FUNCTION meeting_deny(
    p_user_id bigint, p_request_id bigint
) RETURNS void AS $$
DECLARE
    v_req RECORD;
BEGIN
    SELECT id, meeting_id, state, expires_at INTO v_req
      FROM meeting_join_requests WHERE id = p_request_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'join request % is not decidable', p_request_id
            USING ERRCODE='BZ189', HINT='{"type":"unprocessable","detail":"join request not decidable"}';
    END IF;

    PERFORM meeting_require_authority(v_req.meeting_id, p_user_id);

    IF v_req.state <> 'pending' OR v_req.expires_at < now() THEN
        RAISE EXCEPTION 'join request % is not decidable', p_request_id
            USING ERRCODE='BZ189', HINT='{"type":"unprocessable","detail":"join request not decidable"}';
    END IF;

    UPDATE meeting_join_requests SET state = 'denied', decided_by = p_user_id, decided_at = now()
     WHERE id = p_request_id;
END;
$$ LANGUAGE plpgsql;

-- meeting_requests_expire: the worker sweep (Task 12 calls this every tick).
-- Loss-tolerant in the same spirit as the webhook ingest: a late sweep just
-- catches more rows next time, never raises.
CREATE OR REPLACE FUNCTION meeting_requests_expire() RETURNS integer AS $$
DECLARE
    v_count integer;
BEGIN
    UPDATE meeting_join_requests SET state = 'expired'
     WHERE state = 'pending' AND expires_at < now();
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$ LANGUAGE plpgsql;
