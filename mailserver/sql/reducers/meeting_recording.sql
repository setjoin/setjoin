-- meeting_recording.sql: Meet B2 — the reducer-owned recording state machine
-- (spec §3.2/§5) + the guest⇄recording exclusion arm 1 (§8.2). The SFU/Egress
-- hold no authority (DES-011): state commits BEFORE any Egress call (consent
-- banner precedes the first captured frame), and every transition out of
-- 'active' is completed by an Egress API call in Go (law 1).
--
--
-- BZ block (meet B2 = BZ199-200, this file's slice): BZ199 guest⇄recording
-- exclusion (arm 1 here; arm 2 lives in meeting_admit); BZ200 recording
-- state conflict. BZ185/186/190 reused from the B1 block.

-- meeting_recording_active: the ONE envelope/banner predicate (read by
-- meeting_get, the lobby poll, this file's arms, and — since the M4
-- semantic slice — meeting_semantic_recording_start's single-primary-mode
-- gate). SECURITY DEFINER on purpose: meeting_recordings AND
-- meeting_semantic_recordings are FORCE-RLS scoped, and the consent banner
-- must be truthful for callers who are NOT yet participants (a member on
-- the prejoin screen, a guest on the public poll) — an invoker-rights read
-- would fail OPEN for exactly those callers at the native-RLS flip.
-- M4 (V266): "all modes extend the same recording-active predicate" — a
-- live semantic recording counts here too, so every consumer of this
-- predicate (banner, guest-admit BZ199 arm, B2 start's BZ200 arm) sees ONE
-- recording truth across the B2 RoomComposite and M4 semantic modes, and
-- the single-primary-mode invariant holds in both directions.
CREATE OR REPLACE FUNCTION meeting_recording_active(p_meeting_id bigint)
RETURNS boolean LANGUAGE sql SECURITY DEFINER STABLE SET search_path = public AS $$
    SELECT EXISTS (SELECT 1 FROM public.meeting_recordings
                    WHERE meeting_id = p_meeting_id
                      AND state IN ('requested', 'active', 'stopping'))
        OR EXISTS (SELECT 1 FROM public.meeting_semantic_recordings
                    WHERE meeting_id = p_meeting_id
                      AND rec_state = 'active')
$$;
SELECT apply_worker_ownership('meeting_recording_active(bigint)'::regprocedure);

-- meeting_recording_start: host/cohost, live meeting, no in-flight recording,
-- and — the §8.2 invariant, arm 1 — no guest ADMISSION. Opens with the
-- explicit row lock BOTH arms serialize on. FOR UPDATE (not FOR NO KEY
-- UPDATE) deliberately: it also conflicts with the FOR KEY SHARE a
-- participant-row FK insert takes on the meeting row, so even a future admit
-- path that forgot the explicit lock still serializes against this (D4).
CREATE OR REPLACE FUNCTION meeting_recording_start(
    p_user_id bigint, p_meeting_id bigint
) RETURNS bigint AS $$
DECLARE
    v_state  text;
    v_rec_id bigint;
BEGIN
    SELECT state INTO v_state FROM meetings WHERE id = p_meeting_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'meeting % not found', p_meeting_id
            USING ERRCODE='BZ185', HINT='{"type":"notFound"}';
    END IF;
    PERFORM meeting_require_authority(p_meeting_id, p_user_id);
    IF v_state = 'ended' THEN
        RAISE EXCEPTION 'meeting % has ended', p_meeting_id
            USING ERRCODE='BZ190', HINT='{"type":"conflict","detail":"meeting has ended"}';
    END IF;
    IF v_state <> 'live' THEN
        RAISE EXCEPTION 'meeting % is not live', p_meeting_id
            USING ERRCODE='BZ200', HINT='{"type":"conflict","detail":"meeting is not live"}';
    END IF;
    IF meeting_recording_active(p_meeting_id) THEN
        RAISE EXCEPTION 'meeting % is already being recorded', p_meeting_id
            USING ERRCODE='BZ200', HINT='{"type":"conflict","detail":"already recording"}';
    END IF;
    -- §8.2 arm 1 — the ADMISSION fact, not the webhook-fed joined_at: an
    -- admitted-but-not-yet-joined guest must already block start (the review
    -- Critical). left_at is webhook-fed too, but it fails CLOSED — a lost
    -- participant_left blocks start until kick/reconcile clears it (D4's
    -- accepted direction). joined_at is deliberately ABSENT from this WHERE.
    IF EXISTS (SELECT 1 FROM meeting_participants
                WHERE meeting_id = p_meeting_id AND role = 'guest'
                  AND left_at IS NULL AND banned_at IS NULL) THEN
        RAISE EXCEPTION 'guests are admitted to meeting %; recording is blocked', p_meeting_id
            USING ERRCODE='BZ199',
                  HINT='{"type":"forbidden","detail":"kick or wait out admitted guests before recording"}';
    END IF;

    INSERT INTO meeting_recordings (meeting_id, started_by)
      VALUES (p_meeting_id, p_user_id)
      RETURNING id INTO v_rec_id;

    -- The banner fact: pushed from 'requested', BEFORE Go ever calls Egress
    -- (§3.2 — a failed Egress call rolls it back via bind_egress p_ok=false).
    PERFORM notify_meet_state(p_meeting_id, 'recording_state',
        jsonb_build_object('recordingId', v_rec_id, 'state', 'requested'));
    RETURN v_rec_id;
END;
$$ LANGUAGE plpgsql;

-- meeting_recording_bind_egress: Go's post-Egress-call confirmation.
-- requested → active (+egress_id +staging_key — OURS, composed by Go into
-- the StartRoomComposite request, spec §4) or → failed (+banner-off push
-- carrying the reason, so an egress_busy start reads distinguishably on the
-- client too). Idempotent: re-binding the same egress id to an already-
-- active row is a no-op (a Go retry after a lost response must not BZ200).
CREATE OR REPLACE FUNCTION meeting_recording_bind_egress(
    p_recording_id bigint, p_egress_id text, p_staging_key text,
    p_ok boolean, p_error text
) RETURNS void AS $$
DECLARE
    v_rec RECORD;
BEGIN
    SELECT id, meeting_id, state, egress_id INTO v_rec
      FROM meeting_recordings WHERE id = p_recording_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'recording % not found', p_recording_id
            USING ERRCODE='BZ200', HINT='{"type":"conflict","detail":"recording not found"}';
    END IF;
    IF v_rec.state = 'active' AND v_rec.egress_id = p_egress_id THEN
        RETURN;  -- idempotent re-bind
    END IF;
    IF v_rec.state <> 'requested' THEN
        RAISE EXCEPTION 'recording % is not awaiting an egress bind (state %)', p_recording_id, v_rec.state
            USING ERRCODE='BZ200', HINT='{"type":"conflict","detail":"recording is not in requested state"}';
    END IF;

    IF COALESCE(p_ok, false) THEN
        UPDATE meeting_recordings
           SET state = 'active', egress_id = p_egress_id, staging_key = p_staging_key
         WHERE id = p_recording_id;
        PERFORM notify_meet_state(v_rec.meeting_id, 'recording_state',
            jsonb_build_object('recordingId', p_recording_id, 'state', 'active'));
    ELSE
        UPDATE meeting_recordings
           SET state = 'failed', stopped_at = now(),
               error = COALESCE(p_error, 'egress start failed')
         WHERE id = p_recording_id;
        PERFORM notify_meet_state(v_rec.meeting_id, 'recording_state',
            jsonb_build_object('recordingId', p_recording_id, 'state', 'failed',
                               'error', COALESCE(p_error, 'egress start failed')));
    END IF;
END;
$$ LANGUAGE plpgsql;

-- meeting_recording_stop: host/cohost; active → stopping; returns the ids Go
-- needs for StopEgress. BZ200 when nothing is active ('requested' rows are
-- the worker's 2-minute-grace problem, not the stop button's).
CREATE OR REPLACE FUNCTION meeting_recording_stop(
    p_user_id bigint, p_meeting_id bigint
) RETURNS jsonb AS $$
DECLARE
    v_rec RECORD;
BEGIN
    PERFORM meeting_require_authority(p_meeting_id, p_user_id);
    SELECT id, egress_id INTO v_rec
      FROM meeting_recordings
     WHERE meeting_id = p_meeting_id AND state = 'active'
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no active recording on meeting %', p_meeting_id
            USING ERRCODE='BZ200', HINT='{"type":"conflict","detail":"no active recording"}';
    END IF;

    UPDATE meeting_recordings SET state = 'stopping' WHERE id = v_rec.id;
    -- Truthful lifecycle (design D-1): the row IS 'stopping', so that is what
    -- the push says — clients keep the banner ON for requested|active|stopping
    -- (copy may switch to a "stopping" line). 'stopped' is pushed only when
    -- the fact lands (the egress_ended → pending_ingest arm below), so the
    -- push rail and the envelope predicate (meeting_recording_active counts
    -- 'stopping') can never disagree: no window where the in-room banner is
    -- dark while a joiner's envelope still says active.
    PERFORM notify_meet_state(p_meeting_id, 'recording_state',
        jsonb_build_object('recordingId', v_rec.id, 'state', 'stopping'));
    RETURN jsonb_build_object('recordingId', v_rec.id, 'egressId', v_rec.egress_id);
END;
$$ LANGUAGE plpgsql;

-- meeting_recording_event: the FACT rail (law 2 — the verbatim
-- meeting_participant_event contract). Called ONLY from the webhook receiver
-- (the APP pool, internal/meet/webhook.go — no caller GUC) and the worker's
-- reconcile legs; never raises: unknown room/egress, replayed event,
-- out-of-order delivery — all silent no-ops. p_info is the
-- protojson-marshaled EgressInfo: enums are NAMES ("EGRESS_COMPLETE"),
-- int64s are STRINGS, keys are camelCase (fileResults, egressId).
-- SECURITY DEFINER + worker-owned (V134 / native-RLS W4 wave): same
-- rationale, precedent, and search_path pin as meeting_participant_event —
-- a GUC-less webhook surface no invoker-rights policy can admit; self-scoped
-- by the server-resolved room_name+egress_id pair.
CREATE OR REPLACE FUNCTION meeting_recording_event(
    p_room_name uuid, p_egress_id text, p_event text, p_info jsonb DEFAULT NULL
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    v_rec    RECORD;
    v_status text;
BEGIN
    -- F4: FOR UPDATE OF r serializes a concurrent real webhook against a
    -- synthetic worker-reconcile event for the same egress_id — without it,
    -- look-then-act lets the second caller clobber the first's write
    -- instead of blocking behind it (r only, not m: avoids cross-locking
    -- the meetings row other flows already lock via a different order).
    SELECT r.id, r.meeting_id, r.state INTO v_rec
      FROM meeting_recordings r
      JOIN meetings m ON m.id = r.meeting_id
     WHERE r.egress_id = p_egress_id AND m.room_name = p_room_name
       FOR UPDATE OF r;
    IF NOT FOUND THEN
        RETURN;  -- unknown egress/room pair: webhook noise, or a pre-bind race — the reconcile sweep self-heals
    END IF;

    IF p_event = 'egress_started' THEN
        -- confirm only: requested→active is normally Go's bind; a webhook
        -- landing first (or after a terminal state) changes nothing.
        RETURN;

    ELSIF p_event = 'egress_updated' THEN
        RETURN;

    ELSIF p_event = 'egress_ended' THEN
        IF v_rec.state IN ('pending_ingest', 'ready', 'failed') THEN
            RETURN;  -- replay against a settled row
        END IF;
        v_status := COALESCE(p_info->>'status', '');
        IF v_status IN ('EGRESS_COMPLETE', 'EGRESS_LIMIT_REACHED') THEN
            -- payload only CONFIRMS size/duration; staging_key was persisted
            -- at bind (spec §4) and is never read from this payload.
            UPDATE meeting_recordings
               SET state       = 'pending_ingest',
                   stopped_at  = COALESCE(stopped_at, now()),
                   size_bytes  = NULLIF(p_info->'fileResults'->0->>'size', '')::bigint,
                   duration_ms = NULLIF(p_info->'fileResults'->0->>'duration', '')::bigint / 1000000
             WHERE id = v_rec.id;
            -- D-1: THIS is where 'stopped' is true — the banner-off push
            -- (the failed arm below already pushes its own banner-off).
            PERFORM notify_meet_state(v_rec.meeting_id, 'recording_state',
                jsonb_build_object('recordingId', v_rec.id, 'state', 'stopped'));
        ELSE
            UPDATE meeting_recordings
               SET state = 'failed', stopped_at = COALESCE(stopped_at, now()),
                   error = COALESCE(NULLIF(p_info->>'error', ''), 'egress ended ' || v_status)
             WHERE id = v_rec.id;
            PERFORM notify_meet_state(v_rec.meeting_id, 'recording_state',
                jsonb_build_object('recordingId', v_rec.id, 'state', 'failed'));
        END IF;
    END IF;
    -- any other p_event: silent no-op (untrusted, unversioned input).
END;
$$;
SELECT apply_worker_ownership('meeting_recording_event(uuid,text,text,jsonb)'::regprocedure);

-- meeting_recording_ingested: the worker's finalize, called INSIDE the one
-- ingest transaction (spec §3.4) — node/version land atomically with ready.
CREATE OR REPLACE FUNCTION meeting_recording_ingested(
    p_recording_id bigint, p_node_id bigint, p_version_id bigint
) RETURNS void AS $$
DECLARE
    v_rec RECORD;
BEGIN
    SELECT id, meeting_id, state, file_node_id INTO v_rec
      FROM meeting_recordings WHERE id = p_recording_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'recording % not found', p_recording_id
            USING ERRCODE='BZ200', HINT='{"type":"conflict","detail":"recording not found"}';
    END IF;
    IF v_rec.state = 'ready' AND v_rec.file_node_id = p_node_id THEN
        RETURN;  -- idempotent replay of a committed ingest
    END IF;
    IF v_rec.state <> 'pending_ingest' THEN
        RAISE EXCEPTION 'recording % is not pending ingest (state %)', p_recording_id, v_rec.state
            USING ERRCODE='BZ200', HINT='{"type":"conflict","detail":"recording is not pending ingest"}';
    END IF;

    UPDATE meeting_recordings
       SET state = 'ready', file_node_id = p_node_id, version_id = p_version_id
     WHERE id = p_recording_id;
    PERFORM notify_meet_state(v_rec.meeting_id, 'recording_ready',
        jsonb_build_object('recordingId', p_recording_id));
END;
$$ LANGUAGE plpgsql;
