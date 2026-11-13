-- meeting_local_capture.sql — MEET plan M5 slice 2: the Electron
-- local-first capture lease + truthful local-package registration
-- (retired-docs:superpowers/plans/2026-08-25-meet-document-presentation-semantic-
-- recording.md, M5), over the V268 lease table and the frozen contracts in
-- mailserver/internal/meet/presentation/ (acquisition.go CaptureLease,
-- policy.go InvariantLeaseAfterReducerCommit + FailCaptureLeaseExpired,
-- segment.go's segment binding contract) and the slice-1 client substrate
-- in clients/desktop/electron/src/meet/ (sjrec-local-v1 descriptor,
-- meet-local-heartbeat-v1 frames).
--
-- Authority model (DES-011, unchanged): the Electron capture is a
-- PERIPHERAL. The lease exists because policy.go's invariants say every
-- capture runs under a reducer-issued authority committed BEFORE capture
-- begins: the local_registered meeting_semantic_recordings row (banner +
-- single-primary-mode + BZ199 guest arm, all reused from
-- meeting_semantic_recording_start) commits first, then the lease. The
-- client's consent machine is the start GATE on the wire; the server's
-- authority floor (host/cohost via the recording start) is the state rail.
--
-- USER plane (p_user_id authenticated, GUC-scoped by the gateway):
--   · meeting_local_capture_lease_acquire  — reducer-commit-before-capture:
--     starts (or idempotently reattaches to) the meeting's live
--     local_registered semantic recording and mints the lease.
--   · meeting_local_capture_lease_heartbeat — the keepalive: refreshes
--     expiry, records honest liveness facts, enforces monotonic seq.
--   · meeting_local_capture_lease_stop     — revocation/user stop: stops
--     the lease AND its recording in the same txn.
--   · meeting_local_capture_register       — truthful local-package
--     registration: stores the sealed sjrec-local-v1 descriptor's receipt
--     and binds every segment through the EXISTING worker-contract ingest
--     (meeting_semantic_segment_ingest — same rules, same overlap belt,
--     same BZ279), never a second segment writer.
-- WORKER plane (SECURITY DEFINER + apply_worker_ownership — the GUC-less
-- drain surface): meeting_local_capture_lease_expire — the lazy/sweepable
-- expiry arm: a lease past its TTL is 'expired' and its recording is
-- stopped truthfully (segments the device never registered stay
-- unregistered — never synthesized).
--
-- The registration is TRUTHFUL BY CONSTRUCTION: a local_registered package
-- is local_only (V266) and exports nothing centrally (BZ281 local_only);
-- registration stores the descriptor's sealed integrity digest as a
-- RECEIPT, never a claim of retained central bytes. Shape admission is
-- Go's (internal/meet/localcapture.go re-derives the canonical-JSON seal,
-- re-validates every segment through presentation.MediaSegment.Validate
-- and re-computes coverage through presentation.ComputeCoverage); the
-- reducer re-refuses only shapes that could not have passed any admission
-- (the _meeting_semantic_profile_shape precedent).
--
-- BZ block (meet M5 = BZ282-284, this file's slice; sole registration site
-- for the Go surface is internal/meet/errors.go + reducererr.codeClass):
--   BZ282 local capture lease conflict — unknown lease, a lease foreign to
--         the caller, a stale lease generation. An expired lease is NOT
--         this code: the heartbeat arm meets it with the truthful stop
--         FACT (stop:true, reason expired), and a stop against a terminal
--         lease replays its stop fact truthfully (alreadyStopped).
--   BZ283 local capture invalid — malformed acquire/heartbeat/stop shapes:
--         device id out of bounds, unknown surface, heartbeat cadence out
--         of range, a seq regression, a register against a capture that
--         has not stopped.
--   BZ284 local package registration not admitted — an untruthful
--         sjrec-local-v1 descriptor: schema drift, a capturing segment in
--         a sealed package, a verified segment without its
--         digest+size+MIME/codec/container proof, an interrupted/failed
--         segment without its reason, a claimed upload path, coverage or
--         identity drift, an over-cap segment count, a conflicting
--         re-registration. (Admitted-path semantics, the BZ277 genre.)

-- ── private helpers ──────────────────────────────────────────────────────

-- _meeting_local_surfaces_ok: the lease's surfaces are the preflight's
-- CaptureSurfaceId set — non-empty, no duplicates, never a video surface.
CREATE OR REPLACE FUNCTION _meeting_local_surfaces_ok(p_surfaces jsonb)
RETURNS boolean AS $$
BEGIN
    IF p_surfaces IS NULL OR jsonb_typeof(p_surfaces) <> 'array' THEN
        RETURN false;
    END IF;
    IF jsonb_array_length(p_surfaces) NOT BETWEEN 1 AND 2 THEN
        RETURN false;
    END IF;
    IF EXISTS (SELECT 1 FROM jsonb_array_elements_text(p_surfaces) s
                WHERE s NOT IN ('microphone','systemAudio')) THEN
        RETURN false;
    END IF;
    IF (SELECT count(*) FROM jsonb_array_elements_text(p_surfaces) s)
       <> (SELECT count(DISTINCT s) FROM jsonb_array_elements_text(p_surfaces) s) THEN
        RETURN false;
    END IF;
    RETURN true;
END;
$$ LANGUAGE plpgsql;

-- _meeting_local_lease_lock: the newest lease generation for (meeting,
-- recording), FOR UPDATE. Unknown pair is one indistinguishable BZ282.
CREATE OR REPLACE FUNCTION _meeting_local_lease_lock(
    p_meeting_id bigint, p_recording_id bigint
) RETURNS meeting_local_capture_leases AS $$
DECLARE
    v_lease meeting_local_capture_leases;
BEGIN
    SELECT * INTO v_lease
      FROM meeting_local_capture_leases
     WHERE meeting_id = p_meeting_id AND recording_id = p_recording_id
     ORDER BY generation DESC
       FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no capture lease for recording % on meeting %', p_recording_id, p_meeting_id
            USING ERRCODE='BZ282', HINT='{"type":"notFound"}';
    END IF;
    RETURN v_lease;
END;
$$ LANGUAGE plpgsql;

-- _meeting_local_require_owner_or_host: the lease's device owner (the user
-- whose acquire minted it — auth context, never a request field, R2) or the
-- live host/cohost floor may steer the lease.
CREATE OR REPLACE FUNCTION _meeting_local_require_owner_or_host(
    p_meeting_id bigint, p_user_id bigint, p_started_by bigint
) RETURNS void AS $$
BEGIN
    IF p_user_id = p_started_by THEN
        RETURN;
    END IF;
    IF COALESCE(meeting_require_authority(p_meeting_id, p_user_id), '')
       NOT IN ('host', 'cohost') THEN
        RAISE EXCEPTION 'the capturing device owner or meeting authority is required for meeting %', p_meeting_id
            USING ERRCODE='BZ186', HINT='{"type":"forbidden"}';
    END IF;
END;
$$ LANGUAGE plpgsql;

-- _meeting_local_stop_lease: the ONE terminal-flip writer (live → stopped
-- with its named reason) plus the recording stop in the SAME txn — the M4
-- stop arm's shape, so the banner truth (meeting_recording_active) and the
-- lease can never disagree. Caller holds the lease row lock.
CREATE OR REPLACE FUNCTION _meeting_local_stop_lease(
    p_lease meeting_local_capture_leases, p_stop_reason text
) RETURNS void AS $$
BEGIN
    UPDATE meeting_local_capture_leases
       SET lease_state = 'stopped', stop_reason = p_stop_reason,
           stopped_at = now(), updated_at = now()
     WHERE id = p_lease.id;
    UPDATE meeting_semantic_recordings
       SET rec_state = 'stopped', stopped_at = now(), updated_at = now()
     WHERE id = p_lease.recording_id AND rec_state = 'active';
    PERFORM notify_meet_state(p_lease.meeting_id, 'recording_state',
        jsonb_build_object('recordingId', p_lease.recording_id,
                           'state', 'stopped', 'mode', 'semantic',
                           'lease', jsonb_build_object(
                               'generation', p_lease.generation,
                               'stopReason', p_stop_reason)));
END;
$$ LANGUAGE plpgsql;

-- ── meeting_local_capture_lease_acquire ──────────────────────────────────
-- Reducer-commit-before-capture (policy.go): the local_registered semantic
-- recording starts FIRST (meeting_semantic_recording_start reuses every
-- fence: BZ185/BZ186/BZ190/BZ200, the BZ199 guest arm, the BZ278
-- single-primary-mode invariant, the recording_state banner push), then
-- the lease mints under it. An existing LIVE lease for (meeting, device)
-- whose recording is still active reattaches idempotently (crash
-- recovery — the same capture authority returns, never a twin); one whose
-- recording died flips 'recording_ended' and a fresh generation mints.
-- p_heartbeat_seconds is the client's proposed cadence, server-clamped to
-- 5..60 (default 10 — the slice-1 HEARTBEAT_INTERVAL_MS); the server TTL
-- is 3 × cadence: it may tighten the deadline, never loosen the client's
-- own stall stop.
CREATE OR REPLACE FUNCTION meeting_local_capture_lease_acquire(
    p_user_id bigint, p_meeting_id bigint, p_device_id text,
    p_surfaces jsonb, p_producer jsonb,
    p_heartbeat_seconds integer DEFAULT 10
) RETURNS jsonb AS $$
DECLARE
    v_existing   meeting_local_capture_leases;
    v_recording  meeting_semantic_recordings;
    v_rec_id     bigint;
    v_lease      meeting_local_capture_leases;
    v_generation bigint;
    v_seconds    integer := COALESCE(p_heartbeat_seconds, 10);
BEGIN
    IF p_device_id IS NULL OR length(p_device_id) NOT BETWEEN 1 AND 256 THEN
        RAISE EXCEPTION 'device id must be 1..256 characters'
            USING ERRCODE='BZ283', HINT='{"type":"unprocessable","detail":"deviceId"}';
    END IF;
    IF NOT _meeting_local_surfaces_ok(p_surfaces) THEN
        RAISE EXCEPTION 'surfaces must be a non-empty set of microphone/systemAudio'
            USING ERRCODE='BZ283', HINT='{"type":"unprocessable","detail":"surfaces"}';
    END IF;
    IF p_producer IS NULL OR jsonb_typeof(p_producer) <> 'object'
       OR COALESCE(p_producer->>'platform','') = ''
       OR COALESCE(p_producer->>'captureApiVersion','') = '' THEN
        RAISE EXCEPTION 'producer identity must pin platform and captureApiVersion'
            USING ERRCODE='BZ283', HINT='{"type":"unprocessable","detail":"producer"}';
    END IF;
    IF v_seconds NOT BETWEEN 5 AND 60 THEN
        RAISE EXCEPTION 'heartbeat cadence must be 5..60 seconds'
            USING ERRCODE='BZ283', HINT='{"type":"unprocessable","detail":"heartbeatSeconds"}';
    END IF;

    -- Idempotent reattach: the SAME (meeting, device) live lease whose
    -- recording still runs is THE capture authority (crash recovery).
    SELECT * INTO v_existing
      FROM meeting_local_capture_leases
     WHERE meeting_id = p_meeting_id AND device_id = p_device_id
       AND lease_state = 'live'
     ORDER BY generation DESC LIMIT 1
       FOR UPDATE;
    IF FOUND THEN
        SELECT * INTO v_recording FROM meeting_semantic_recordings
         WHERE id = v_existing.recording_id FOR UPDATE;
        IF FOUND AND v_recording.rec_state = 'active'
           AND v_recording.capture_mode = 'local_registered' THEN
            RETURN jsonb_build_object(
                'recordingId', v_existing.recording_id,
                'meetingId', v_existing.meeting_id,
                'leaseGeneration', v_existing.generation,
                'expiresAtUnixMs', (EXTRACT(EPOCH FROM v_existing.expires_at) * 1000)::bigint,
                'heartbeatSeconds', v_existing.heartbeat_seconds,
                'reattached', true);
        END IF;
        -- The lease outlived its recording (a foreign stop path): belt it
        -- terminal — the name is the observable fact, never a user claim.
        PERFORM _meeting_local_stop_lease(v_existing, 'recording_ended');
    END IF;

    -- The fence chain rides the M4 start verbatim (its profile records the
    -- honest evidence_pending class for the SERVER-audio qualification
    -- contract; the local producer identity rides the lease row itself).
    v_rec_id := meeting_semantic_recording_start(
        p_user_id, p_meeting_id, 'local_registered',
        jsonb_build_object('class', 'evidence_pending',
                           'producerId', p_producer->>'platform',
                           'producerVersion', p_producer->>'captureApiVersion'));

    SELECT COALESCE(MAX(generation), 0) + 1 INTO v_generation
      FROM meeting_local_capture_leases
     WHERE meeting_id = p_meeting_id AND device_id = p_device_id;

    INSERT INTO meeting_local_capture_leases
         (meeting_id, recording_id, device_id, lease_state, generation,
          surfaces, producer, heartbeat_seconds, expires_at, started_by)
    VALUES (p_meeting_id, v_rec_id, p_device_id, 'live', v_generation,
            p_surfaces, p_producer, v_seconds,
            now() + make_interval(secs => v_seconds * 3), p_user_id)
    RETURNING * INTO v_lease;

    RETURN jsonb_build_object(
        'recordingId', v_lease.recording_id,
        'meetingId', v_lease.meeting_id,
        'leaseGeneration', v_lease.generation,
        'expiresAtUnixMs', (EXTRACT(EPOCH FROM v_lease.expires_at) * 1000)::bigint,
        'heartbeatSeconds', v_lease.heartbeat_seconds,
        'reattached', false);
END;
$$ LANGUAGE plpgsql;

-- ── meeting_local_capture_lease_heartbeat ────────────────────────────────
-- The keepalive. Honesty rules (the slice-1 wire contract): frames are
-- numbered monotonically from 1 and never fabricated — an exact replay of
-- the last frame (a lost response retried) refreshes the SAME deadline; a
-- seq REGRESSION is BZ283 (reordered/fabricated history fails closed); a
-- stale lease generation is BZ282. An expired lease is met with the stop
-- FACT (stop:true) after it is flipped expired and its recording stopped
-- — never with a refreshed deadline. A final captureState='stopped' frame
-- stops the lease truthfully (reason device_stopped).
CREATE OR REPLACE FUNCTION meeting_local_capture_lease_heartbeat(
    p_user_id bigint, p_meeting_id bigint, p_recording_id bigint,
    p_lease_generation bigint, p_seq bigint,
    p_capture_state text DEFAULT 'capturing',
    p_disk_free_bytes bigint DEFAULT NULL
) RETURNS jsonb AS $$
DECLARE
    v_lease meeting_local_capture_leases;
    v_ttl   interval;
BEGIN
    IF p_capture_state NOT IN ('capturing','stopping','stopped') THEN
        RAISE EXCEPTION 'unknown capture state %', p_capture_state
            USING ERRCODE='BZ283', HINT='{"type":"unprocessable","detail":"captureState"}';
    END IF;
    IF p_seq IS NULL OR p_seq < 1 THEN
        RAISE EXCEPTION 'heartbeat sequence numbers from 1'
            USING ERRCODE='BZ283', HINT='{"type":"unprocessable","detail":"seq"}';
    END IF;

    v_lease := _meeting_local_lease_lock(p_meeting_id, p_recording_id);
    IF v_lease.started_by <> p_user_id THEN
        -- A lease is device-private: a stranger gets the indistinguishable
        -- not-found (the semantic read posture), never lease facts.
        RAISE EXCEPTION 'no capture lease for recording % on meeting %', p_recording_id, p_meeting_id
            USING ERRCODE='BZ282', HINT='{"type":"notFound"}';
    END IF;
    IF v_lease.lease_state <> 'live' THEN
        -- Already terminal: the truthful stop fact, not an exception (the
        -- device's stop evaluator consumes exactly this shape). An
        -- expired row carries no stop_reason — its state IS the reason.
        RETURN jsonb_build_object('stop', true,
                                  'stopReason', COALESCE(v_lease.stop_reason, v_lease.lease_state),
                                  'leaseGeneration', v_lease.generation,
                                  'recordingState', 'stopped');
    END IF;
    IF p_lease_generation IS NULL OR p_lease_generation <> v_lease.generation THEN
        RAISE EXCEPTION 'lease generation % is stale (current %)', p_lease_generation, v_lease.generation
            USING ERRCODE='BZ282',
                  HINT='{"type":"conflict","detail":"stale lease generation"}';
    END IF;

    -- Meeting-end belt (the meeting_end same-txn arm is the primary): if
    -- the meeting died without the arm reaching this lease, stop now.
    IF (SELECT state FROM meetings WHERE id = p_meeting_id) <> 'live' THEN
        PERFORM _meeting_local_stop_lease(v_lease, 'meeting_ended');
        RETURN jsonb_build_object('stop', true, 'stopReason', 'meeting_ended',
                                  'leaseGeneration', v_lease.generation,
                                  'recordingState', 'stopped');
    END IF;

    -- Expiry: a live lease past its TTL is dead. Flip + stop + report.
    IF v_lease.expires_at <= now() THEN
        UPDATE meeting_local_capture_leases
           SET lease_state = 'expired', stopped_at = now(), updated_at = now()
         WHERE id = v_lease.id;
        UPDATE meeting_semantic_recordings
           SET rec_state = 'stopped', stopped_at = now(), updated_at = now()
         WHERE id = v_lease.recording_id AND rec_state = 'active';
        PERFORM notify_meet_state(p_meeting_id, 'recording_state',
            jsonb_build_object('recordingId', p_recording_id,
                               'state', 'stopped', 'mode', 'semantic',
                               'lease', jsonb_build_object(
                                   'generation', v_lease.generation,
                                   'stopReason', 'expired')));
        RETURN jsonb_build_object('stop', true, 'stopReason', 'expired',
                                  'leaseGeneration', v_lease.generation,
                                  'recordingState', 'stopped');
    END IF;

    -- Monotonic seq: an exact replay of the last frame is the lost-response
    -- retry (refresh kindly); a regression is fabricated history.
    IF v_lease.last_seq IS NOT NULL AND p_seq < v_lease.last_seq THEN
        RAISE EXCEPTION 'heartbeat seq % regresses below committed seq %', p_seq, v_lease.last_seq
            USING ERRCODE='BZ283',
                  HINT='{"type":"conflict","detail":"heartbeat sequence regression"}';
    END IF;

    v_ttl := make_interval(secs => v_lease.heartbeat_seconds * 3);
    UPDATE meeting_local_capture_leases
       SET last_seq = p_seq, last_seen_at = now(),
           last_disk_free_bytes = p_disk_free_bytes,
           expires_at = now() + v_ttl, updated_at = now()
     WHERE id = v_lease.id;

    -- The final stopped frame: the capture ended cleanly on the device.
    IF p_capture_state = 'stopped' THEN
        PERFORM _meeting_local_stop_lease(v_lease, 'device_stopped');
        RETURN jsonb_build_object('stop', true, 'stopReason', 'device_stopped',
                                  'leaseGeneration', v_lease.generation,
                                  'recordingState', 'stopped');
    END IF;

    RETURN jsonb_build_object('stop', false,
                              'leaseGeneration', v_lease.generation,
                              'seq', p_seq,
                              'expiresAtUnixMs',
                              (EXTRACT(EPOCH FROM (now() + v_ttl)) * 1000)::bigint);
END;
$$ LANGUAGE plpgsql;

-- ── meeting_local_capture_lease_stop ─────────────────────────────────────
-- The revocation/user stop: the device owner (auth context) or the live
-- host/cohost floor stops the lease AND its recording in the same txn.
-- Idempotent: an already-terminal lease replays its stop fact. An unknown
-- lease is the indistinguishable BZ282.
CREATE OR REPLACE FUNCTION meeting_local_capture_lease_stop(
    p_user_id bigint, p_meeting_id bigint, p_recording_id bigint,
    p_lease_generation bigint DEFAULT NULL,
    p_reason text DEFAULT 'user_stop'
) RETURNS jsonb AS $$
DECLARE
    v_lease meeting_local_capture_leases;
BEGIN
    IF COALESCE(p_reason, '') NOT IN ('user_stop','revoked') THEN
        RAISE EXCEPTION 'a lease stop names user_stop or revoked'
            USING ERRCODE='BZ283', HINT='{"type":"unprocessable","detail":"reason"}';
    END IF;

    v_lease := _meeting_local_lease_lock(p_meeting_id, p_recording_id);
    PERFORM _meeting_local_require_owner_or_host(p_meeting_id, p_user_id, v_lease.started_by);

    IF v_lease.lease_state <> 'live' THEN
        RETURN jsonb_build_object('recordingId', p_recording_id,
                                  'leaseGeneration', v_lease.generation,
                                  'leaseState', v_lease.lease_state,
                                  'stopReason', v_lease.stop_reason,
                                  'alreadyStopped', true);
    END IF;
    IF p_lease_generation IS NOT NULL AND p_lease_generation <> v_lease.generation THEN
        RAISE EXCEPTION 'lease generation % is stale (current %)', p_lease_generation, v_lease.generation
            USING ERRCODE='BZ282',
                  HINT='{"type":"conflict","detail":"stale lease generation"}';
    END IF;

    PERFORM _meeting_local_stop_lease(v_lease, p_reason);
    RETURN jsonb_build_object('recordingId', p_recording_id,
                              'leaseGeneration', v_lease.generation,
                              'leaseState', 'stopped',
                              'stopReason', p_reason,
                              'alreadyStopped', false);
END;
$$ LANGUAGE plpgsql;

-- ── meeting_local_capture_lease_expire ───────────────────────────────────
-- The WORKER-plane expiry arm (SECURITY DEFINER — the GUC-less drain
-- surface): every live lease past its TTL flips 'expired' and its still-
-- active recording stops truthfully, one push per recording. Bounded by
-- p_limit (default 50, the sweep-leg genre). Returns the count. A heartbeat
-- arriving after expiry meets the stop FACT (the heartbeat arm), so this
-- drain converges state; it never strands a live banner row.
CREATE OR REPLACE FUNCTION meeting_local_capture_lease_expire(
    p_limit integer DEFAULT 50
) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    v_row     RECORD;
    v_count   integer := 0;
BEGIN
    FOR v_row IN
        SELECT l.id, l.meeting_id, l.recording_id, l.generation
          FROM meeting_local_capture_leases l
         WHERE l.lease_state = 'live' AND l.expires_at <= now()
         ORDER BY l.expires_at
         LIMIT GREATEST(COALESCE(p_limit, 50), 1)
           FOR UPDATE OF l SKIP LOCKED
    LOOP
        UPDATE meeting_local_capture_leases
           SET lease_state = 'expired', stopped_at = now(), updated_at = now()
         WHERE id = v_row.id;
        UPDATE meeting_semantic_recordings
           SET rec_state = 'stopped', stopped_at = now(), updated_at = now()
         WHERE id = v_row.recording_id AND rec_state = 'active';
        PERFORM notify_meet_state(v_row.meeting_id, 'recording_state',
            jsonb_build_object('recordingId', v_row.recording_id,
                               'state', 'stopped', 'mode', 'semantic',
                               'lease', jsonb_build_object(
                                   'generation', v_row.generation,
                                   'stopReason', 'expired')));
        v_count := v_count + 1;
    END LOOP;
    RETURN v_count;
END;
$$;
SELECT apply_worker_ownership('meeting_local_capture_lease_expire(integer)'::regprocedure);

-- ── meeting_local_capture_register ───────────────────────────────────────
-- The truthful local-package registration (the sjrec-local-v1 descriptor).
-- Post-stop by nature (finalize → register), so the authority floor is the
-- HISTORICAL attendee helper: the capturing device owner (started_by) or
-- host/cohost; an absent caller gets the indistinguishable BZ278 (the
-- semantic package verbs' posture).
--
-- Reuse, not a second writer: every segment binds through the EXISTING
-- meeting_semantic_segment_ingest (the wave-4 worker-contract reducer) —
-- the same truthful-promotion rules, the same duplicate-media overlap belt,
-- the same BZ279, the same idempotent (recording, seq) re-entry. The
-- descriptor-level belt below refuses only shapes that could not have
-- passed Go's admission (localcapture.go re-derives the canonical-JSON
-- seal, re-validates every segment via presentation.MediaSegment.Validate,
-- re-computes coverage via presentation.ComputeCoverage).
--
-- The receipt, never a retention claim: registration stores the sealed
-- descriptor's integrity digest + registered_at on the local_only
-- recording row (V268 §B). A local_registered package exports nothing
-- centrally (BZ281 local_only) — the plan's "never claims unuploaded bytes
-- are retained" holds by construction.
CREATE OR REPLACE FUNCTION meeting_local_capture_register(
    p_user_id bigint, p_meeting_id bigint, p_recording_id bigint,
    p_descriptor jsonb
) RETURNS jsonb AS $$
DECLARE
    v_rec        meeting_semantic_recordings;
    v_role       text;
    v_pkg        jsonb := p_descriptor;
    v_digest     text;
    v_state      text;
    v_started    bigint;
    v_ended      bigint;
    v_segs       jsonb;
    v_n          integer;
    v_i          integer;
    v_seg        jsonb;
    v_seg_state  text;
    v_seq        integer;
    v_start_ms   bigint;
    v_end_ms     bigint;
    v_wall_start bigint;
    v_wall_end   bigint;
    v_reason     text;
BEGIN
    -- AUTHORITY FIRST (the anti-oracle posture): an absent caller gets the
    -- indistinguishable BZ278 and a non-authoritative attendee gets BZ186
    -- before the descriptor says ANYTHING about itself.
    SELECT * INTO v_rec FROM meeting_semantic_recordings
     WHERE id = p_recording_id AND meeting_id = p_meeting_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'semantic recording % not found on meeting %', p_recording_id, p_meeting_id
            USING ERRCODE='BZ278', HINT='{"type":"notFound"}';
    END IF;
    v_role := meeting_attendee_role(p_meeting_id, p_user_id);
    IF v_role IS NULL THEN
        RAISE EXCEPTION 'semantic recording % not found on meeting %', p_recording_id, p_meeting_id
            USING ERRCODE='BZ278', HINT='{"type":"notFound"}';
    END IF;
    IF v_rec.started_by <> p_user_id
       AND COALESCE(v_role, '') NOT IN ('host', 'cohost') THEN
        RAISE EXCEPTION 'the capturing device owner or meeting authority is required for meeting %', p_meeting_id
            USING ERRCODE='BZ186', HINT='{"type":"forbidden"}';
    END IF;

    IF v_pkg IS NULL OR jsonb_typeof(v_pkg) <> 'object' THEN
        RAISE EXCEPTION 'registration requires an sjrec-local-v1 descriptor object'
            USING ERRCODE='BZ284', HINT='{"type":"forbidden","detail":"descriptorShape"}';
    END IF;
    IF v_rec.capture_mode <> 'local_registered' THEN
        RAISE EXCEPTION 'recording % is %, not a local_registered capture', p_recording_id, v_rec.capture_mode
            USING ERRCODE='BZ284', HINT='{"type":"forbidden","detail":"captureMode"}';
    END IF;
    IF v_rec.rec_state <> 'stopped' THEN
        RAISE EXCEPTION 'stop the capture before registering package % (rec_state %)', p_recording_id, v_rec.rec_state
            USING ERRCODE='BZ283',
                  HINT='{"type":"conflict","detail":"stop and reconcile before register"}';
    END IF;

    -- ── The descriptor envelope belt (post-authority) ──
    IF v_pkg->>'schema' <> 'sjrec-local-v1' THEN
        RAISE EXCEPTION 'descriptor schema % is not sjrec-local-v1', COALESCE(v_pkg->>'schema','')
            USING ERRCODE='BZ284', HINT='{"type":"forbidden","detail":"schema"}';
    END IF;
    IF v_pkg->>'captureMode' <> 'local_registered' THEN
        RAISE EXCEPTION 'descriptor captureMode must be local_registered'
            USING ERRCODE='BZ284', HINT='{"type":"forbidden","detail":"captureMode"}';
    END IF;
    IF COALESCE(v_pkg->>'uploadedToDrive', 'true') <> 'false' THEN
        RAISE EXCEPTION 'descriptor claims an upload path that does not exist'
            USING ERRCODE='BZ284', HINT='{"type":"forbidden","detail":"uploadedToDrive"}';
    END IF;
    IF COALESCE(v_pkg->>'meetingId', '') <> p_meeting_id::text THEN
        RAISE EXCEPTION 'descriptor binds meeting %, not %', v_pkg->>'meetingId', p_meeting_id
            USING ERRCODE='BZ284', HINT='{"type":"forbidden","detail":"meetingId"}';
    END IF;

    v_digest := v_pkg->>'integrityDigest';
    IF v_digest IS NULL OR v_digest !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'descriptor carries no sealed integrity digest'
            USING ERRCODE='BZ284', HINT='{"type":"forbidden","detail":"integrityDigest"}';
    END IF;

    -- Idempotent registration: the SAME sealed descriptor replays its
    -- receipt; a conflicting re-registration rewrites settled history.
    IF v_rec.registered_at IS NOT NULL THEN
        IF v_rec.local_descriptor_digest = v_digest THEN
            RETURN jsonb_build_object('recordingId', p_recording_id,
                                      'alreadyRegistered', true);
        END IF;
        RAISE EXCEPTION 'recording % is already registered under digest %; a conflicting descriptor fails closed',
            p_recording_id, v_rec.local_descriptor_digest
            USING ERRCODE='BZ284',
                  HINT='{"type":"conflict","detail":"registration is immutable"}';
    END IF;

    v_state := COALESCE(v_pkg->>'packageState', '');
    IF v_state NOT IN ('finalized','interrupted','registered') THEN
        RAISE EXCEPTION 'a % descriptor is not a sealed package', COALESCE(v_state, 'recording')
            USING ERRCODE='BZ284', HINT='{"type":"forbidden","detail":"packageState"}';
    END IF;
    IF v_pkg->>'startedAtUnixMs' IS NULL OR v_pkg->>'startedAtUnixMs' !~ '^[0-9]+$'
       OR (v_pkg->>'startedAtUnixMs')::bigint <= 0 THEN
        RAISE EXCEPTION 'descriptor missing its start time'
            USING ERRCODE='BZ284', HINT='{"type":"forbidden","detail":"startedAt"}';
    END IF;
    IF v_pkg->>'endedAtUnixMs' IS NULL OR v_pkg->>'endedAtUnixMs' !~ '^[0-9]+$' THEN
        RAISE EXCEPTION 'a sealed descriptor must carry its end time'
            USING ERRCODE='BZ284', HINT='{"type":"forbidden","detail":"endedAt"}';
    END IF;
    v_started := (v_pkg->>'startedAtUnixMs')::bigint;
    v_ended   := (v_pkg->>'endedAtUnixMs')::bigint;
    IF v_ended < v_started THEN
        RAISE EXCEPTION 'descriptor ends before it starts'
            USING ERRCODE='BZ284', HINT='{"type":"forbidden","detail":"endedAt"}';
    END IF;

    IF v_pkg->'surfaces' IS NULL OR NOT _meeting_local_surfaces_ok(v_pkg->'surfaces') THEN
        RAISE EXCEPTION 'descriptor surfaces must be a non-empty set of microphone/systemAudio'
            USING ERRCODE='BZ284', HINT='{"type":"forbidden","detail":"surfaces"}';
    END IF;

    v_segs := v_pkg->'segments';
    IF v_segs IS NULL OR jsonb_typeof(v_segs) <> 'array'
       OR jsonb_array_length(v_segs) NOT BETWEEN 1 AND 10000 THEN
        RAISE EXCEPTION 'descriptor segments must number 1..10000'
            USING ERRCODE='BZ284', HINT='{"type":"forbidden","detail":"segmentCap"}';
    END IF;

    v_n := jsonb_array_length(v_segs);
    FOR v_i IN 0 .. v_n - 1 LOOP
        v_seg := v_segs -> v_i;
        v_seg_state := COALESCE(v_seg->>'state', '');
        IF v_seg_state NOT IN ('verified','interrupted','failed') THEN
            -- A sealed package carries no capturing segment (the builder's
            -- finalize refuses open segments; so does the durable twin).
            RAISE EXCEPTION 'sealed descriptor segment % carries state %', COALESCE(v_seg->>'seq','?'), v_seg_state
                USING ERRCODE='BZ284', HINT='{"type":"forbidden","detail":"segmentState"}';
        END IF;
        IF v_seg->>'seq' IS NULL OR v_seg->>'seq' !~ '^[0-9]+$'
           OR (v_seg->>'seq')::integer < 1 THEN
            RAISE EXCEPTION 'segment sequence numbers from 1'
                USING ERRCODE='BZ284', HINT='{"type":"forbidden","detail":"segmentSeq"}';
        END IF;
        v_seq := (v_seg->>'seq')::integer;
        IF v_seg->>'interval' IS NULL OR jsonb_typeof(v_seg->'interval') <> 'object'
           OR v_seg->'interval'->>'startMs' IS NULL OR v_seg->'interval'->>'startMs' !~ '^[0-9]+$'
           OR v_seg->'interval'->>'endMs' IS NULL OR v_seg->'interval'->>'endMs' !~ '^[0-9]+$' THEN
            RAISE EXCEPTION 'segment % carries no truthful interval', v_seq
                USING ERRCODE='BZ284', HINT='{"type":"forbidden","detail":"segmentInterval"}';
        END IF;
        v_start_ms := (v_seg->'interval'->>'startMs')::bigint;
        v_end_ms   := (v_seg->'interval'->>'endMs')::bigint;
        IF v_end_ms <= v_start_ms THEN
            RAISE EXCEPTION 'segment % interval [%s,%s) is not a positive interval', v_seq, v_start_ms, v_end_ms
                USING ERRCODE='BZ284', HINT='{"type":"forbidden","detail":"segmentInterval"}';
        END IF;
        IF v_seg->>'wallStartUnixMs' IS NULL OR v_seg->>'wallStartUnixMs' !~ '^[0-9]+$'
           OR v_seg->>'wallEndUnixMs' IS NULL OR v_seg->>'wallEndUnixMs' !~ '^[0-9]+$' THEN
            RAISE EXCEPTION 'segment % carries no wall-clock anchors', v_seq
                USING ERRCODE='BZ284', HINT='{"type":"forbidden","detail":"segmentWall"}';
        END IF;
        v_wall_start := (v_seg->>'wallStartUnixMs')::bigint;
        v_wall_end   := (v_seg->>'wallEndUnixMs')::bigint;
        IF v_wall_end < v_wall_start THEN
            RAISE EXCEPTION 'segment % wall-clock anchors run backwards', v_seq
                USING ERRCODE='BZ284', HINT='{"type":"forbidden","detail":"segmentWall"}';
        END IF;
        v_reason := v_seg->>'interruptReason';

        IF v_seg_state = 'verified' THEN
            IF v_seg->>'contentSha256' IS NULL OR v_seg->>'contentSha256' !~ '^[0-9a-f]{64}$'
               OR v_seg->>'byteSize' IS NULL OR v_seg->>'byteSize' !~ '^[0-9]+$'
               OR (v_seg->>'byteSize')::bigint <= 0
               OR COALESCE(v_seg->>'mimeType','') = ''
               OR COALESCE(v_seg->>'codec','') = ''
               OR COALESCE(v_seg->>'container','') = '' THEN
                -- MR-01: the complete-record claim has no home without its proof.
                RAISE EXCEPTION 'verified segment % lacks its digest/size/media identity proof', v_seq
                    USING ERRCODE='BZ284',
                          HINT='{"type":"forbidden","detail":"unverified completeness claim"}';
            END IF;
            -- The registration IS the acknowledgement: the descriptor's
            -- sealed digest pins these exact segment facts (the ingest
            -- marks the row acknowledged, the same contract the worker
            -- plane satisfies with its producer ack).
            PERFORM meeting_semantic_segment_ingest(
                p_recording_id, v_seq, 'verified',
                v_seg->>'contentSha256', (v_seg->>'byteSize')::bigint,
                v_seg->>'mimeType', v_seg->>'codec', v_seg->>'container',
                v_start_ms, v_end_ms, v_wall_start, v_wall_end, NULL);
        ELSE
            IF COALESCE(v_reason, '') = '' THEN
                RAISE EXCEPTION 'segment % stopped % without a reason; partial results must be truthful', v_seq, v_seg_state
                    USING ERRCODE='BZ284',
                          HINT='{"type":"forbidden","detail":"truthful partial result required"}';
            END IF;
            IF v_seg->>'contentSha256' IS NOT NULL
               AND v_seg->>'contentSha256' !~ '^[0-9a-f]{64}$' THEN
                RAISE EXCEPTION 'segment % observed digest is not a valid sha256', v_seq
                    USING ERRCODE='BZ284', HINT='{"type":"forbidden","detail":"segmentDigest"}';
            END IF;
            -- Observed bytes ride along as OBSERVED-only (never a
            -- completeness claim): a present size must be a positive
            -- integer, or the shape could not have passed any admission.
            IF v_seg->>'byteSize' IS NOT NULL
               AND (v_seg->>'byteSize' !~ '^[0-9]+$' OR (v_seg->>'byteSize')::bigint <= 0) THEN
                RAISE EXCEPTION 'segment % observed byte size must be a positive integer', v_seq
                    USING ERRCODE='BZ284', HINT='{"type":"forbidden","detail":"segmentSize"}';
            END IF;
            PERFORM meeting_semantic_segment_ingest(
                p_recording_id, v_seq, v_seg_state,
                v_seg->>'contentSha256',
                CASE WHEN v_seg->>'byteSize' IS NOT NULL
                     THEN (v_seg->>'byteSize')::bigint ELSE NULL END,
                v_seg->>'mimeType', v_seg->>'codec', v_seg->>'container',
                v_start_ms, v_end_ms, v_wall_start, v_wall_end, v_reason);
        END IF;
    END LOOP;

    -- The receipt: the sealed digest + when registration happened, on the
    -- local_only row. Package_state stays ACTIVE — the delete/hold
    -- lifecycle (V266) keeps governing the central reference.
    UPDATE meeting_semantic_recordings
       SET local_descriptor_digest = v_digest,
           registered_at = now(),
           updated_at = now()
     WHERE id = v_rec.id;

    PERFORM notify_meet_state(p_meeting_id, 'semantic_package_state',
        jsonb_build_object('recordingId', p_recording_id,
                           'packageState', 'ACTIVE',
                           'localRegistered', true,
                           'descriptorDigest', v_digest));
    RETURN jsonb_build_object('recordingId', p_recording_id,
                              'registeredAt', (EXTRACT(EPOCH FROM now()) * 1000)::bigint,
                              'descriptorDigest', v_digest,
                              'segmentCount', v_n,
                              'alreadyRegistered', false);
END;
$$ LANGUAGE plpgsql;
