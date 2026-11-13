-- meeting_semantic_recording.sql — MEET plan M4 slice 1: the semantic event
-- capture and replay authority (retired-docs:superpowers/plans/2026-08-25-meet-
-- document-presentation-semantic-recording.md, M4), over the frozen
-- contracts in mailserver/internal/meet/presentation/ (lifecycle.go's .sjrec
-- package machine, segment.go's segment binding contract, export.go's
-- idempotent receipts, acquisition.go's fail-closed adapter).
--
-- Authority model (DES-011, unchanged): the audio producer is a peripheral.
-- Every lifecycle-affecting fact here is reducer-owned and committed
-- atomically with its state bump, its push fact and (for the package
-- boundary) its receipt ledger. The worker NEVER writes these tables
-- directly and NEVER touches blobs.ref_count — it requests each child
-- release through the owning reducer and records the result.
--
-- Two planes, the V134/meeting_recording_event precedent:
--   · USER plane (p_user_id authenticated, GUC-scoped by the gateway):
--     start/stop, package mark-delete/hold/restore, export request. Host/
--     cohost floor via BZ186 — the LIVE helper (meeting_require_authority)
--     for the pre-end verbs (start/stop) and the HISTORICAL helper
--     (meeting_attendee_role, the post-end gate the meet DOX prescribes)
--     for the package verbs, which are post-end by nature; live-meeting
--     gates (BZ190/BZ200) on start; BZ199 guest exclusion via the SHARED
--     meeting_recording_active predicate (extended in meeting_recording.sql
--     to count live semantic rows — one recording-active truth for every
--     mode) plus this file's own start-time arm.
--   · WORKER plane (SECURITY DEFINER + apply_worker_ownership — the GUC-less
--     drain surfaces): segment ingest, child release, package finalize,
--     export claim/complete. Every one is idempotent-first: an exact replay
--     is a no-op, a stale generation fails closed.
--
-- Truthfulness contract (M4 bullet 2): a segment only ever becomes
-- 'verified' with digest+size+actual MIME/codec/container+acknowledgement
-- (MR-01: no unsupported complete-record claim); interrupted/failed rows
-- name why they stopped; verified segments can never overlap (duplicate
-- media fails closed at BZ279 here AND at the V266 trigger belt); gaps are
-- recorded absence — nothing synthesizes silence.
--
-- BZ block (meet M4 = BZ278-281, this file's slice; sole registration site
-- for the Go surface is internal/meet/errors.go):
--   BZ278 semantic recording conflict — one primary recording mode per
--         meeting (B2⇄M4), lifecycle illegal (stop/delete/restore arms),
--         completion against a settled export receipt.
--   BZ279 semantic segment ingest conflict — duplicate media interval,
--         untruthful state promotion, conflicting replay of one segment.
--   BZ280 .sjrec package delete/hold conflict — child release outside
--         DELETE_PENDING or against a stale deletion generation, a child
--         outside the expected set, delete outside ACTIVE, hold/restore
--         against DELETED, restore from a non-HELD_COMPLETE package,
--         export against a deletion-fenced package.
--   BZ281 semantic export invalid — request against a recording that never
--         captured, or a receipt whose confirmed bounds cannot be honored.

-- ── private helpers (the _meeting_presentation_* genre) ─────────────────

-- _meeting_semantic_lock: fetch the package FOR UPDATE; unknown id or a
-- package foreign to p_meeting_id is one indistinguishable BZ278.
CREATE OR REPLACE FUNCTION _meeting_semantic_lock(
    p_meeting_id bigint, p_recording_id bigint
) RETURNS meeting_semantic_recordings AS $$
DECLARE
    v_rec meeting_semantic_recordings;
BEGIN
    SELECT * INTO v_rec
      FROM meeting_semantic_recordings
     WHERE id = p_recording_id AND meeting_id = p_meeting_id
       FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'semantic recording % not found on meeting %', p_recording_id, p_meeting_id
            USING ERRCODE='BZ278', HINT='{"type":"notFound"}';
    END IF;
    RETURN v_rec;
END;
$$ LANGUAGE plpgsql;

-- _meeting_semantic_require_authority: the host/cohost floor for the
-- package verbs — deliberately the HISTORICAL role (meeting_attendee_role),
-- NOT meeting_require_authority's live meeting_member_role: delete, hold,
-- restore and export are POST-END lifecycle verbs by nature (a meeting ends
-- long before its recording is ever deleted, held or exported), and
-- meeting_end mass-stamps left_at, which makes the live helper read DEAD
-- for exactly the actor who owns the package. Same BZ186 raise, same floor,
-- the meeting_attendee_role gate the DOX prescribes for every post-end
-- surface.
CREATE OR REPLACE FUNCTION _meeting_semantic_require_authority(
    p_meeting_id bigint, p_user_id bigint
) RETURNS text AS $$
DECLARE
    v_role text;
BEGIN
    v_role := meeting_attendee_role(p_meeting_id, p_user_id);
    IF COALESCE(v_role, '') NOT IN ('host', 'cohost') THEN
        RAISE EXCEPTION 'host or cohost authority required for meeting %', p_meeting_id
            USING ERRCODE='BZ186', HINT='{"type":"forbidden"}';
    END IF;
    RETURN v_role;
END;
$$ LANGUAGE plpgsql;

-- _meeting_semantic_profile_shape: minimal reducer-side profile validation
-- (the ADMISSION gate is Go's fail-closed adapter — acquisition.go
-- AdmitCaptureProfile; the reducer only refuses records that could not
-- have passed any admission: a 'qualified' class without evidence, or
-- with an evidence reference that carries no receipt digest — the wave-1
-- B4 test-contract row 32 amendment: a plain-string EvidenceRef is not a
-- verifiable pin, so a qualified profile's evidenceRef must end
-- '#sha256=<64 hex>' exactly as the MP-AUDIO-001 evidence harness prints).
CREATE OR REPLACE FUNCTION _meeting_semantic_profile_shape(p_profile jsonb)
RETURNS void AS $$
BEGIN
    IF p_profile IS NULL THEN
        RETURN; -- evidence_pending by default
    END IF;
    IF COALESCE(p_profile->>'class', 'evidence_pending') NOT IN
       ('qualified','evidence_pending','unsupported') THEN
        RAISE EXCEPTION 'unknown capture profile class'
            USING ERRCODE='BZ276',
                  HINT='{"type":"unprocessable","detail":"profileClass"}';
    END IF;
    IF p_profile->>'class' = 'qualified'
       AND COALESCE(p_profile->>'evidenceRef', '') = '' THEN
        RAISE EXCEPTION 'qualified capture profile requires qualification evidence'
            USING ERRCODE='BZ276',
                  HINT='{"type":"unprocessable","detail":"profileEvidence"}';
    END IF;
    IF p_profile->>'class' = 'qualified'
       AND COALESCE(p_profile->>'evidenceRef', '')
           !~ '^[^#\s]+#sha256=[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'qualified capture profile evidence must be a digest-bearing reference (<path>#sha256=<64 hex>)'
            USING ERRCODE='BZ276',
                  HINT='{"type":"unprocessable","detail":"profileEvidenceDigest"}';
    END IF;
END;
$$ LANGUAGE plpgsql;

-- _meeting_semantic_seed_children: the expected child set begins with the
-- package's structural children (manifest/timeline/integrity, always
-- required) plus the media track (required for server_audio). Capture-born
-- children (presentations/captions/annotations/legacy video) are appended
-- at mark-delete time from the facts that actually exist — never invented.
CREATE OR REPLACE FUNCTION _meeting_semantic_seed_children(
    p_recording_id bigint, p_media_required boolean
) RETURNS void AS $$
BEGIN
    INSERT INTO meeting_semantic_children (recording_id, child, child_state, required)
    VALUES (p_recording_id, 'manifest.json',     'absent', true),
           (p_recording_id, 'timeline.ndjson',   'absent', true),
           (p_recording_id, 'integrity/sha256.json', 'absent', true)
    ON CONFLICT (recording_id, child) DO NOTHING;
    IF p_media_required THEN
        INSERT INTO meeting_semantic_children (recording_id, child, child_state, required)
        VALUES (p_recording_id, 'media/audio-<segment>', 'absent', true)
        ON CONFLICT (recording_id, child) DO NOTHING;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- ── meeting_semantic_recording_start ─────────────────────────────────────
-- The user-plane start. Host/cohost only; live meeting; the SAME BZ199
-- guest-admission arm as meeting_recording_start (no admitted guest is ever
-- recorded — the M4 "all modes extend the same recording-active predicate,
-- BZ199 guest exclusion, banner" invariant); and the SINGLE-PRIMARY-MODE
-- invariant: the shared meeting_recording_active predicate (which now
-- counts live semantic rows too) must be false, so a B2 RoomComposite
-- recording and a semantic recording can never run concurrently and there
-- is no automatic producer fallback.
CREATE OR REPLACE FUNCTION meeting_semantic_recording_start(
    p_user_id bigint, p_meeting_id bigint,
    p_capture_mode text DEFAULT 'server_audio',
    p_profile jsonb DEFAULT NULL
) RETURNS bigint AS $$
DECLARE
    v_state   text;
    v_rec_id  bigint;
    v_class   text;
    v_local   boolean;
BEGIN
    IF p_capture_mode NOT IN ('server_audio','local_registered','b2_companion_index') THEN
        RAISE EXCEPTION 'unknown capture mode %', p_capture_mode
            USING ERRCODE='BZ276',
                  HINT='{"type":"unprocessable","detail":"captureMode"}';
    END IF;
    PERFORM _meeting_semantic_profile_shape(p_profile);
    v_class := COALESCE(p_profile->>'class', 'evidence_pending');
    v_local := p_capture_mode = 'local_registered';

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

    -- Single primary mode + one live semantic recording per meeting: the
    -- shared predicate covers BOTH directions (it counts live B2 rows and
    -- live semantic rows), so this one check is the whole invariant.
    IF meeting_recording_active(p_meeting_id) THEN
        RAISE EXCEPTION 'meeting % already has a primary recording in flight', p_meeting_id
            USING ERRCODE='BZ278',
                  HINT='{"type":"conflict","detail":"single-primary-recording-mode"}';
    END IF;

    -- BZ199 arm (same-txn, admission-fact based — the meeting_recording_start
    -- shape verbatim; recording consent extends to every mode).
    IF EXISTS (SELECT 1 FROM meeting_participants
                WHERE meeting_id = p_meeting_id AND role = 'guest'
                  AND left_at IS NULL AND banned_at IS NULL) THEN
        RAISE EXCEPTION 'guests are admitted to meeting %; recording is blocked', p_meeting_id
            USING ERRCODE='BZ199',
                  HINT='{"type":"forbidden","detail":"kick or wait out admitted guests before recording"}';
    END IF;

    INSERT INTO meeting_semantic_recordings
         (meeting_id, capture_mode, rec_state, package_state,
          profile_class, producer_id, producer_version, container, codec,
          profile_evidence, policy_mode, local_only, started_by)
    VALUES (p_meeting_id, p_capture_mode, 'active', 'ACTIVE',
            v_class,
            COALESCE(p_profile->>'producerId', ''),
            COALESCE(p_profile->>'producerVersion', ''),
            COALESCE(p_profile->>'container', ''),
            COALESCE(p_profile->>'codec', ''),
            COALESCE(p_profile->>'evidenceRef', ''),
            'server_only',
            v_local, p_user_id)
    RETURNING id INTO v_rec_id;

    -- policy_mode snapshot: the admin policy SOURCE lands with the public
    -- recording contract (evidence-gated, plan "Recording policy"); until
    -- that exists the snapshot records the only posture this slice admits
    -- (server_only semantics) rather than reading a policy that isn't there.
    PERFORM _meeting_semantic_seed_children(v_rec_id, p_capture_mode = 'server_audio');

    -- The banner fact: server state ahead of any capture (§3.2 discipline,
    -- extended to the semantic mode). mode:'semantic' lets the client
    -- label the banner while the show/hide behavior stays the shared one.
    PERFORM notify_meet_state(p_meeting_id, 'recording_state',
        jsonb_build_object('recordingId', v_rec_id, 'state', 'requested',
                           'mode', 'semantic', 'captureMode', p_capture_mode));
    RETURN v_rec_id;
END;
$$ LANGUAGE plpgsql;

-- ── meeting_semantic_recording_stop ──────────────────────────────────────
-- The user-plane stop (the drain boundary exports wait for). Host/cohost;
-- the row goes 'stopped' truthfully — capture segments that never closed
-- stay whatever they truthfully are (the worker marks them interrupted).
CREATE OR REPLACE FUNCTION meeting_semantic_recording_stop(
    p_user_id bigint, p_meeting_id bigint
) RETURNS jsonb AS $$
DECLARE
    v_rec meeting_semantic_recordings;
BEGIN
    PERFORM meeting_require_authority(p_meeting_id, p_user_id);
    SELECT * INTO v_rec
      FROM meeting_semantic_recordings
     WHERE meeting_id = p_meeting_id AND rec_state = 'active'
       FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no active semantic recording on meeting %', p_meeting_id
            USING ERRCODE='BZ278',
                  HINT='{"type":"conflict","detail":"no active semantic recording"}';
    END IF;
    UPDATE meeting_semantic_recordings
       SET rec_state = 'stopped', stopped_at = now(), updated_at = now()
     WHERE id = v_rec.id;
    PERFORM notify_meet_state(p_meeting_id, 'recording_state',
        jsonb_build_object('recordingId', v_rec.id, 'state', 'stopped',
                           'mode', 'semantic'));
    RETURN jsonb_build_object('recordingId', v_rec.id);
END;
$$ LANGUAGE plpgsql;

-- ── meeting_semantic_segment_ingest ──────────────────────────────────────
-- The WORKER-plane segment binding (SECURITY DEFINER — the GUC-less drain
-- surface, meeting_recording_event precedent). Records one segment's
-- TRUTHFUL state:
--   p_state='capturing'  → provisional interval, no completeness claims.
--   p_state='verified'   → requires digest+size+actual MIME/codec/container
--                          and the ingest acknowledgement; the interval is
--                          final; overlap with another verified segment is
--                          BZ279 (duplicate media).
--   p_state='interrupted'/'failed' → p_reason MANDATORY (why it stopped);
--                          observed bytes may ride along, never as a
--                          completeness claim.
-- Idempotent by (recording, seq): an exact replay of committed facts is a
-- silent no-op; a CONFLICTING replay (same seq, different facts) is BZ279 —
-- a restart opens a NEW seq, it never rewrites history.
CREATE OR REPLACE FUNCTION meeting_semantic_segment_ingest(
    p_recording_id bigint, p_seq integer, p_state text,
    p_content_sha256 text, p_byte_size bigint,
    p_mime text, p_codec text, p_container text,
    p_start_ms bigint, p_end_ms bigint,
    p_wall_start_ms bigint, p_wall_end_ms bigint,
    p_reason text DEFAULT NULL
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    v_rec      meeting_semantic_recordings;
    v_existing meeting_semantic_segments;
    v_ack      text := 'none';
BEGIN
    IF p_state NOT IN ('capturing','verified','interrupted','failed') THEN
        RAISE EXCEPTION 'unknown segment state %', p_state
            USING ERRCODE='BZ279', HINT='{"type":"unprocessable","detail":"segmentState"}';
    END IF;
    IF p_seq < 1 THEN
        RAISE EXCEPTION 'segment sequence numbers from 1'
            USING ERRCODE='BZ279', HINT='{"type":"unprocessable","detail":"segmentSeq"}';
    END IF;
    IF p_end_ms <= p_start_ms THEN
        RAISE EXCEPTION 'segment interval [%s,%s) is not a positive interval', p_start_ms, p_end_ms
            USING ERRCODE='BZ279', HINT='{"type":"unprocessable","detail":"segmentInterval"}';
    END IF;

    SELECT * INTO v_rec FROM meeting_semantic_recordings
     WHERE id = p_recording_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'semantic recording % not found', p_recording_id
            USING ERRCODE='BZ278', HINT='{"type":"notFound"}';
    END IF;

    IF p_state = 'verified' THEN
        IF p_content_sha256 IS NULL OR p_content_sha256 !~ '^[0-9a-f]{64}$'
           OR p_byte_size IS NULL OR p_byte_size <= 0
           OR COALESCE(p_mime,'') = '' OR COALESCE(p_codec,'') = ''
           OR COALESCE(p_container,'') = '' THEN
            -- MR-01: the complete-record claim has no home without its proof.
            RAISE EXCEPTION 'verified segment % lacks its digest/size/media identity proof', p_seq
                USING ERRCODE='BZ279',
                      HINT='{"type":"conflict","detail":"unverified completeness claim"}';
        END IF;
        v_ack := 'acknowledged';
    ELSIF p_state IN ('interrupted','failed') AND COALESCE(p_reason,'') = '' THEN
        RAISE EXCEPTION 'segment % stopped % without a reason; partial results must be truthful', p_seq, p_state
            USING ERRCODE='BZ279',
                  HINT='{"type":"conflict","detail":"truthful partial result required"}';
    END IF;

    SELECT * INTO v_existing FROM meeting_semantic_segments
     WHERE recording_id = p_recording_id AND seq = p_seq FOR UPDATE;
    IF FOUND THEN
        -- Idempotency: byte-identical facts (modulo the ack) replay clean.
        IF v_existing.state = p_state
           AND COALESCE(v_existing.content_sha256,'') = COALESCE(p_content_sha256,'')
           AND COALESCE(v_existing.byte_size,0) = COALESCE(p_byte_size,0)
           AND v_existing.start_ms = p_start_ms AND v_existing.end_ms = p_end_ms THEN
            IF v_existing.state = 'verified' THEN
                UPDATE meeting_semantic_segments SET ack_state = 'acknowledged', updated_at = now()
                 WHERE id = v_existing.id AND ack_state <> 'acknowledged';
            END IF;
            RETURN jsonb_build_object('segmentSeq', p_seq, 'state', v_existing.state,
                                      'alreadyRecorded', true);
        END IF;
        -- A verified row is immutable history; a capturing row may only be
        -- PROMOTED by exactly its own completion (same interval).
        IF v_existing.state = 'verified'
           OR (v_existing.state = 'capturing' AND v_existing.start_ms <> p_start_ms)
           OR (p_state = 'capturing') THEN
            RAISE EXCEPTION 'segment % re-entry conflicts with its committed state %', p_seq, v_existing.state
                USING ERRCODE='BZ279',
                      HINT='{"type":"conflict","detail":"segment re-entry conflict"}';
        END IF;
        -- Promotion (capturing → verified/interrupted/failed): the overlap
        -- belt fires on UPDATE too; explicit check gives the friendly error.
        IF p_state = 'verified' AND EXISTS (
            SELECT 1 FROM meeting_semantic_segments s
             WHERE s.recording_id = p_recording_id AND s.id <> v_existing.id
               AND s.state = 'verified'
               AND s.start_ms < p_end_ms AND p_start_ms < s.end_ms) THEN
            RAISE EXCEPTION 'verified segment % overlaps an existing verified segment — duplicate media fails closed', p_seq
                USING ERRCODE='BZ279',
                      HINT='{"type":"conflict","detail":"duplicate media interval"}';
        END IF;
        UPDATE meeting_semantic_segments
           SET state = p_state, ack_state = v_ack,
               content_sha256 = p_content_sha256, byte_size = p_byte_size,
               mime_type = COALESCE(p_mime, mime_type),
               codec = COALESCE(p_codec, codec),
               container = COALESCE(p_container, container),
               end_ms = p_end_ms, wall_end_unix_ms = p_wall_end_ms,
               interrupt_reason = p_reason, updated_at = now()
         WHERE id = v_existing.id;
        RETURN jsonb_build_object('segmentSeq', p_seq, 'state', p_state,
                                  'alreadyRecorded', false);
    END IF;

    -- Fresh insert. Overlap belt: the trigger (V266) is the last word; the
    -- explicit check names the conflict before the constraint would.
    IF p_state = 'verified' AND EXISTS (
        SELECT 1 FROM meeting_semantic_segments s
         WHERE s.recording_id = p_recording_id
           AND s.state = 'verified'
           AND s.start_ms < p_end_ms AND p_start_ms < s.end_ms) THEN
        RAISE EXCEPTION 'verified segment % overlaps an existing verified segment — duplicate media fails closed', p_seq
            USING ERRCODE='BZ279',
                  HINT='{"type":"conflict","detail":"duplicate media interval"}';
    END IF;
    INSERT INTO meeting_semantic_segments
         (recording_id, seq, state, ack_state, content_sha256, byte_size,
          mime_type, codec, container, start_ms, end_ms,
          wall_start_unix_ms, wall_end_unix_ms, interrupt_reason)
    VALUES (p_recording_id, p_seq, p_state, v_ack, p_content_sha256, p_byte_size,
            COALESCE(p_mime,''), COALESCE(p_codec,''), COALESCE(p_container,''),
            p_start_ms, p_end_ms, p_wall_start_ms, p_wall_end_ms, p_reason);
    RETURN jsonb_build_object('segmentSeq', p_seq, 'state', p_state,
                              'alreadyRecorded', false);
END;
$$;
SELECT apply_worker_ownership('meeting_semantic_segment_ingest(bigint,integer,text,text,bigint,text,text,text,bigint,bigint,bigint,bigint,text)'::regprocedure);

-- ── meeting_semantic_child_release ───────────────────────────────────────
-- The WORKER-plane per-child release (lifecycle.go ReleaseReceipt's durable
-- twin). Under the package row lock the reducer RECHECKS: the deletion
-- generation the sweep is executing under (a stale worker fails closed),
-- the current hold state (a hold linearized before the release fences it —
-- receipt says so, nothing is released), and the exact child. Releasing a
-- child removes its LOGICAL reference once; retries replay as
-- alreadyReleased. The worker never writes blobs.ref_count — physical
-- reclamation stays the storage owner's live-reference fence.
CREATE OR REPLACE FUNCTION meeting_semantic_child_release(
    p_recording_id bigint, p_child text, p_generation bigint
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    v_rec    meeting_semantic_recordings;
    v_child  meeting_semantic_children;
BEGIN
    SELECT * INTO v_rec FROM meeting_semantic_recordings
     WHERE id = p_recording_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'semantic recording % not found', p_recording_id
            USING ERRCODE='BZ278', HINT='{"type":"notFound"}';
    END IF;
    -- The receipt ledger is checked BEFORE the state refusal, in this
    -- order: an already-released child replays its receipt in ANY state,
    -- and a hold linearized before the release fences it as a RECEIPT —
    -- not a raise — so a sweep racing a hold converges instead of
    -- crash-looping (lifecycle.go ReleaseReceipt's HeldBeforeRelease).
    SELECT * INTO v_child FROM meeting_semantic_children
     WHERE recording_id = p_recording_id AND child = p_child FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'child % is not part of package %', p_child, p_recording_id
            USING ERRCODE='BZ280',
                  HINT='{"type":"conflict","detail":"child outside the expected set"}';
    END IF;

    IF v_child.released THEN
        RETURN jsonb_build_object('child', p_child,
                                  'releaseGeneration', v_child.release_generation,
                                  'alreadyReleased', true,
                                  'heldBeforeRelease', false);
    END IF;
    IF v_rec.holds > 0 AND v_rec.package_state IN
       ('DELETE_PENDING','HELD_COMPLETE','HELD_PARTIAL') THEN
        RETURN jsonb_build_object('child', p_child,
                                  'releaseGeneration', p_generation,
                                  'alreadyReleased', false,
                                  'heldBeforeRelease', true);
    END IF;
    IF v_rec.package_state <> 'DELETE_PENDING' THEN
        RAISE EXCEPTION 'package % is %, not DELETE_PENDING; no release is lawful', p_recording_id, v_rec.package_state
            USING ERRCODE='BZ280',
                  HINT='{"type":"conflict","detail":"package is not pending deletion"}';
    END IF;
    IF p_generation IS NULL OR p_generation <> v_rec.deletion_generation THEN
        RAISE EXCEPTION 'release generation % is stale (current %); a stale worker fails closed',
            p_generation, v_rec.deletion_generation
            USING ERRCODE='BZ280',
                  HINT='{"type":"conflict","detail":"stale deletion generation"}';
    END IF;

    UPDATE meeting_semantic_children
       SET released = true, release_generation = p_generation,
           child_state = CASE WHEN child_state = 'embedded' THEN 'expired' ELSE child_state END
     WHERE id = v_child.id;
    RETURN jsonb_build_object('child', p_child,
                              'releaseGeneration', p_generation,
                              'alreadyReleased', false,
                              'heldBeforeRelease', false);
END;
$$;
SELECT apply_worker_ownership('meeting_semantic_child_release(bigint,text,bigint)'::regprocedure);

-- ── meeting_semantic_package_finalize ────────────────────────────────────
-- The WORKER-plane finalize: expected set exhausted + zero holds → DELETED.
-- Returns true when it finalized, false when the sweep must stay open
-- (holds or unreleased children) — never raises for the ordinary
-- not-yet-done case, so a retrying sweep cannot wedge the package.
CREATE OR REPLACE FUNCTION meeting_semantic_package_finalize(
    p_recording_id bigint, p_generation bigint
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    v_rec       meeting_semantic_recordings;
    v_remaining integer;
BEGIN
    SELECT * INTO v_rec FROM meeting_semantic_recordings
     WHERE id = p_recording_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'semantic recording % not found', p_recording_id
            USING ERRCODE='BZ278', HINT='{"type":"notFound"}';
    END IF;
    IF v_rec.package_state <> 'DELETE_PENDING' THEN
        RETURN false; -- already finalized / held / restored
    END IF;
    IF v_rec.holds > 0 THEN
        RETURN false; -- a hold suspends the remainder; already reclaimed bytes stay reclaimed
    END IF;
    SELECT COUNT(*) INTO v_remaining
      FROM meeting_semantic_children
     WHERE recording_id = p_recording_id AND NOT released;
    IF v_remaining > 0 THEN
        RETURN false; -- finalization requires the expected set exhausted
    END IF;
    UPDATE meeting_semantic_recordings
       SET package_state = 'DELETED', updated_at = now()
     WHERE id = v_rec.id;
    PERFORM notify_meet_state(v_rec.meeting_id, 'semantic_package_state',
        jsonb_build_object('recordingId', v_rec.id, 'packageState', 'DELETED'));
    RETURN true;
END;
$$;
SELECT apply_worker_ownership('meeting_semantic_package_finalize(bigint,bigint)'::regprocedure);

-- ── meeting_semantic_package_mark_delete ─────────────────────────────────
-- The user-plane delete: ACTIVE → DELETE_PENDING (the ONLY legal edge —
-- lifecycle.go CanTransitionPackage), under a stopped recording (capture is
-- stopped and reconciled first — "stop and reconcile before a separately
-- authorized replacement"). Records/refreshes the expected child set from
-- the facts that exist (capture-born children appended here, absent unless
-- retained), bumps the deletion generation (old receipts go stale), and
-- emits ONE work item — the DELETE_PENDING row the sweep's index drains.
CREATE OR REPLACE FUNCTION meeting_semantic_package_mark_delete(
    p_user_id bigint, p_meeting_id bigint, p_recording_id bigint
) RETURNS jsonb AS $$
DECLARE
    v_rec  meeting_semantic_recordings;
    v_expected integer;
BEGIN
    v_rec := _meeting_semantic_lock(p_meeting_id, p_recording_id);
    PERFORM _meeting_semantic_require_authority(p_meeting_id, p_user_id);

    IF v_rec.rec_state = 'active' THEN
        RAISE EXCEPTION 'stop the semantic recording before deleting package %', p_recording_id
            USING ERRCODE='BZ278',
                  HINT='{"type":"conflict","detail":"stop and reconcile before delete"}';
    END IF;
    IF v_rec.package_state <> 'ACTIVE' THEN
        RAISE EXCEPTION 'package % is %; only ACTIVE packages delete', p_recording_id, v_rec.package_state
            USING ERRCODE='BZ280',
                  HINT='{"type":"conflict","detail":"package lifecycle refuses delete"}';
    END IF;

    -- Capture-born children join the expected set from existing facts:
    -- a retained B2 companion index (optional), and the annotations member
    -- when committed annotation facts exist (the M4 admission slice — V267
    -- — extends THIS seed with its owning child, never a second sweep; the
    -- snapshot bytes ride the presentation annotation ledger, so the member
    -- is 'embedded' in the logical package via the committed references).
    INSERT INTO meeting_semantic_children (recording_id, child, child_state, required)
    VALUES (v_rec.id, 'media/legacy-video-reference.json', 'absent', false)
    ON CONFLICT (recording_id, child) DO NOTHING;
    IF EXISTS (
        SELECT 1 FROM meeting_presentation_annotations a
         WHERE a.meeting_id = v_rec.meeting_id
           AND a.created_at >= v_rec.started_at) THEN
        INSERT INTO meeting_semantic_children (recording_id, child, child_state, required)
        VALUES (v_rec.id, 'annotations/<snapshot>.json', 'embedded', false)
        ON CONFLICT (recording_id, child) DO NOTHING;
    END IF;

    UPDATE meeting_semantic_recordings
       SET package_state = 'DELETE_PENDING',
           deletion_generation = deletion_generation + 1,
           updated_at = now()
     WHERE id = v_rec.id
    RETURNING deletion_generation INTO v_expected;

    PERFORM notify_meet_state(p_meeting_id, 'semantic_package_state',
        jsonb_build_object('recordingId', v_rec.id,
                           'packageState', 'DELETE_PENDING',
                           'deletionGeneration', v_expected));
    RETURN jsonb_build_object('recordingId', v_rec.id,
                              'packageState', 'DELETE_PENDING',
                              'deletionGeneration', v_expected);
END;
$$ LANGUAGE plpgsql;

-- ── meeting_semantic_package_hold / restore ──────────────────────────────
-- Hold bumps the fence count (a hold linearized before a child release
-- prevents it; a later hold suspends the remainder but cannot recall
-- already reclaimed bytes). Hold is lawful in every state except DELETED
-- (nothing remains to protect). Restore is the HELD_COMPLETE→ACTIVE edge
-- ONLY (CanTransitionPackage): HELD_PARTIAL is ineligible in V1 even if a
-- read currently sees bytes, and DELETED has no resurrect arm.
CREATE OR REPLACE FUNCTION meeting_semantic_package_hold(
    p_user_id bigint, p_meeting_id bigint, p_recording_id bigint,
    p_hold boolean DEFAULT true
) RETURNS integer AS $$
DECLARE
    v_rec   meeting_semantic_recordings;
    v_holds integer;
BEGIN
    v_rec := _meeting_semantic_lock(p_meeting_id, p_recording_id);
    PERFORM _meeting_semantic_require_authority(p_meeting_id, p_user_id);
    IF v_rec.package_state = 'DELETED' THEN
        RAISE EXCEPTION 'package % is DELETED; nothing remains to hold or restore', p_recording_id
            USING ERRCODE='BZ280',
                  HINT='{"type":"conflict","detail":"package already deleted"}';
    END IF;
    UPDATE meeting_semantic_recordings
       SET holds = GREATEST(holds + CASE WHEN COALESCE(p_hold, true) THEN 1 ELSE -1 END, 0),
           updated_at = now()
     WHERE id = v_rec.id
    RETURNING holds INTO v_holds;

    -- The hold's lifecycle arm: a hold taken while a delete sweep is open
    -- classifies the package per the V1 rule — zero released REQUIRED
    -- children is HELD_COMPLETE (restorable), any released required child
    -- is HELD_PARTIAL (ineligible for restore even if a HEAD currently
    -- sees bytes: that observation does not defeat concurrent physical
    -- GC). A hold on an ACTIVE package is just the retention fence; a hold
    -- on a HELD package never un-holds it (restore is the explicit arm).
    IF COALESCE(p_hold, true) AND v_rec.package_state = 'DELETE_PENDING' THEN
        UPDATE meeting_semantic_recordings
           SET package_state = CASE WHEN EXISTS (
                     SELECT 1 FROM meeting_semantic_children
                      WHERE recording_id = v_rec.id AND required AND released)
               THEN 'HELD_PARTIAL' ELSE 'HELD_COMPLETE' END,
               updated_at = now()
         WHERE id = v_rec.id;
        PERFORM notify_meet_state(v_rec.meeting_id, 'semantic_package_state',
            jsonb_build_object('recordingId', v_rec.id,
                               'packageState', (SELECT package_state
                                                  FROM meeting_semantic_recordings
                                                 WHERE id = v_rec.id)));
    END IF;
    RETURN v_holds;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION meeting_semantic_package_restore(
    p_user_id bigint, p_meeting_id bigint, p_recording_id bigint
) RETURNS jsonb AS $$
DECLARE
    v_rec       meeting_semantic_recordings;
    v_released  integer;
BEGIN
    v_rec := _meeting_semantic_lock(p_meeting_id, p_recording_id);
    PERFORM _meeting_semantic_require_authority(p_meeting_id, p_user_id);

    IF v_rec.package_state <> 'HELD_COMPLETE' THEN
        RAISE EXCEPTION 'package % is %; restore is legal only from HELD_COMPLETE', p_recording_id, v_rec.package_state
            USING ERRCODE='BZ280',
                  HINT='{"type":"conflict","detail":"restore requires HELD_COMPLETE"}';
    END IF;
    SELECT COUNT(*) INTO v_released
      FROM meeting_semantic_children
     WHERE recording_id = v_rec.id AND required AND released;
    IF v_released > 0 THEN
        RAISE EXCEPTION 'package % shows % released required children; HELD_COMPLETE cannot hold them', p_recording_id, v_released
            USING ERRCODE='BZ280',
                  HINT='{"type":"conflict","detail":"required references no longer protected"}';
    END IF;

    -- The restore atomically verifies every required live reference (above)
    -- and cancels the deletion generation: the generation bumps so any
    -- stale worker receipt from the suspended sweep fails closed forever.
    UPDATE meeting_semantic_recordings
       SET package_state = 'ACTIVE',
           deletion_generation = deletion_generation + 1,
           updated_at = now()
     WHERE id = v_rec.id;
    PERFORM notify_meet_state(p_meeting_id, 'semantic_package_state',
        jsonb_build_object('recordingId', v_rec.id, 'packageState', 'ACTIVE'));
    RETURN jsonb_build_object('recordingId', v_rec.id, 'packageState', 'ACTIVE');
END;
$$ LANGUAGE plpgsql;

-- ── meeting_semantic_export_request ──────────────────────────────────────
-- The user-plane export request: ONE idempotent receipt per (recording,
-- generation). Host/cohost; the recording must be stopped and the package
-- ACTIVE (delete fences exports). p_bounds/p_exclusions are the CONFIRMED
-- windows computed by Go's PlanExport from the verified coverage — the
-- receipt pins them so the composition refuses drift (R5.4: reselection,
-- never silent clipping). NULL bounds defer to the worker's coverage
-- computation; an export without verified audio is refused HERE (BZ281) —
-- a pages-only package exports nothing (never a fabricated video).
CREATE OR REPLACE FUNCTION meeting_semantic_export_request(
    p_user_id bigint, p_meeting_id bigint, p_recording_id bigint,
    p_bounds jsonb DEFAULT NULL, p_exclusions jsonb DEFAULT NULL
) RETURNS jsonb AS $$
DECLARE
    v_rec        meeting_semantic_recordings;
    v_generation bigint;
    v_verified   integer;
    v_receipt    jsonb;
BEGIN
    v_rec := _meeting_semantic_lock(p_meeting_id, p_recording_id);
    PERFORM _meeting_semantic_require_authority(p_meeting_id, p_user_id);

    IF v_rec.rec_state <> 'stopped' THEN
        RAISE EXCEPTION 'semantic recording % is %; exports await the stop/drain boundary', p_recording_id, v_rec.rec_state
            USING ERRCODE='BZ278',
                  HINT='{"type":"conflict","detail":"stop and reconcile before export"}';
    END IF;
    IF v_rec.package_state <> 'ACTIVE' THEN
        RAISE EXCEPTION 'package % is %; deletion fences new exports', p_recording_id, v_rec.package_state
            USING ERRCODE='BZ280',
                  HINT='{"type":"conflict","detail":"package deletion fences exports"}';
    END IF;
    SELECT COUNT(*) INTO v_verified
      FROM meeting_semantic_segments
     WHERE recording_id = v_rec.id AND state = 'verified';
    IF v_verified = 0 THEN
        RAISE EXCEPTION 'no verified audio segments: nothing is exportable; the semantic replay source is retained'
            USING ERRCODE='BZ281',
                  HINT='{"type":"unprocessable","detail":"no verified audio interval"}';
    END IF;
    IF v_rec.capture_mode = 'local_registered' THEN
        RAISE EXCEPTION 'local-only registration exports nothing centrally (truthful locality)'
            USING ERRCODE='BZ281',
                  HINT='{"type":"unprocessable","detail":"local_only"}';
    END IF;

    SELECT COALESCE(MAX(generation), 0) + 1 INTO v_generation
      FROM meeting_semantic_exports
     WHERE recording_id = v_rec.id;

    INSERT INTO meeting_semantic_exports
         (recording_id, generation, state, bounds, exclusions)
    VALUES (v_rec.id, v_generation, 'pending', p_bounds, p_exclusions);

    SELECT jsonb_build_object('recordingId', v_rec.id,
                              'generation', v_generation,
                              'state', 'pending') INTO v_receipt;
    PERFORM notify_meet_state(p_meeting_id, 'semantic_export_state', v_receipt);
    RETURN v_receipt;
END;
$$ LANGUAGE plpgsql;

-- ── meeting_semantic_export_claim ────────────────────────────────────────
-- The WORKER-plane bounded-composition claim. pending → composing with a
-- fresh claim; a composing receipt whose claim is stale (exportLease) is
-- re-claimable (a crashed worker cannot wedge the queue); attempts are
-- durable and capped (MaxExportAttempts) — an exhausted receipt returns
-- {claimable:false, exhausted:true} and the sweep marks it failed. Returns
-- NULL when the receipt is not claimable right now (fresh lease elsewhere,
-- terminal states).
CREATE OR REPLACE FUNCTION meeting_semantic_export_claim(
    p_recording_id bigint, p_generation bigint
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    v_exp meeting_semantic_exports;
BEGIN
    SELECT * INTO v_exp FROM meeting_semantic_exports
     WHERE recording_id = p_recording_id AND generation = p_generation
       FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'export receipt %/% not found', p_recording_id, p_generation
            USING ERRCODE='BZ281', HINT='{"type":"notFound"}';
    END IF;
    IF v_exp.state = 'ready' THEN
        RETURN jsonb_build_object('claimable', false, 'state', 'ready',
                                  'driveNodeId', v_exp.drive_node_id,
                                  'driveVersionId', v_exp.drive_version_id);
    END IF;
    IF v_exp.state = 'failed' THEN
        RETURN jsonb_build_object('claimable', false, 'state', 'failed');
    END IF;
    IF v_exp.state = 'composing' AND v_exp.claimed_at > now() - interval '10 minutes' THEN
        RETURN NULL; -- a fresh lease holds it
    END IF;
    IF v_exp.attempts >= 5 THEN
        RETURN jsonb_build_object('claimable', false, 'exhausted', true, 'state', v_exp.state);
    END IF;
    UPDATE meeting_semantic_exports
       SET state = 'composing', claimed_at = now(), attempts = attempts + 1,
           updated_at = now()
     WHERE id = v_exp.id;
    RETURN jsonb_build_object('claimable', true, 'state', 'composing',
                              'attempts', v_exp.attempts + 1,
                              'bounds', v_exp.bounds,
                              'exclusions', v_exp.exclusions);
END;
$$;
SELECT apply_worker_ownership('meeting_semantic_export_claim(bigint,bigint)'::regprocedure);

-- ── meeting_semantic_export_complete ─────────────────────────────────────
-- The WORKER-plane idempotent completion. composing → ready (output
-- identity committed ONCE — the no-duplicate-Drive-version root) or →
-- failed (reason kept; the semantic source is untouched by every arm). An
-- exact replay of a committed completion is a silent no-op; a conflicting
-- completion (different output identity against a ready receipt) is BZ278.
CREATE OR REPLACE FUNCTION meeting_semantic_export_complete(
    p_recording_id bigint, p_generation bigint,
    p_ok boolean, p_node_id bigint DEFAULT NULL, p_version_id bigint DEFAULT NULL,
    p_error text DEFAULT NULL
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    v_exp meeting_semantic_exports;
    v_meeting bigint;
BEGIN
    SELECT * INTO v_exp FROM meeting_semantic_exports e
     WHERE e.recording_id = p_recording_id AND e.generation = p_generation
       FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'export receipt %/% not found', p_recording_id, p_generation
            USING ERRCODE='BZ281', HINT='{"type":"notFound"}';
    END IF;
    SELECT meeting_id INTO v_meeting
      FROM meeting_semantic_recordings
     WHERE id = p_recording_id;

    IF v_exp.state = 'ready' THEN
        IF COALESCE(p_ok, false) AND v_exp.drive_node_id = p_node_id
           AND v_exp.drive_version_id = p_version_id THEN
            RETURN; -- idempotent replay of the committed completion
        END IF;
        RAISE EXCEPTION 'export receipt %/% is ready with output %/%; conflicting completion fails closed',
            p_recording_id, p_generation, v_exp.drive_node_id, v_exp.drive_version_id
            USING ERRCODE='BZ278',
                  HINT='{"type":"conflict","detail":"export receipt already ready"}';
    END IF;
    IF v_exp.state = 'failed' THEN
        -- A crash after committing the failure but before the response is
        -- the retry case the rescue registry names: the exact failure
        -- replay is a silent no-op. A SUCCESS after a committed failure
        -- cannot land — that generation is terminal; a retry is a NEW
        -- generation receipt, never a mutation of settled history.
        IF NOT COALESCE(p_ok, false) THEN
            RETURN;
        END IF;
        RAISE EXCEPTION 'export receipt %/% already failed (%); a retry is a new generation, not a mutation',
            p_recording_id, p_generation, COALESCE(v_exp.error, 'exportCompositionFailed')
            USING ERRCODE='BZ278',
                  HINT='{"type":"conflict","detail":"export receipt already failed"}';
    END IF;
    IF v_exp.state <> 'composing' THEN
        RAISE EXCEPTION 'export receipt %/% is %; completion is lawful only from composing',
            p_recording_id, p_generation, v_exp.state
            USING ERRCODE='BZ278',
                  HINT='{"type":"conflict","detail":"export receipt not composing"}';
    END IF;

    IF COALESCE(p_ok, false) THEN
        IF p_node_id IS NULL OR p_version_id IS NULL THEN
            RAISE EXCEPTION 'a successful export completion requires its output identity'
                USING ERRCODE='BZ281',
                      HINT='{"type":"unprocessable","detail":"output identity required"}';
        END IF;
        UPDATE meeting_semantic_exports
           SET state = 'ready', drive_node_id = p_node_id,
               drive_version_id = p_version_id, updated_at = now()
         WHERE id = v_exp.id;
    ELSE
        UPDATE meeting_semantic_exports
           SET state = 'failed', error = COALESCE(p_error, 'exportCompositionFailed'),
               updated_at = now()
         WHERE id = v_exp.id;
    END IF;
    PERFORM notify_meet_state(v_meeting, 'semantic_export_state',
        jsonb_build_object('recordingId', p_recording_id,
                           'generation', p_generation,
                           'state', CASE WHEN COALESCE(p_ok, false) THEN 'ready' ELSE 'failed' END));
END;
$$;
SELECT apply_worker_ownership('meeting_semantic_export_complete(bigint,bigint,boolean,bigint,bigint,text)'::regprocedure);

-- ── meeting_semantic_package_read ────────────────────────────────────────
-- The authorized package projection (the checkpoint-read genre): the
-- manifest facts, the truthful segment/coverage state, and the receipt
-- ledger a replay or export consumer needs. Scoped to HISTORICAL attendees
-- (meeting_attendee_role) — a post-end replay read converges; an absent
-- caller gets the indistinguishable BZ278. Delete-fenced: DELETE_PENDING
-- and beyond still READ (the package boundary fences reads for
-- already-released children, whose child_state says so), never re-exported.
CREATE OR REPLACE FUNCTION meeting_semantic_package_read(
    p_user_id bigint, p_meeting_id bigint, p_recording_id bigint
) RETURNS jsonb AS $$
DECLARE
    v_out jsonb;
BEGIN
    IF meeting_attendee_role(p_meeting_id, p_user_id) IS NULL THEN
        RAISE EXCEPTION 'semantic recording % not found on meeting %', p_recording_id, p_meeting_id
            USING ERRCODE='BZ278', HINT='{"type":"notFound"}';
    END IF;
    SELECT jsonb_build_object(
             'recordingId', r.id,
             'meetingId', r.meeting_id,
             'captureMode', r.capture_mode,
             'recState', r.rec_state,
             'packageState', r.package_state,
             'localOnly', r.local_only,
             'policyMode', r.policy_mode,
             'manifestDigest', r.manifest_digest,
             'timelineSha256', r.timeline_sha256,
             'timelineRecords', r.timeline_records,
             'deletionGeneration', r.deletion_generation,
             'holds', r.holds,
             'startedAt', r.started_at,
             'stoppedAt', r.stopped_at,
             'segments', (
               SELECT COALESCE(jsonb_agg(jsonb_build_object(
                        'seq', s.seq, 'state', s.state, 'ack', s.ack_state,
                        'contentSha256', s.content_sha256, 'byteSize', s.byte_size,
                        'mimeType', s.mime_type, 'codec', s.codec, 'container', s.container,
                        'startMs', s.start_ms, 'endMs', s.end_ms,
                        'wallStartUnixMs', s.wall_start_unix_ms,
                        'wallEndUnixMs', s.wall_end_unix_ms,
                        'interruptReason', s.interrupt_reason
                      ) ORDER BY s.seq), '[]'::jsonb)
               FROM meeting_semantic_segments s
              WHERE s.recording_id = r.id),
             'children', (
               SELECT COALESCE(jsonb_agg(jsonb_build_object(
                        'child', c.child, 'childState', c.child_state,
                        'required', c.required, 'released', c.released,
                        'releaseGeneration', c.release_generation
                      ) ORDER BY c.child), '[]'::jsonb)
               FROM meeting_semantic_children c
              WHERE c.recording_id = r.id),
             'exports', (
               SELECT COALESCE(jsonb_agg(jsonb_build_object(
                        'generation', e.generation, 'state', e.state,
                        'attempts', e.attempts, 'bounds', e.bounds,
                        'exclusions', e.exclusions, 'error', e.error,
                        'driveNodeId', e.drive_node_id,
                        'driveVersionId', e.drive_version_id
                      ) ORDER BY e.generation), '[]'::jsonb)
               FROM meeting_semantic_exports e
              WHERE e.recording_id = r.id)
           ) INTO v_out
      FROM meeting_semantic_recordings r
     WHERE r.id = p_recording_id AND r.meeting_id = p_meeting_id;
    IF v_out IS NULL THEN
        RAISE EXCEPTION 'semantic recording % not found on meeting %', p_recording_id, p_meeting_id
            USING ERRCODE='BZ278', HINT='{"type":"notFound"}';
    END IF;
    RETURN v_out;
END;
$$ LANGUAGE plpgsql;

-- ── meeting_semantic_replay_read ─────────────────────────────────────────
-- The deterministic replay feed (M4: "Build deterministic web replay ...
-- presentation version links visible"; the webmail mirror
-- webmail/src/lib/meet/semanticReplay.ts consumes exactly this). The
-- package read's own projection (above — manifest facts, truthful segment
-- state, receipt ledger) COMPOSED with the recorded-fact rails it names:
--   · presentationLinks — the presentation sessions whose live window
--     overlaps the recording's (source version links are never hidden; the
--     session's OWN status rides along, never a fabricated child-state
--     claim about retained bytes that V1 has not retained).
--   · annotations — the committed annotation snapshots inside the recording
--     window (the V267 admission ledger), bound by stable reference + the
--     in-database-derived content identity; the bytes themselves ride the
--     authorized bounded read (meeting_presentation_annotation_read), never
--     this feed.
--   · facts — the durable presentation events of the window with BOTH
--     clocks: atMs (wall) and mediaMs (media-aligned against the earliest
--     verified segment's wall start — replay.go renders a MediaMs<0 fact in
--     the fact rail, never silently on the media axis; no verified media ⇒
--     -1 ⇒ fact rail, and nothing invents an alignment).
--   · captions — an EMPTY list by contract: the caption binding producer is
--     a named follow-up (captions.go genre binding rows), and the feed
--     names that absence instead of hiding it.
-- Same HISTORICAL-attendee gate and indistinguishable BZ278 as the package
-- read; deterministic for a STOPPED package: same facts in, same jsonb
-- out. A live recording's window ends at now(), so its projection grows
-- by design until the stop boundary.
CREATE OR REPLACE FUNCTION meeting_semantic_replay_read(
    p_user_id bigint, p_meeting_id bigint, p_recording_id bigint
) RETURNS jsonb AS $$
DECLARE
    v_pkg     jsonb;
    v_out     jsonb;
    v_base    bigint;
    v_end     timestamptz;
    v_start   timestamptz;
BEGIN
    v_pkg := meeting_semantic_package_read(p_user_id, p_meeting_id, p_recording_id);
    IF v_pkg IS NULL THEN
        RAISE EXCEPTION 'semantic recording % not found on meeting %', p_recording_id, p_meeting_id
            USING ERRCODE='BZ278', HINT='{"type":"notFound"}';
    END IF;
    SELECT r.started_at,
           COALESCE(r.stopped_at, now()),
           (SELECT MIN(s.wall_start_unix_ms)
              FROM meeting_semantic_segments s
             WHERE s.recording_id = r.id AND s.state = 'verified')
      INTO v_start, v_end, v_base
      FROM meeting_semantic_recordings r
     WHERE r.id = p_recording_id AND r.meeting_id = p_meeting_id;

    v_out := v_pkg || jsonb_build_object(
        'presentationLinks', (
          SELECT COALESCE(jsonb_agg(jsonb_build_object(
                   'presentationId', p.id, 'status', p.status,
                   'driveNodeId', p.drive_node_id,
                   'driveVersionId', p.drive_version_id,
                   'manifestDigest', p.manifest_digest,
                   'manifestGeneration', p.manifest_generation,
                   'startedAt', p.started_at, 'endedAt', p.ended_at,
                   'annotationSnapshotRef', p.annotation_snapshot_ref
                 ) ORDER BY p.id), '[]'::jsonb)
            FROM meeting_presentations p
           WHERE p.meeting_id = p_meeting_id
             AND p.created_at <= v_end
             AND COALESCE(p.ended_at, now()) >= v_start),
        'annotations', (
          SELECT COALESCE(jsonb_agg(jsonb_build_object(
                   'presentationId', a.presentation_id,
                   'checkpointSeq', a.checkpoint_seq,
                   'presenterGeneration', a.presenter_generation,
                   'snapshotPath', a.snapshot_path,
                   'sha256', a.content_sha256,
                   'byteSize', a.byte_size,
                   'createdAt', a.created_at
                 ) ORDER BY a.created_at, a.id), '[]'::jsonb)
            FROM meeting_presentation_annotations a
           WHERE a.meeting_id = p_meeting_id
             AND a.created_at <= v_end
             AND a.created_at >= v_start),
        'facts', (
          SELECT COALESCE(jsonb_agg(jsonb_build_object(
                   'presentationId', e.presentation_id,
                   'checkpointSeq', e.checkpoint_seq,
                   'kind', e.kind,
                   'payload', e.payload,
                   'atMs', (EXTRACT(EPOCH FROM e.created_at) * 1000)::bigint,
                   'mediaMs', CASE WHEN v_base IS NULL THEN -1
                              ELSE (EXTRACT(EPOCH FROM e.created_at) * 1000)::bigint - v_base END
                 ) ORDER BY e.created_at, e.id), '[]'::jsonb)
            FROM meeting_presentation_events e
           WHERE e.meeting_id = p_meeting_id
             AND e.created_at <= v_end
             AND e.created_at >= v_start),
        'captions', '[]'::jsonb);
    RETURN v_out;
END;
$$ LANGUAGE plpgsql;
