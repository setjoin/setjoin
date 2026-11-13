-- meeting_presentation.sql — MEET plan M2: the reducer-owned presentation
-- session (retired-docs:superpowers/plans/2026-08-25-meet-document-presentation-
-- semantic-recording.md, M2), over the M0/M1 frozen contracts in
-- mailserver/internal/meet/presentation/ (lifecycle.go's state machine,
-- envelope.go's durable kind vocabulary, driveboundary.go's Drive-side
-- source boundary).
--
-- Every mutating verb is fenced on the SAME four axes, in this order:
--   1. participant + session identity  — the row is locked FOR UPDATE and
--      must name THIS meeting (BZ272; unknown id and a foreign meeting's
--      session id are indistinguishable — the anti-oracle posture).
--   2. verb-specific authority (the plan's security table) — host/cohost
--      floor via meeting_require_authority (BZ186) for authority verbs;
--      CURRENT-presenter scope for presenter verbs (BZ273); Drive source
--      rights via drive_runtime_has_node_capability(...,'preview') for
--      prepare/source-switch (BZ273) — capability authority stays Drive's;
--      a page-only presenter grant adds nothing to the source ACL.
--   3. lifecycle — the frozen M0 state machine, enforced per verb against
--      exactly the source states lifecycle.go's legality table admits
--      (BZ275). A terminal state never resurrects.
--   4. generation + checkpoint sequence — presenter_generation and
--      checkpoint_seq are optimistic fences: a stale caller's mutation
--      refuses with BZ274 and the rescue is "refresh the checkpoint"
--      (the plan's stalePresenterGeneration / presentationSequenceGap
--      registry row). Host/cohost takeover deliberately takes NO
--      generation fence: superseding a stale presenter is its purpose.
--
-- Each mutating verb commits, IN ONE TRANSACTION: the checkpoint UPDATE,
-- exactly one durable event row (§C of V265, widened by V267), the state
-- bump, and the notify_meet_state push fact ('presentation_state') — logic
-- where the data is. Annotations are ADMITTED through exactly one writer
-- since M4 (V267): the meeting_presentation_annotation_commit admitted-shape
-- gate (a well-formed snapshot commit or a clear); every un-admitted
-- annotation shape still refuses BZ277 — the flip added the admission path,
-- it did not remove the guard.
--
-- Flag posture: Go gates the new-intent routes on
-- feature.meet_document_presentation; these reducers are the authority
-- once a route is reached. The drain verbs (end/revoke + the checkpoint
-- read) stay reachable with the flag OFF so a flipped-off deployment
-- resolves committed sessions (DisableDrain; the recording D11 genre).
--
-- Actor scope: these reducers run on the authenticated meet surface —
-- every actor resolves through a users.id. Guests are page-capability
-- RECEIVERS (driveboundary.go admits them), never presenter-verb actors;
-- a guest presenter target is legal and confers page verbs only, and the
-- guest's own session rides the public lobby surface (M3+), not these
-- authenticated routes.
--
-- BZ block (meet M2 = BZ272-277, this file's slice; sole registration site
-- for the Go surface is internal/meet/errors.go):
--   BZ272 presentation not found / foreign to the meeting (anti-oracle)
--   BZ273 presentation authority refused (not presenter / no Drive source right / target not live)
--   BZ274 stale presenter generation or checkpoint sequence (refresh checkpoint)
--   BZ275 presentation lifecycle conflict (illegal state-machine transition)
--   BZ276 presentation invalid arguments (page range, same-version switch, shape)
--   BZ277 annotation not admitted — since M4 (V267) this is ADMITTED-PATH
--         semantics: a well-formed snapshot commit or a clear through
--         meeting_presentation_annotation_commit is admitted; every
--         un-admitted annotation shape (malformed, empty, oversized,
--         reference-less commit) still refuses BZ277 fail-closed.

-- meeting_presentation_live: the ONE live-session predicate (the
-- meeting_recording_active genre). SECURITY DEFINER on purpose: the read
-- backstop (V265 §B) is participant-scoped, and the meeting_get
-- button-visibility signal must stay truthful for callers who are NOT yet
-- participants (a prejoin member deciding whether the stage exists) — an
-- invoker-rights read would fail OPEN for exactly those callers at the
-- native-RLS flip.
CREATE OR REPLACE FUNCTION meeting_presentation_live(p_meeting_id bigint)
RETURNS boolean LANGUAGE sql SECURITY DEFINER STABLE SET search_path = public AS $$
    SELECT EXISTS (SELECT 1 FROM public.meeting_presentations
                    WHERE meeting_id = p_meeting_id
                      AND status IN ('PREPARING','READY','ACTIVE','DEGRADED'))
$$;
SELECT apply_worker_ownership('meeting_presentation_live(bigint)'::regprocedure);

-- ── private helpers (the raise_breakout_invalid precedent: file-local
--    support functions for this one concern) ─────────────────────────────

-- _meeting_presentation_lock: fetch the session FOR UPDATE under the four-
-- axis fence's axis 1. Unknown id OR a session foreign to p_meeting_id is
-- one indistinguishable BZ272.
CREATE OR REPLACE FUNCTION _meeting_presentation_lock(
    p_meeting_id bigint, p_presentation_id bigint
) RETURNS meeting_presentations AS $$
DECLARE
    v_pres meeting_presentations;
BEGIN
    SELECT * INTO v_pres
      FROM meeting_presentations
     WHERE id = p_presentation_id AND meeting_id = p_meeting_id
       FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'presentation % not found on meeting %', p_presentation_id, p_meeting_id
            USING ERRCODE='BZ272', HINT='{"type":"notFound"}';
    END IF;
    RETURN v_pres;
END;
$$ LANGUAGE plpgsql;

-- _meeting_presentation_require_status: axis 3. Each verb names the exact
-- source states the frozen M0 table admits for its edge
-- (presentation.CanTransition): PREPARING→READY/FAILED/CANCELLED ·
-- READY→ACTIVE/FAILED/CANCELLED · ACTIVE→ENDED/REVOKED/DEGRADED ·
-- DEGRADED→ACTIVE · terminals final. The refusal names the CURRENT state
-- (the client refreshes the checkpoint), never the missing privilege.
CREATE OR REPLACE FUNCTION _meeting_presentation_require_status(
    p_status text, p_allowed text[]
) RETURNS void AS $$
BEGIN
    IF NOT (p_status = ANY (p_allowed)) THEN
        RAISE EXCEPTION 'presentation status % refuses this transition', p_status
            USING ERRCODE='BZ275',
                  HINT=jsonb_build_object('type','conflict','detail',
                    format('presentation is %s', p_status))::text;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- _meeting_presentation_require_live: axis 3 for presenter-of-record
-- changes — a grant/takeover is NOT a session transition, so it is lawful
-- in every LIVE state and unlawful in every terminal one (a terminal
-- session never resurrects, not even sideways).
CREATE OR REPLACE FUNCTION _meeting_presentation_require_live(
    p_status text
) RETURNS void AS $$
BEGIN
    IF p_status IN ('FAILED','CANCELLED','ENDED','REVOKED') THEN
        RAISE EXCEPTION 'presentation is %; terminal sessions never resurrect', p_status
            USING ERRCODE='BZ275',
                  HINT=jsonb_build_object('type','conflict','detail',
                    format('presentation is %s', p_status))::text;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- _meeting_presentation_require_generation: axis 4 for presenter-scoped
-- verbs. NULL p_expected means the caller is an authority verb that
-- bypasses the fence by design (takeover / host end); anything else must
-- equal the CURRENT presenter generation or it is exactly the
-- stalePresenterGeneration race the plan's registry names.
CREATE OR REPLACE FUNCTION _meeting_presentation_require_generation(
    p_generation bigint, p_expected bigint
) RETURNS void AS $$
BEGIN
    IF p_expected IS NOT NULL AND p_expected <> p_generation THEN
        RAISE EXCEPTION 'stale presenter generation % (current %)', p_expected, p_generation
            USING ERRCODE='BZ274',
                  HINT=jsonb_build_object('type','conflict','detail','stalePresenterGeneration',
                    'presenterGeneration', p_generation)::text;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- _meeting_presentation_require_sequence: the checkpoint-sequence half of
-- axis 4. The reducer's linearization point: a mutation composed against a
-- seq that is no longer current is out-of-order by construction (the
-- stale-controls-overwrite-current-page failure the plan names) and
-- refuses with the same refresh-checkpoint rescue as BZ274.
CREATE OR REPLACE FUNCTION _meeting_presentation_require_sequence(
    p_seq bigint, p_expected bigint
) RETURNS void AS $$
BEGIN
    IF p_expected IS NOT NULL AND p_expected <> p_seq THEN
        RAISE EXCEPTION 'stale checkpoint sequence % (current %)', p_expected, p_seq
            USING ERRCODE='BZ274',
                  HINT=jsonb_build_object('type','conflict','detail','presentationSequenceGap',
                    'checkpointSeq', p_seq)::text;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- _meeting_presentation_require_presenter: axis 2 for presenter-scoped
-- verbs — the actor's participant row must BE the session's current
-- presenter. (The comparison is on participant ids so a superseded
-- presenter cannot launder authority through a stale identity.) A NULL
-- actor — no live participant row: never joined, departed, or banned — is
-- an explicit refusal, never a silent pass: SQL's `id <> NULL` yields NULL
-- (not true), so without the arm an absent caller skipped this fence
-- entirely and was fenced only by the guessable generation/sequence pair.
CREATE OR REPLACE FUNCTION _meeting_presentation_require_presenter(
    p_presenter_participant_id bigint, p_participant_id bigint
) RETURNS void AS $$
BEGIN
    IF p_presenter_participant_id IS NULL
       OR p_participant_id IS NULL
       OR p_presenter_participant_id <> p_participant_id THEN
        RAISE EXCEPTION 'presenter authority required'
            USING ERRCODE='BZ273',
                  HINT='{"type":"forbidden","detail":"current presenter required"}';
    END IF;
END;
$$ LANGUAGE plpgsql;

-- _meeting_presentation_emit: commit ONE durable event + the state bump +
-- the push fact, under the caller's row lock. checkpoint_seq is per-session
-- monotonic (the events_seq_uq index is the belt: a double-emit inside one
-- verb would be a constraint failure, never a silent fork of history).
-- Returns the NEW checkpoint sequence and builds the wire fact jsonb the
-- push and the verb's return share byte for byte.
CREATE OR REPLACE FUNCTION _meeting_presentation_emit(
    p_presentation_id bigint, p_meeting_id bigint,
    p_presenter_generation bigint, p_page_index integer,
    p_manifest_generation bigint, p_status text,
    p_kind text, p_actor_user_id bigint, p_actor_participant_id bigint,
    p_payload jsonb
) RETURNS jsonb AS $$
DECLARE
    v_seq  bigint;
    v_fact jsonb;
BEGIN
    UPDATE meeting_presentations
       SET checkpoint_seq = checkpoint_seq + 1,
           last_actor_user_id = p_actor_user_id,
           updated_at = now()
     WHERE id = p_presentation_id
    RETURNING checkpoint_seq INTO v_seq;

    INSERT INTO meeting_presentation_events
         (presentation_id, meeting_id, checkpoint_seq, presenter_generation,
          kind, actor_user_id, actor_participant_id, payload)
    VALUES (p_presentation_id, p_meeting_id, v_seq, p_presenter_generation,
            p_kind, p_actor_user_id, p_actor_participant_id, p_payload);

    v_fact := jsonb_build_object(
        'presentationId', p_presentation_id,
        'status', p_status,
        'checkpointSeq', v_seq,
        'presenterGeneration', p_presenter_generation,
        'pageIndex', p_page_index,
        'manifestGeneration', p_manifest_generation);

    PERFORM notify_meet_state(p_meeting_id, 'presentation_state', v_fact);
    RETURN v_fact;
END;
$$ LANGUAGE plpgsql;

-- _meeting_presentation_participant_of: the CALLER's live participant row
-- id (host/cohost/member; guests have user_id NULL and never resolve one).
-- NULL when the caller has no live row (absent/left/banned).
CREATE OR REPLACE FUNCTION _meeting_presentation_participant_of(
    p_meeting_id bigint, p_user_id bigint
) RETURNS bigint AS $$
    SELECT id FROM meeting_participants
     WHERE meeting_id = p_meeting_id AND user_id = p_user_id
       AND left_at IS NULL AND banned_at IS NULL
     ORDER BY (role = 'host') DESC, (role = 'cohost') DESC, id LIMIT 1
$$ LANGUAGE sql STABLE;

-- ── prepare ──────────────────────────────────────────────────────────────
-- meeting_presentation_prepare: host/cohost AND current Drive source right
-- on the node ('preview' — the driveboundary.go capability authority).
-- Creates the session PREPARING with the caller as presenter (generation 1)
-- and derives source_sha256 from Drive's own version row (never from the
-- request — R2). The one-live-session partial unique index is the belt
-- behind the BZ275 existence guard.
CREATE OR REPLACE FUNCTION meeting_presentation_prepare(
    p_user_id bigint, p_meeting_id bigint,
    p_node_id bigint, p_version_id bigint, p_manifest_digest text
) RETURNS bigint AS $$
DECLARE
    v_meeting_state text;
    v_role          text;
    v_participant   bigint;
    v_sha           text;
    v_pres_id       bigint;
BEGIN
    SELECT state INTO v_meeting_state FROM meetings WHERE id = p_meeting_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'meeting % not found', p_meeting_id
            USING ERRCODE='BZ185', HINT='{"type":"notFound"}';
    END IF;
    v_role := meeting_require_authority(p_meeting_id, p_user_id);
    IF v_meeting_state = 'ended' THEN
        RAISE EXCEPTION 'meeting % has ended', p_meeting_id
            USING ERRCODE='BZ190', HINT='{"type":"conflict","detail":"meeting has ended"}';
    END IF;
    IF v_meeting_state <> 'live' THEN
        RAISE EXCEPTION 'meeting % is not live', p_meeting_id
            USING ERRCODE='BZ275', HINT='{"type":"conflict","detail":"meeting is not live"}';
    END IF;
    v_participant := _meeting_presentation_participant_of(p_meeting_id, p_user_id);
    IF v_participant IS NULL THEN
        RAISE EXCEPTION 'presentation authority refused on meeting %', p_meeting_id
            USING ERRCODE='BZ273', HINT='{"type":"forbidden","detail":"no live participant row"}';
    END IF;

    -- Source identity comes from DRIVE, in the same transaction: the node
    -- must be a live file, the version must belong to it, and the actor
    -- must hold Drive's own preview capability (page-only grants later
    -- never re-derive any of this).
    SELECT v.content_sha256 INTO v_sha
      FROM drive_file_versions v
      JOIN drive_nodes n ON n.id = v.file_node_id
     WHERE v.id = p_version_id AND n.id = p_node_id
       AND n.kind = 'file' AND n.deleted_at IS NULL;
    IF v_sha IS NULL THEN
        RAISE EXCEPTION 'drive source %/% not presentable', p_node_id, p_version_id
            USING ERRCODE='BZ272',
                  HINT='{"type":"notFound","detail":"sourceVersionGone"}';
    END IF;
    IF NOT drive_runtime_has_node_capability(p_user_id, p_node_id, 'preview') THEN
        RAISE EXCEPTION 'drive source rights required to present %', p_node_id
            USING ERRCODE='BZ273',
                  HINT='{"type":"forbidden","detail":"no source right on the Drive node"}';
    END IF;

    IF EXISTS (SELECT 1 FROM meeting_presentations
                WHERE meeting_id = p_meeting_id
                  AND status IN ('PREPARING','READY','ACTIVE','DEGRADED')) THEN
        RAISE EXCEPTION 'meeting % already has a live presentation', p_meeting_id
            USING ERRCODE='BZ275',
                  HINT='{"type":"conflict","detail":"a presentation session already exists"}';
    END IF;

    IF p_manifest_digest IS NULL OR p_manifest_digest !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'manifest digest must be a 64-hex digest'
            USING ERRCODE='BZ276',
                  HINT='{"type":"unprocessable","detail":"manifestDigest"}';
    END IF;

    INSERT INTO meeting_presentations
         (meeting_id, drive_node_id, drive_version_id, source_sha256,
          manifest_digest, status, presenter_participant_id, presenter_generation,
          initiated_by, last_actor_user_id)
    VALUES (p_meeting_id, p_node_id, p_version_id, v_sha,
            p_manifest_digest, 'PREPARING', v_participant, 1,
            p_user_id, p_user_id)
    RETURNING id INTO v_pres_id;

    PERFORM notify_meet_state(p_meeting_id, 'presentation_state',
        jsonb_build_object('presentationId', v_pres_id, 'status', 'PREPARING',
                           'checkpointSeq', 0, 'presenterGeneration', 1,
                           'pageIndex', 0, 'manifestGeneration', 1,
                           'driveNodeId', p_node_id, 'driveVersionId', p_version_id));
    RETURN v_pres_id;
END;
$$ LANGUAGE plpgsql;

-- ── ready ────────────────────────────────────────────────────────────────
-- meeting_presentation_ready: PREPARING → READY (rendition ready), the
-- durable 'ready' event. The M2 API-level confirm is host/cohost authority
-- (the rendition worker's own drain leg arrives with the M1 pipeline
-- wiring and rides this same verb). An optional refreshed digest rides
-- along when the rendition produced its pinned manifest identity; NULL
-- keeps the prepared digest.
CREATE OR REPLACE FUNCTION meeting_presentation_ready(
    p_user_id bigint, p_meeting_id bigint, p_presentation_id bigint,
    p_manifest_digest text DEFAULT NULL
) RETURNS jsonb AS $$
DECLARE
    v_pres   meeting_presentations;
    v_digest text;
BEGIN
    v_pres := _meeting_presentation_lock(p_meeting_id, p_presentation_id);
    PERFORM meeting_require_authority(p_meeting_id, p_user_id);
    PERFORM _meeting_presentation_require_status(v_pres.status, ARRAY['PREPARING']);
    IF p_manifest_digest IS NOT NULL THEN
        IF p_manifest_digest !~ '^[0-9a-f]{64}$' THEN
            RAISE EXCEPTION 'manifest digest must be a 64-hex digest'
                USING ERRCODE='BZ276',
                      HINT='{"type":"unprocessable","detail":"manifestDigest"}';
        END IF;
        v_digest := p_manifest_digest;
    ELSE
        v_digest := v_pres.manifest_digest;
    END IF;

    UPDATE meeting_presentations
       SET status = 'READY', manifest_digest = v_digest, updated_at = now()
     WHERE id = v_pres.id;

    RETURN _meeting_presentation_emit(
        v_pres.id, v_pres.meeting_id, v_pres.presenter_generation,
        v_pres.page_index, v_pres.manifest_generation, 'READY',
        'ready', p_user_id,
        _meeting_presentation_participant_of(p_meeting_id, p_user_id),
        jsonb_build_object('manifestDigest', v_digest));
END;
$$ LANGUAGE plpgsql;

-- ── start (present) ──────────────────────────────────────────────────────
-- meeting_presentation_start: READY → ACTIVE, the durable 'start' event
-- (the plan's prepare ─▶ ready ─▶ present arc). Presenter-scoped (host/
-- cohost bypass as authority verbs) under the generation fence;
-- started_at stamps once.
CREATE OR REPLACE FUNCTION meeting_presentation_start(
    p_user_id bigint, p_meeting_id bigint, p_presentation_id bigint,
    p_expected_presenter_generation bigint DEFAULT NULL
) RETURNS jsonb AS $$
DECLARE
    v_pres meeting_presentations;
BEGIN
    v_pres := _meeting_presentation_lock(p_meeting_id, p_presentation_id);
    PERFORM _meeting_presentation_require_presenter(v_pres.presenter_participant_id,
        _meeting_presentation_participant_of(p_meeting_id, p_user_id));
    PERFORM _meeting_presentation_require_generation(v_pres.presenter_generation,
        p_expected_presenter_generation);
    PERFORM _meeting_presentation_require_status(v_pres.status, ARRAY['READY']);

    UPDATE meeting_presentations
       SET status = 'ACTIVE', started_at = COALESCE(started_at, now()), updated_at = now()
     WHERE id = v_pres.id;

    RETURN _meeting_presentation_emit(
        v_pres.id, v_pres.meeting_id, v_pres.presenter_generation,
        v_pres.page_index, v_pres.manifest_generation, 'ACTIVE',
        'start', p_user_id,
        _meeting_presentation_participant_of(p_meeting_id, p_user_id),
        jsonb_build_object('pageIndex', v_pres.page_index));
END;
$$ LANGUAGE plpgsql;

-- ── page change ──────────────────────────────────────────────────────────
-- meeting_presentation_page: ACTIVE only, presenter only, BOTH fences
-- (generation + checkpoint sequence). The page payload is the closed
-- page.changed contract: a typed integer index in [0, 500) — the M0
-- MaxPagesPerManifest bound, mirrored in envelope.go's payload validator.
CREATE OR REPLACE FUNCTION meeting_presentation_page(
    p_user_id bigint, p_meeting_id bigint, p_presentation_id bigint,
    p_expected_presenter_generation bigint, p_expected_checkpoint_seq bigint,
    p_page_index integer
) RETURNS jsonb AS $$
DECLARE
    v_pres meeting_presentations;
BEGIN
    v_pres := _meeting_presentation_lock(p_meeting_id, p_presentation_id);
    PERFORM _meeting_presentation_require_presenter(v_pres.presenter_participant_id,
        _meeting_presentation_participant_of(p_meeting_id, p_user_id));
    PERFORM _meeting_presentation_require_generation(v_pres.presenter_generation,
        p_expected_presenter_generation);
    PERFORM _meeting_presentation_require_sequence(v_pres.checkpoint_seq,
        p_expected_checkpoint_seq);
    PERFORM _meeting_presentation_require_status(v_pres.status, ARRAY['ACTIVE']);
    IF p_page_index IS NULL OR p_page_index < 0 OR p_page_index >= 500 THEN
        RAISE EXCEPTION 'page index % outside [0,500)', p_page_index
            USING ERRCODE='BZ276',
                  HINT='{"type":"unprocessable","detail":"pageIndex"}';
    END IF;

    UPDATE meeting_presentations
       SET page_index = p_page_index, updated_at = now()
     WHERE id = v_pres.id;

    RETURN _meeting_presentation_emit(
        v_pres.id, v_pres.meeting_id, v_pres.presenter_generation,
        p_page_index, v_pres.manifest_generation, v_pres.status,
        'page.changed', p_user_id,
        _meeting_presentation_participant_of(p_meeting_id, p_user_id),
        jsonb_build_object('pageIndex', p_page_index));
END;
$$ LANGUAGE plpgsql;

-- ── presenter grant / takeover ───────────────────────────────────────────
-- meeting_presentation_presenter: handoff (p_takeover=false — the CURRENT
-- presenter under the generation fence, or a host/cohost) and takeover
-- (p_takeover=true — host/cohost authority, deliberately NO generation
-- fence: superseding a stale presenter is the verb's purpose, and the
-- departing-presenter rescue leaves controls unavailable until exactly
-- this). Lawful in every LIVE state (a presenter change is not a session
-- transition); a terminal session never resurrects sideways. Target must
-- be a CURRENT live participant row of THIS meeting (page-only authority:
-- the grant confers presenter verbs, never Drive rights — a guest target
-- can page-change but can never pass the source-switch capability check).
-- Every grant bumps presenter_generation: an old presenter's next fenced
-- verb refuses BZ274 by construction.
CREATE OR REPLACE FUNCTION meeting_presentation_presenter(
    p_user_id bigint, p_meeting_id bigint, p_presentation_id bigint,
    p_target_participant_id bigint, p_takeover boolean DEFAULT false,
    p_expected_presenter_generation bigint DEFAULT NULL
) RETURNS jsonb AS $$
DECLARE
    v_pres   meeting_presentations;
    v_actor  bigint;
    v_role   text;
    v_kind   text;
    v_target RECORD;
BEGIN
    v_pres := _meeting_presentation_lock(p_meeting_id, p_presentation_id);
    PERFORM _meeting_presentation_require_live(v_pres.status);
    v_actor := _meeting_presentation_participant_of(p_meeting_id, p_user_id);
    v_role := meeting_member_role(p_meeting_id, p_user_id);

    IF COALESCE(p_takeover, false) THEN
        -- takeover: host/cohost only, no generation fence.
        IF COALESCE(v_role, '') NOT IN ('host', 'cohost') THEN
            RAISE EXCEPTION 'host or cohost authority required to take over presentation %',
                p_presentation_id
                USING ERRCODE='BZ186', HINT='{"type":"forbidden"}';
        END IF;
        v_kind := 'presenter.takeover';
    ELSE
        -- grant: the current presenter (under the fence) or a host/cohost.
        IF COALESCE(v_role, '') IN ('host', 'cohost') THEN
            v_kind := 'presenter.granted';
        ELSE
            PERFORM _meeting_presentation_require_presenter(
                v_pres.presenter_participant_id, v_actor);
            PERFORM _meeting_presentation_require_generation(
                v_pres.presenter_generation, p_expected_presenter_generation);
            v_kind := 'presenter.granted';
        END IF;
    END IF;

    -- The target must be a CURRENT live participant of THIS meeting.
    SELECT id, role INTO v_target
      FROM meeting_participants
     WHERE id = p_target_participant_id AND meeting_id = p_meeting_id
       AND left_at IS NULL AND banned_at IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'presenter target % is not a live participant', p_target_participant_id
            USING ERRCODE='BZ273',
                  HINT='{"type":"forbidden","detail":"presenter target must be a live participant"}';
    END IF;

    UPDATE meeting_presentations
       SET presenter_participant_id = v_target.id,
           presenter_generation = presenter_generation + 1,
           updated_at = now()
     WHERE id = v_pres.id;

    RETURN _meeting_presentation_emit(
        v_pres.id, v_pres.meeting_id, v_pres.presenter_generation + 1,
        v_pres.page_index, v_pres.manifest_generation, v_pres.status,
        v_kind, p_user_id, v_actor,
        jsonb_build_object('targetParticipantId', v_target.id,
                           'targetRole', v_target.role));
END;
$$ LANGUAGE plpgsql;

-- ── source-version switch ────────────────────────────────────────────────
-- meeting_presentation_source_switch: an EXPLICIT presenter action to a
-- different immutable Drive version (a source edit never moves a pinned
-- session silently). Presenter-scoped under BOTH fences AND a live Drive
-- source right on the NEW node ('preview') — the security table's
-- "Actor's current Drive source rights"; handoff never launders it. The
-- new identity is re-derived from Drive (R2); manifest_generation bumps
-- (rendition identity changed) and the page resets to 0 (a NEW document's
-- first page — the manifest the digest pins has its own page set).
CREATE OR REPLACE FUNCTION meeting_presentation_source_switch(
    p_user_id bigint, p_meeting_id bigint, p_presentation_id bigint,
    p_new_node_id bigint, p_new_version_id bigint, p_new_manifest_digest text,
    p_expected_presenter_generation bigint DEFAULT NULL,
    p_expected_checkpoint_seq bigint DEFAULT NULL
) RETURNS jsonb AS $$
DECLARE
    v_pres         meeting_presentations;
    v_sha          text;
    v_generation   bigint;
BEGIN
    v_pres := _meeting_presentation_lock(p_meeting_id, p_presentation_id);
    PERFORM _meeting_presentation_require_presenter(v_pres.presenter_participant_id,
        _meeting_presentation_participant_of(p_meeting_id, p_user_id));
    PERFORM _meeting_presentation_require_generation(v_pres.presenter_generation,
        p_expected_presenter_generation);
    PERFORM _meeting_presentation_require_sequence(v_pres.checkpoint_seq,
        p_expected_checkpoint_seq);
    PERFORM _meeting_presentation_require_status(v_pres.status, ARRAY['READY','ACTIVE']);

    IF p_new_manifest_digest IS NULL OR p_new_manifest_digest !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'manifest digest must be a 64-hex digest'
            USING ERRCODE='BZ276',
                  HINT='{"type":"unprocessable","detail":"manifestDigest"}';
    END IF;

    SELECT v.content_sha256 INTO v_sha
      FROM drive_file_versions v
      JOIN drive_nodes n ON n.id = v.file_node_id
     WHERE v.id = p_new_version_id AND n.id = p_new_node_id
       AND n.kind = 'file' AND n.deleted_at IS NULL;
    IF v_sha IS NULL THEN
        RAISE EXCEPTION 'drive source %/% not presentable', p_new_node_id, p_new_version_id
            USING ERRCODE='BZ272',
                  HINT='{"type":"notFound","detail":"sourceVersionGone"}';
    END IF;
    IF v_pres.drive_node_id = p_new_node_id AND v_pres.drive_version_id = p_new_version_id THEN
        RAISE EXCEPTION 'source switch must name a different version'
            USING ERRCODE='BZ276',
                  HINT='{"type":"unprocessable","detail":"switch names the pinned version"}';
    END IF;
    IF NOT drive_runtime_has_node_capability(p_user_id, p_new_node_id, 'preview') THEN
        RAISE EXCEPTION 'drive source rights required to switch to %', p_new_node_id
            USING ERRCODE='BZ273',
                  HINT='{"type":"forbidden","detail":"no source right on the Drive node"}';
    END IF;

    UPDATE meeting_presentations
       SET drive_node_id = p_new_node_id,
           drive_version_id = p_new_version_id,
           source_sha256 = v_sha,
           manifest_digest = p_new_manifest_digest,
           manifest_generation = manifest_generation + 1,
           page_index = 0,
           updated_at = now()
     WHERE id = v_pres.id
    RETURNING manifest_generation INTO v_generation;

    RETURN _meeting_presentation_emit(
        v_pres.id, v_pres.meeting_id, v_pres.presenter_generation,
        0, v_generation, v_pres.status,
        'source.switched', p_user_id,
        _meeting_presentation_participant_of(p_meeting_id, p_user_id),
        jsonb_build_object('driveNodeId', p_new_node_id,
                           'driveVersionId', p_new_version_id,
                           'manifestDigest', p_new_manifest_digest,
                           'manifestGeneration', v_generation));
END;
$$ LANGUAGE plpgsql;

-- ── degrade / recover ────────────────────────────────────────────────────
-- meeting_presentation_degrade: ACTIVE → DEGRADED (renderer lost), the
-- ONLY edge into DEGRADED. The durable vocabulary has no failure kind —
-- it rides the 'fallback.changed' event plus the push fact, and the state
-- column stays the authority. Presenter (under the fence) or host/cohost.
CREATE OR REPLACE FUNCTION meeting_presentation_degrade(
    p_user_id bigint, p_meeting_id bigint, p_presentation_id bigint,
    p_expected_presenter_generation bigint DEFAULT NULL, p_reason text DEFAULT NULL
) RETURNS jsonb AS $$
DECLARE
    v_pres  meeting_presentations;
    v_actor bigint;
    v_role  text;
BEGIN
    v_pres := _meeting_presentation_lock(p_meeting_id, p_presentation_id);
    v_actor := _meeting_presentation_participant_of(p_meeting_id, p_user_id);
    v_role := meeting_member_role(p_meeting_id, p_user_id);
    IF COALESCE(v_role, '') IN ('host', 'cohost') THEN
        NULL;  -- authority verb: no generation fence
    ELSE
        PERFORM _meeting_presentation_require_presenter(
            v_pres.presenter_participant_id, v_actor);
        PERFORM _meeting_presentation_require_generation(
            v_pres.presenter_generation, p_expected_presenter_generation);
    END IF;
    PERFORM _meeting_presentation_require_status(v_pres.status, ARRAY['ACTIVE']);

    UPDATE meeting_presentations
       SET status = 'DEGRADED', updated_at = now()
     WHERE id = v_pres.id;

    RETURN _meeting_presentation_emit(
        v_pres.id, v_pres.meeting_id, v_pres.presenter_generation,
        v_pres.page_index, v_pres.manifest_generation, 'DEGRADED',
        'fallback.changed', p_user_id, v_actor,
        jsonb_build_object('degraded', true, 'reason', COALESCE(p_reason, 'renderer lost')));
END;
$$ LANGUAGE plpgsql;

-- meeting_presentation_recover: DEGRADED → ACTIVE (the ONLY outgoing edge
-- of DEGRADED in the frozen table — recover, never a direct end or
-- resurrect). Presenter (under the fence — the presenter re-asserts on the
-- recovered renderer) or host/cohost.
CREATE OR REPLACE FUNCTION meeting_presentation_recover(
    p_user_id bigint, p_meeting_id bigint, p_presentation_id bigint,
    p_expected_presenter_generation bigint DEFAULT NULL
) RETURNS jsonb AS $$
DECLARE
    v_pres  meeting_presentations;
    v_actor bigint;
    v_role  text;
BEGIN
    v_pres := _meeting_presentation_lock(p_meeting_id, p_presentation_id);
    v_actor := _meeting_presentation_participant_of(p_meeting_id, p_user_id);
    v_role := meeting_member_role(p_meeting_id, p_user_id);
    IF COALESCE(v_role, '') IN ('host', 'cohost') THEN
        NULL;
    ELSE
        PERFORM _meeting_presentation_require_presenter(
            v_pres.presenter_participant_id, v_actor);
        PERFORM _meeting_presentation_require_generation(
            v_pres.presenter_generation, p_expected_presenter_generation);
    END IF;
    PERFORM _meeting_presentation_require_status(v_pres.status, ARRAY['DEGRADED']);

    UPDATE meeting_presentations
       SET status = 'ACTIVE', updated_at = now()
     WHERE id = v_pres.id;

    RETURN _meeting_presentation_emit(
        v_pres.id, v_pres.meeting_id, v_pres.presenter_generation,
        v_pres.page_index, v_pres.manifest_generation, 'ACTIVE',
        'fallback.changed', p_user_id, v_actor,
        jsonb_build_object('degraded', false));
END;
$$ LANGUAGE plpgsql;

-- ── end / revoke ─────────────────────────────────────────────────────────
-- meeting_presentation_end: the user-visible end. ACTIVE → ENDED;
-- PREPARING/READY → CANCELLED (nothing was presented yet — the state
-- machine's cancel arm, never a fabricated ENDED). DEGRADED refuses:
-- recover first, then end (the frozen table has no DEGRADED→ENDED edge).
-- ACTIVE end is presenter (under the fence) or host/cohost; PREPARING/
-- READY cancel is a host/cohost authority verb (the BZ186 arm).
CREATE OR REPLACE FUNCTION meeting_presentation_end(
    p_user_id bigint, p_meeting_id bigint, p_presentation_id bigint,
    p_expected_presenter_generation bigint DEFAULT NULL
) RETURNS jsonb AS $$
DECLARE
    v_pres   meeting_presentations;
    v_actor  bigint;
    v_role   text;
    v_status text;
BEGIN
    v_pres := _meeting_presentation_lock(p_meeting_id, p_presentation_id);
    v_actor := _meeting_presentation_participant_of(p_meeting_id, p_user_id);
    v_role := meeting_member_role(p_meeting_id, p_user_id);

    IF v_pres.status = 'ACTIVE' THEN
        IF COALESCE(v_role, '') IN ('host', 'cohost') THEN
            NULL;
        ELSE
            PERFORM _meeting_presentation_require_presenter(
                v_pres.presenter_participant_id, v_actor);
            PERFORM _meeting_presentation_require_generation(
                v_pres.presenter_generation, p_expected_presenter_generation);
        END IF;
        v_status := 'ENDED';
    ELSIF v_pres.status IN ('PREPARING', 'READY') THEN
        PERFORM meeting_require_authority(p_meeting_id, p_user_id);
        v_status := 'CANCELLED';
    ELSE
        PERFORM _meeting_presentation_require_status(v_pres.status,
            ARRAY['PREPARING','READY','ACTIVE']);
    END IF;

    UPDATE meeting_presentations
       SET status = v_status, ended_at = now(), updated_at = now()
     WHERE id = v_pres.id;

    RETURN _meeting_presentation_emit(
        v_pres.id, v_pres.meeting_id, v_pres.presenter_generation,
        v_pres.page_index, v_pres.manifest_generation, v_status,
        'end', p_user_id, v_actor,
        jsonb_build_object('status', v_status));
END;
$$ LANGUAGE plpgsql;

-- meeting_presentation_revoke: source-authority revocation. ACTIVE →
-- REVOKED (presented material loses its authorization); PREPARING/READY →
-- FAILED (rendition access was lost before anything was presented — both
-- edges exist in the frozen table). Host/cohost only: revocation fences
-- presenter events and is never a presenter self-service verb. Capability
-- expiry is the serving layer's read-side consequence (the checkpoint read
-- reports the terminal state); already-rendered pixels are honestly out of
-- reach.
CREATE OR REPLACE FUNCTION meeting_presentation_revoke(
    p_user_id bigint, p_meeting_id bigint, p_presentation_id bigint,
    p_reason text DEFAULT NULL
) RETURNS jsonb AS $$
DECLARE
    v_pres   meeting_presentations;
    v_status text;
BEGIN
    v_pres := _meeting_presentation_lock(p_meeting_id, p_presentation_id);
    PERFORM meeting_require_authority(p_meeting_id, p_user_id);

    IF v_pres.status = 'ACTIVE' THEN
        v_status := 'REVOKED';
    ELSIF v_pres.status IN ('PREPARING', 'READY') THEN
        v_status := 'FAILED';
    ELSE
        PERFORM _meeting_presentation_require_status(v_pres.status,
            ARRAY['ACTIVE','PREPARING','READY']);
    END IF;

    UPDATE meeting_presentations
       SET status = v_status, ended_at = now(), updated_at = now()
     WHERE id = v_pres.id;

    RETURN _meeting_presentation_emit(
        v_pres.id, v_pres.meeting_id, v_pres.presenter_generation,
        v_pres.page_index, v_pres.manifest_generation, v_status,
        'end', p_user_id,
        _meeting_presentation_participant_of(p_meeting_id, p_user_id),
        jsonb_build_object('status', v_status,
                           'reason', COALESCE(p_reason, 'presentationAccessRevoked')));
END;
$$ LANGUAGE plpgsql;

-- ── annotation admission (the M4 flip; BZ277 = admitted-path semantics) ──
-- meeting_presentation_annotation_commit: the M4 DURABLE annotation commit
-- (plan "Presentation state": "clear or commit annotation snapshot" durable
-- event; "Annotation persistence and snapshot/reconnect convergence are M4
-- acceptance work"). The M2 always-refusal narrowed to ADMITTED-PATH
-- semantics — the guard was not removed, it gained exactly one admitting
-- writer. The four-axis fence runs in the file's documented order:
--   1. participant + session identity (BZ272 anti-oracle, _lock).
--   2. authority — PRESENTER-scope (BZ273): an annotation commit mutates the
--      presented checkpoint the same way a page change does; the plan's
--      security table has no attendee durable-mutation verb, and M3's
--      attendee ink stays ephemeral. Presenter generation fence (BZ274).
--   3. lifecycle — ACTIVE only (BZ275; the page/handoff/annotate arc).
--   4. checkpoint sequence fence (BZ274) — the linearization point.
-- Then the ADMITTED-SHAPE gate (BZ277): a commit is admitted ONLY as
--   · a well-formed snapshot commit — the exact serialized snapshot text
--     whose byte size is 1..16384 (the stored-object bound; a larger
--     snapshot has no home here and needs the separately designed
--     reference-storage contract, never fragmentation) and whose digest and
--     size are DERIVED in-database from those bytes (never request-trusted,
--     R2) — or
--   · a clear (p_clear=true, no snapshot).
-- Every other annotation-shaped call still refuses BZ277.
-- The commit, IN ONE TRANSACTION: the snapshot ledger row (V267 §A — bound
-- to the NEXT checkpoint seq, its .sjrec StableRef path derived from
-- (presentation, seq)), the checkpoint's annotation_snapshot_ref, the
-- durable annotation.committed/cleared event, the state bump, and the push
-- fact — logic where the data is. The returned fact carries an `annotation`
-- rider (snapshotRef/sha256/byteSize) the Go surface builds the versioned
-- envelope payload from (the 14000-byte wire bound is respected by
-- construction: the envelope carries the bounded reference, never the
-- snapshot bytes — "larger durable snapshots use an authorized bounded
-- reference/read path").
CREATE OR REPLACE FUNCTION meeting_presentation_annotation_commit(
    p_user_id bigint, p_meeting_id bigint, p_presentation_id bigint,
    p_expected_presenter_generation bigint, p_expected_checkpoint_seq bigint,
    p_clear boolean,
    p_snapshot_text text DEFAULT NULL,
    p_snapshot_bytes integer DEFAULT NULL
) RETURNS jsonb AS $$
DECLARE
    v_pres  meeting_presentations;
    v_actor bigint;
    v_kind  text;
    v_ref   text;
    v_sha   text;
    v_bytes integer;
    v_fact  jsonb;
BEGIN
    v_pres := _meeting_presentation_lock(p_meeting_id, p_presentation_id);
    v_actor := _meeting_presentation_participant_of(p_meeting_id, p_user_id);
    PERFORM _meeting_presentation_require_presenter(v_pres.presenter_participant_id, v_actor);
    PERFORM _meeting_presentation_require_generation(v_pres.presenter_generation,
        p_expected_presenter_generation);
    PERFORM _meeting_presentation_require_sequence(v_pres.checkpoint_seq,
        p_expected_checkpoint_seq);
    PERFORM _meeting_presentation_require_status(v_pres.status, ARRAY['ACTIVE']);

    IF COALESCE(p_clear, false) THEN
        -- Clear: the checkpoint's snapshot ref releases; history (the event
        -- rail and the ledger row) is never rewritten.
        v_kind := 'annotation.cleared';
        UPDATE meeting_presentations
           SET annotation_snapshot_ref = NULL, updated_at = now()
         WHERE id = v_pres.id;
    ELSE
        v_kind := 'annotation.committed';
        v_bytes := COALESCE(p_snapshot_bytes, 0);
        IF p_snapshot_text IS NULL OR v_bytes < 1 OR v_bytes > 16384
           OR octet_length(convert_to(p_snapshot_text, 'UTF8')) <> v_bytes THEN
            RAISE EXCEPTION 'annotation snapshot is not an admissible committed shape (missing, empty, or over the 16384-byte stored-object bound)'
                USING ERRCODE='BZ277',
                      HINT='{"type":"forbidden","detail":"annotationNotAdmitted","detailReason":"snapshotShape"}';
        END IF;
        v_sha := encode(sha256(convert_to(p_snapshot_text, 'UTF8')), 'hex');
        -- The StableRef path derives from the identity the snapshot binds:
        -- the NEXT checkpoint sequence (the emit below commits this seq).
        v_ref := 'annotations/p' || v_pres.id::text || '-s'
                 || (v_pres.checkpoint_seq + 1)::text || '.json';
        UPDATE meeting_presentations
           SET annotation_snapshot_ref = v_ref, updated_at = now()
         WHERE id = v_pres.id;
        INSERT INTO meeting_presentation_annotations
             (presentation_id, meeting_id, checkpoint_seq, presenter_generation,
              actor_user_id, actor_participant_id, snapshot_path, content,
              content_sha256, byte_size)
        VALUES (v_pres.id, v_pres.meeting_id, v_pres.checkpoint_seq + 1,
                v_pres.presenter_generation, p_user_id, v_actor, v_ref,
                p_snapshot_text, v_sha, v_bytes);
    END IF;

    v_fact := _meeting_presentation_emit(
        v_pres.id, v_pres.meeting_id, v_pres.presenter_generation,
        v_pres.page_index, v_pres.manifest_generation, v_pres.status,
        v_kind, p_user_id, v_actor,
        CASE WHEN v_kind = 'annotation.committed'
             THEN jsonb_build_object('snapshotRef', v_ref,
                                     'sha256', v_sha,
                                     'byteSize', v_bytes)
             ELSE NULL END);
    IF v_kind = 'annotation.committed' THEN
        v_fact := v_fact || jsonb_build_object('annotation',
            jsonb_build_object('snapshotRef', v_ref, 'sha256', v_sha,
                               'byteSize', v_bytes));
    END IF;
    RETURN v_fact;
END;
$$ LANGUAGE plpgsql;

-- meeting_presentation_annotation_read: the authorized bounded reference/
-- read path the envelope contract names for durable snapshots — the
-- reconnect-convergence half of the admission (checkpoint read says WHAT is
-- current; this says the snapshot's exact committed bytes). Scoped to
-- HISTORICAL attendees (meeting_attendee_role — retained material, the
-- post-end gate the DOX prescribes; V267 §B's RLS backstop matches).
-- Unknown id / foreign meeting / non-attendee are the same indistinguishable
-- BZ272. No snapshot yet is a NULL `snapshot` member (truthful absence),
-- never an error.
CREATE OR REPLACE FUNCTION meeting_presentation_annotation_read(
    p_user_id bigint, p_meeting_id bigint, p_presentation_id bigint
) RETURNS jsonb AS $$
DECLARE
    v_out jsonb;
BEGIN
    IF meeting_attendee_role(p_meeting_id, p_user_id) IS NULL THEN
        RAISE EXCEPTION 'presentation % not found on meeting %', p_presentation_id, p_meeting_id
            USING ERRCODE='BZ272', HINT='{"type":"notFound"}';
    END IF;
    SELECT jsonb_build_object(
             'presentationId', p.id,
             'snapshot', (
               SELECT jsonb_build_object(
                        'snapshotRef', a.snapshot_path,
                        'sha256', a.content_sha256,
                        'byteSize', a.byte_size,
                        'checkpointSeq', a.checkpoint_seq,
                        'presenterGeneration', a.presenter_generation,
                        'content', a.content,
                        'createdAt', a.created_at)
                 FROM meeting_presentation_annotations a
                WHERE a.presentation_id = p.id
                ORDER BY a.checkpoint_seq DESC
                LIMIT 1)
           ) INTO v_out
      FROM meeting_presentations p
     WHERE p.id = p_presentation_id AND p.meeting_id = p_meeting_id;
    IF v_out IS NULL THEN
        RAISE EXCEPTION 'presentation % not found on meeting %', p_presentation_id, p_meeting_id
            USING ERRCODE='BZ272', HINT='{"type":"notFound"}';
    END IF;
    RETURN v_out;
END;
$$ LANGUAGE plpgsql;

-- ── the authorized checkpoint read ───────────────────────────────────────
-- meeting_presentation_checkpoint: the attendee-scoped projection the
-- coalesced client refresh (M1's CheckpointRefresher) converges on, and the
-- field set a versioned envelope is built FROM. Scoped by
-- meeting_attendee_role (the HISTORICAL attendee gate, V129 — a host who
-- left, or a post-end read, still converges; an absent caller does not).
-- Unknown id / foreign meeting / non-attendee are the same
-- indistinguishable BZ272. These are committed facts, not frames: clients
-- never promote a received envelope past what an authorized read like this
-- one confirms.
CREATE OR REPLACE FUNCTION meeting_presentation_checkpoint(
    p_user_id bigint, p_meeting_id bigint, p_presentation_id bigint
) RETURNS jsonb AS $$
DECLARE
    v_out jsonb;
BEGIN
    IF meeting_attendee_role(p_meeting_id, p_user_id) IS NULL THEN
        RAISE EXCEPTION 'presentation % not found on meeting %', p_presentation_id, p_meeting_id
            USING ERRCODE='BZ272', HINT='{"type":"notFound"}';
    END IF;

    SELECT jsonb_build_object(
             'presentationId', p.id,
             'meetingId', p.meeting_id,
             'status', p.status,
             'checkpointSeq', p.checkpoint_seq,
             'presenterGeneration', p.presenter_generation,
             'presenterParticipantId', p.presenter_participant_id,
             'pageIndex', p.page_index,
             'manifestGeneration', p.manifest_generation,
             'manifestDigest', p.manifest_digest,
             'driveNodeId', p.drive_node_id,
             'driveVersionId', p.drive_version_id,
             'sourceSha256', p.source_sha256,
             'annotationSnapshotRef', p.annotation_snapshot_ref,
             'startedAt', p.started_at,
             'endedAt', p.ended_at,
             'myParticipantId', _meeting_presentation_participant_of(p.meeting_id, p_user_id),
             'amPresenter', (p.presenter_participant_id
                             = _meeting_presentation_participant_of(p.meeting_id, p_user_id)),
             'events', (
               SELECT COALESCE(jsonb_agg(jsonb_build_object(
                        'checkpointSeq', e.checkpoint_seq,
                        'presenterGeneration', e.presenter_generation,
                        'kind', e.kind,
                        'payload', e.payload,
                        'createdAt', e.created_at
                      ) ORDER BY e.checkpoint_seq), '[]'::jsonb)
                 FROM meeting_presentation_events e
                WHERE e.presentation_id = p.id)
           ) INTO v_out
      FROM meeting_presentations p
     WHERE p.id = p_presentation_id AND p.meeting_id = p_meeting_id;
    IF v_out IS NULL THEN
        RAISE EXCEPTION 'presentation % not found on meeting %', p_presentation_id, p_meeting_id
            USING ERRCODE='BZ272', HINT='{"type":"notFound"}';
    END IF;
    RETURN v_out;
END;
$$ LANGUAGE plpgsql;
