-- mailserver/sql/reducers/drive_meet_history_emit.sql
-- The MEET Drive-History emitter's owning Drive authority (the named M4/M1
-- follow-up: "Drive History events" — mailserver/internal/meet/DOX.md's
-- linkage note and retired-docs:verification/2026-09-19-old5-wave4.md).
--
-- WHY A DRIVE REDUCER: the only Drive-side history surfaces are
-- drive_audit_log (V114 §9.3 — the per-space TAMPER-EVIDENT CHAIN, checksum
-- in after_state, "maintained exclusively by Drive's own reducers") and the
-- drive_changes feed. A meet-side writer appending into Drive's chain is the
-- second-coordinator move the MEET plan forbids. So the ingest lives HERE,
-- in Drive's reducer lane, and appends THROUGH drive_access_audit — the
-- owning chain writer — while meet (internal/meet/drive_history_emitter.go's
-- worker leg) only CALLS it at the three frozen lifecycle points. Meet
-- contributes ordered human events; Drive History stays the sole timeline
-- owner.
--
-- CLOSED CONTRACT (restraint): exactly three lifecycle points emit, one
-- chain entry per meet fact, never rewritten:
--   · 'recording.stopped'      → action 'meet.recording.stopped'
--     (rec_state='stopped'; attaches to the package's ready export
--     node/version — a package that never exported has NO Drive home and is
--     truthfully receipted 'absent', never synthesized into a chain).
--   · 'annotation.committed'   → action 'meet.annotation.committed'
--     (a V267 ledger row; attaches to the session's pinned node/version).
--   · 'presentation.pinned'    → action 'meet.presentation.pinned'
--     (the V265 session's pinned source identity; attaches to it).
-- No bulk backfill, no second coordinator, no changes to M0–M4 behavior:
-- the emitter is observational (nothing in meet reads these receipts).
--
-- IDEMPOTENCE: a per-fact advisory xact lock serializes concurrent emits
-- (the hashtext genre of drive_access_audit's per-space lock); the V269
-- receipt ledger's UNIQUE (source_kind, source_id) is the durable belt. A
-- replay returns the committed receipt verbatim (replayed:true) — a retried
-- emit can never mint a second chain entry. The chain append and the
-- receipt land in ONE transaction: a crash between them rolls both back,
-- so the worker's next tick re-emits cleanly.
--
-- Security: SECURITY DEFINER + apply_worker_ownership (setjoin_worker owns
-- it — BYPASSRLS — so drive_access_audit's MAX(id) sees the whole chain
-- regardless of caller; the drive_access_audit header documents exactly
-- this trap). EXECUTE revoked from PUBLIC. Refusals: BZ276 = unknown source
-- kind (closed catalog); BZ272 = unknown meet fact (the indistinguishable
-- not-found — the annotation-read convention for foreign/absent ids).
CREATE OR REPLACE FUNCTION drive_meet_history_emit(
  p_source_kind text,
  p_source_id   bigint
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_action    text;
  v_meeting   bigint;
  v_recording bigint;
  v_actor     bigint;
  v_node      bigint;
  v_version   bigint;
  v_space     bigint;
  v_seq       bigint;
  v_ref       text;
  v_sha       text;
  v_bytes     integer;
  v_status    text;
  v_after     jsonb;
  v_notes     text;
  v_audit_id  bigint;
  v_existing  drive_meet_history_events%ROWTYPE;
BEGIN
  -- The closed source-kind catalog → its audit action. Anything else is
  -- BZ276 (the argument-guard code the meet lane maps to
  -- presentation-invalid-arguments; the Go caller only logs this).
  v_action := CASE p_source_kind
                WHEN 'recording.stopped'    THEN 'meet.recording.stopped'
                WHEN 'annotation.committed' THEN 'meet.annotation.committed'
                WHEN 'presentation.pinned'  THEN 'meet.presentation.pinned'
              END;
  IF v_action IS NULL THEN
    RAISE EXCEPTION 'unknown meet history source kind %', p_source_kind
      USING ERRCODE='BZ276',
            HINT='{"type":"unprocessable","detail":"sourceKind"}';
  END IF;
  IF p_source_id IS NULL OR p_source_id < 1 THEN
    RAISE EXCEPTION 'meet history source id must be a positive fact id'
      USING ERRCODE='BZ276',
            HINT='{"type":"unprocessable","detail":"sourceId"}';
  END IF;

  -- One emit per fact at a time; the receipt check below is race-free under
  -- it, so a double emit can never double-append (the chain stays one
  -- entry per fact even under concurrent worker ticks).
  PERFORM pg_advisory_xact_lock(
    hashtext('drive_meet_history_emit:' || p_source_kind || ':' || p_source_id::text));

  SELECT * INTO v_existing
    FROM drive_meet_history_events
   WHERE source_kind = p_source_kind AND source_id = p_source_id;
  IF FOUND THEN
    RETURN jsonb_build_object(
      'status', v_existing.state,
      'replayed', TRUE,
      'spaceId', v_existing.space_id,
      'driveNodeId', v_existing.drive_node_id,
      'driveVersionId', v_existing.drive_version_id,
      'auditId', v_existing.audit_id,
      'action', v_existing.audit_action);
  END IF;

  -- Resolve the fact + its Drive attachment from COMMITTED meet state
  -- (never request-owned identity — the R2 posture). Every arm below reads
  -- the surfaces the meet reducers own; this function writes nothing on the
  -- meet side.
  IF p_source_kind = 'recording.stopped' THEN
    SELECT r.meeting_id, r.started_by, r.id
      INTO v_meeting, v_actor, v_recording
      FROM meeting_semantic_recordings r
     WHERE r.id = p_source_id AND r.rec_state = 'stopped';
    IF NOT FOUND THEN
      RAISE EXCEPTION 'meet recording % is not a stopped package', p_source_id
        USING ERRCODE='BZ272', HINT='{"type":"notFound"}';
    END IF;
    -- The attachment: the package's ready export — the rendition bound into
    -- Drive. No ready export (or its node row is gone) ⇒ no Drive home ⇒
    -- truthful 'absent' receipt (never a synthesized chain entry, never a
    -- retry-forever).
    SELECT e.drive_node_id, e.drive_version_id
      INTO v_node, v_version
      FROM meeting_semantic_exports e
     WHERE e.recording_id = p_source_id AND e.state = 'ready'
     ORDER BY e.generation DESC
     LIMIT 1;
    IF v_node IS NULL OR NOT EXISTS (
         SELECT 1 FROM drive_nodes n WHERE n.id = v_node) THEN
      INSERT INTO drive_meet_history_events
           (source_kind, source_id, state, meeting_id, recording_id, actor_user_id)
      VALUES (p_source_kind, p_source_id, 'absent', v_meeting, v_recording, v_actor);
      RETURN jsonb_build_object('status', 'absent', 'replayed', FALSE,
                                'meetingId', v_meeting, 'recordingId', v_recording);
    END IF;
    v_after := jsonb_build_object(
      'sourceKind', p_source_kind, 'meetingId', v_meeting,
      'recordingId', v_recording, 'driveVersionId', v_version);
    v_notes := 'meet: recording #' || v_recording::text
             || ' stopped — meeting #' || v_meeting::text;
  ELSIF p_source_kind = 'annotation.committed' THEN
    SELECT a.meeting_id, a.actor_user_id,
           p.drive_node_id, p.drive_version_id,
           a.checkpoint_seq, a.snapshot_path,
           a.content_sha256, a.byte_size
      INTO v_meeting, v_actor,
           v_node, v_version,
           v_seq, v_ref, v_sha, v_bytes
      FROM meeting_presentation_annotations a
      JOIN meeting_presentations p ON p.id = a.presentation_id
     WHERE a.id = p_source_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'meet annotation % not found', p_source_id
        USING ERRCODE='BZ272', HINT='{"type":"notFound"}';
    END IF;
    -- The content identity triple is DERIVED from the ledger row (V267
    -- CHECKs re-derive it from the stored bytes in-database — never
    -- request-trusted), carried as the bounded reference, never snapshot
    -- bytes.
    v_after := jsonb_build_object(
      'sourceKind', p_source_kind, 'meetingId', v_meeting,
      'presentationId', p_source_id, 'checkpointSeq', v_seq,
      'snapshotRef', v_ref, 'sha256', v_sha, 'byteSize', v_bytes);
    v_notes := 'meet: annotation committed on presentation #' || p_source_id::text
             || ' (checkpoint ' || v_seq::text || ')';
  ELSE -- 'presentation.pinned'
    SELECT p.meeting_id, p.initiated_by,
           p.drive_node_id, p.drive_version_id, p.status
      INTO v_meeting, v_actor, v_node, v_version, v_status
      FROM meeting_presentations p
     WHERE p.id = p_source_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'meet presentation % not found', p_source_id
        USING ERRCODE='BZ272', HINT='{"type":"notFound"}';
    END IF;
    v_after := jsonb_build_object(
      'sourceKind', p_source_kind, 'meetingId', v_meeting,
      'presentationId', p_source_id, 'driveVersionId', v_version,
      'sessionStatus', v_status);
    v_notes := 'meet: presentation #' || p_source_id::text
             || ' pinned to this version — meeting #' || v_meeting::text;
  END IF;

  -- The attachment node's OWN space owns the chain entry (the chain is
  -- per-space; the emitter never picks a space by caller identity).
  SELECT n.space_id INTO v_space FROM drive_nodes n WHERE n.id = v_node;

  -- Append through the OWNING chain writer (V114 §9.3 discipline: the
  -- checksum, the per-space advisory lock and MAX(id)+1 are
  -- drive_access_audit's, never duplicated here). target_type='node' makes
  -- the entry surface in drive_file_history_query's audit source for the
  -- attached file.
  v_audit_id := drive_access_audit(v_actor, v_space, v_action, 'node', v_node,
                                   NULL, v_after, NULL, v_notes);

  INSERT INTO drive_meet_history_events
       (source_kind, source_id, state, space_id, drive_node_id,
        drive_version_id, audit_id, audit_action, meeting_id,
        recording_id, actor_user_id)
  VALUES (p_source_kind, p_source_id, 'emitted', v_space, v_node,
          v_version, v_audit_id, v_action, v_meeting,
          v_recording, v_actor);

  RETURN jsonb_build_object(
    'status', 'emitted', 'replayed', FALSE,
    'spaceId', v_space, 'driveNodeId', v_node,
    'driveVersionId', v_version, 'auditId', v_audit_id, 'action', v_action);
END;
$$;

SELECT apply_worker_ownership('drive_meet_history_emit(text,bigint)'::regprocedure);
