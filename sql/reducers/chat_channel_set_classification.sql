-- chat_channel_set_classification.sql — Chat A4a Task 8: the gxp/WORM
-- upgrade reducer.
--
-- SECURITY DEFINER + apply_worker_ownership: chat_channels has no UPDATE
-- policy (V119 FORCE-RLS, deny-by-default is the correct fail-closed
-- interim — Global Constraints), so an invoker-rights UPDATE would match 0
-- rows and surface as a bogus "channel missing" (the recurring
-- DEFINER-under-FORCE-RLS trap). Authorization is route-declared
-- (chat.compliance_manage, Task 11a) — this reducer takes the admin id for
-- audit provenance only.
--
-- Only 'regular' -> 'gxp' is a valid transition (BZ195); the reverse is
-- already forbidden by the V126 trg_chat_channel_no_downgrade_fn trigger
-- (BZ192) — this precondition check is the friendlier belt, not the backstop.
-- retention_days/worm_mode must already be set on the channel (drive's own
-- ordering, drive_space_set_classification.sql:28-31) — Task 11a's admin
-- handler sets them first, then calls this.
--
-- Pillar C2 Task 2 (Q7 arm 2): a channel already bound to a federated room
-- (federated_room_id IS NOT NULL) may never be classified gxp — a WORM
-- claim unenforceable on remote member orgs' independent copies would be a
-- false compliance claim. Arm 1 (federation_room_create refusing a gxp
-- channel, BZ210) lives in federation_room_create.sql; this is the reverse
-- direction, same code.
CREATE OR REPLACE FUNCTION chat_channel_set_classification(
  p_admin_user_id BIGINT, p_channel_id BIGINT, p_new TEXT
) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_old     TEXT;
  v_ret     INT;
  v_worm    TEXT;
  v_room_id TEXT;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key = 'feature.chat_compliance'), FALSE) THEN
    RAISE EXCEPTION 'chat compliance is disabled' USING ERRCODE='BZ195',
      HINT='{"type":"invalidArguments","detail":"compliance disabled"}';
  END IF;

  SELECT classification, retention_days, worm_mode, federated_room_id
    INTO v_old, v_ret, v_worm, v_room_id
    FROM chat_channels WHERE id = p_channel_id;
  IF v_old IS NULL THEN
    RAISE EXCEPTION 'channel % not found', p_channel_id
      USING ERRCODE='BZ195', HINT='{"type":"invalidArguments","detail":"channel not found"}';
  END IF;

  IF p_new <> 'gxp' OR v_old <> 'regular' THEN
    RAISE EXCEPTION 'only a regular channel may be upgraded to gxp'
      USING ERRCODE='BZ195',
            HINT='{"type":"invalidArguments","detail":"only regular -> gxp is a valid transition"}';
  END IF;

  IF v_room_id IS NOT NULL THEN
    RAISE EXCEPTION 'a channel bound to a federated room cannot be classified gxp'
      USING ERRCODE='BZ210', HINT='{"type":"conflict","detail":"channel is bound to a federated room"}';
  END IF;

  IF v_ret IS NULL OR v_worm IS NULL THEN
    RAISE EXCEPTION 'gxp upgrade requires retention_days and worm_mode'
      USING ERRCODE='BZ195', HINT='{"type":"invalidArguments"}';
  END IF;

  UPDATE chat_channels SET classification = 'gxp' WHERE id = p_channel_id;

  PERFORM chat_access_audit(p_admin_user_id, p_channel_id, 'classification.change', 'channel', p_channel_id,
    jsonb_build_object('classification', v_old), jsonb_build_object('classification', 'gxp'), NULL, NULL);

  -- Gate-1 replacement for the cut chunk re-scope (plan §Global Constraints
  -- decision 1): stamp a WORM retain_until high-water mark on the channel's
  -- EXISTING attachment chunks, in their existing 'g' (global-dedup) scope.
  -- A 'g' chunk with retain_until in the future is GC-proof
  -- (internal/drive/worker.go:26-40, gcDecide -> gcSkip) and refcount-proof,
  -- so it cannot be reclaimed while the channel's WORM window runs.
  -- Immutability of gxp chat attachments comes from the DB triggers + BZ175
  -- (a chat-referenced node cannot be trashed/moved/renamed/re-versioned
  -- through Drive), NOT from the scope key. Per-space scope only becomes
  -- meaningful once Drive P5 lands the S3 Object-Lock call
  -- (drive_file_put_version.sql:5-6, wormPending:false) — that re-scope
  -- migration is deferred to P5, where it can be done once, with the
  -- feature that needs it.
  PERFORM drive_chunks_extend_retention('g',
    ARRAY(SELECT DISTINCT vc.chunk_sha256
            FROM chat_message_attachments a
            JOIN drive_file_versions v ON v.file_node_id = a.file_node_id
            JOIN drive_version_chunks vc ON vc.version_id = v.id
            JOIN chat_messages m ON m.id = a.message_id
           WHERE m.channel_id = p_channel_id AND vc.scope_key = 'g'),
    now() + make_interval(days => v_ret));
END;
$$;

SELECT apply_worker_ownership('chat_channel_set_classification(BIGINT, BIGINT, TEXT)'::regprocedure);
