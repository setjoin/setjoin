-- chat_ediscovery_export_begin.sql — Chat A4b Task 4: the export handshake
-- (spec §6.1 row 5, §7, contract #3/#7). deps: chat_access_audit
--
-- Validates scope, writes one export.run act per included channel + a
-- kind='export' chat_ediscovery_searches row, and returns ONLY what must
-- precede the stream: per-channel chain head (id, checksum) + purge floors +
-- act ids. result_count is 0 at begin BY DESIGN — counts are computed in the
-- SAME PASS that streams (Task 7), never here: content committed between
-- begin and the stream would otherwise diverge the manifest from
-- messages.jsonl, and a whole-file sha256 cannot precede the bytes anyway.
-- After this commits, Go opens ONE REPEATABLE READ transaction for the
-- entire export; manifest.json is the ZIP's LAST entry (§7).
--
-- Scope validation is all-or-nothing: every channel id in p_channel_ids must
-- exist BEFORE any export.run act is written (an export scope can never be
-- partially committed).
--
-- The returned chainHead is (at least) the export.run act just written for
-- that channel. NOTE: the MANIFEST's chain-head pin is NOT this value — the
-- Go export handler re-reads the head inside its REPEATABLE READ stream
-- transaction (admin_chat_ediscovery_export.go, streamExportChannel) so the
-- pin also covers any act committed in the begin→snapshot gap. This returned
-- head still lower-bounds it (RR head ≥ this head ≥ the export.run act), so
-- the pin always covers the export act itself — off-box notarization for
-- free.
CREATE OR REPLACE FUNCTION chat_ediscovery_export_begin(
    p_actor BIGINT, p_case_id BIGINT, p_channel_ids BIGINT[], p_query JSONB
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_status    TEXT;
  v_search_id BIGINT;
  v_cid       BIGINT;
  v_act_id    BIGINT;
  v_head_id   BIGINT;
  v_head_sum  TEXT;
  v_channels  JSONB := '[]'::jsonb;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key = 'feature.chat_compliance'), FALSE) THEN
    RAISE EXCEPTION 'chat compliance is disabled' USING ERRCODE='BZ197',
      HINT='{"type":"invalidArguments","detail":"compliance disabled"}';
  END IF;
  SELECT status INTO v_status FROM ediscovery_cases WHERE id = p_case_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'case % not found', p_case_id USING ERRCODE='BZ197',
      HINT='{"type":"invalidArguments","detail":"case not found"}';
  END IF;
  IF v_status <> 'active' THEN
    RAISE EXCEPTION 'case % is not open', p_case_id USING ERRCODE='BZ198',
      HINT='{"type":"stateMismatch","detail":"case is not open"}';
  END IF;

  IF p_channel_ids IS NULL OR array_length(p_channel_ids, 1) IS NULL THEN
    RAISE EXCEPTION 'at least one channel required' USING ERRCODE='BZ197',
      HINT='{"type":"invalidArguments","detail":"at least one channel required"}';
  END IF;
  -- every id must exist (fail before ANY act is written — an export scope
  -- must be all-or-nothing)
  IF EXISTS (SELECT 1 FROM unnest(p_channel_ids) cid
              WHERE NOT EXISTS (SELECT 1 FROM chat_channels c WHERE c.id = cid)) THEN
    RAISE EXCEPTION 'unknown channel in export scope' USING ERRCODE='BZ197',
      HINT='{"type":"invalidArguments","detail":"unknown channel in export scope"}';
  END IF;

  INSERT INTO chat_ediscovery_searches (case_id, kind, query, result_count, executed_by)
  VALUES (p_case_id, 'export', p_query, 0, p_actor)   -- counts come from the stream, never here
  RETURNING id INTO v_search_id;

  FOREACH v_cid IN ARRAY p_channel_ids LOOP
    v_act_id := chat_access_audit(p_actor, v_cid, 'export.run', 'channel', v_cid, NULL,
      jsonb_build_object('caseId', p_case_id, 'searchId', v_search_id, 'query', p_query),
      NULL, NULL);
    SELECT a.id, a.after_state->>'_checksum' INTO v_head_id, v_head_sum
      FROM chat_audit_log a WHERE a.channel_id = v_cid ORDER BY a.id DESC LIMIT 1;
    -- the head is (at least) the export.run act just written; it
    -- lower-bounds the manifest's pin, which the Go handler re-reads at the
    -- RR snapshot (see the header comment).
    v_channels := v_channels || jsonb_build_object(
      'channelId', v_cid, 'exportActId', v_act_id,
      'chainHead', jsonb_build_object('id', v_head_id, 'checksum', v_head_sum),
      'lastPurgedSeq', (SELECT last_purged_seq FROM chat_channels WHERE id = v_cid),
      'purgeActs', COALESCE((SELECT jsonb_agg(jsonb_build_object(
          'actId', pa.id, 'idFrom', (pa.after_state->>'idFrom')::bigint,
          'idTo', (pa.after_state->>'idTo')::bigint,
          'purgedCount', (pa.after_state->>'purgedCount')::int) ORDER BY pa.id)
          FROM chat_audit_log pa
         WHERE pa.channel_id = v_cid AND pa.action = 'purge.execute'), '[]'::jsonb));
  END LOOP;
  RETURN jsonb_build_object('searchId', v_search_id, 'channels', v_channels);
END;
$$;

SELECT apply_worker_ownership('chat_ediscovery_export_begin(BIGINT, BIGINT, BIGINT[], JSONB)'::regprocedure);
