-- chat_ediscovery_read.sql — Chat A4b Task 4: the case-scoped channel read
-- window (spec §6.1 row 4, L8, D-B, contract #3/#7). deps: chat_access_audit
--
-- Carries BOTH chat_ediscovery_message_json (the D-B canonical per-message
-- projection) and chat_ediscovery_read — single-homed so this reducer and
-- Task 7's streaming export query can never drift on the shape of a message
-- (the drive_member_role lesson: one function, every consumer calls it).
--
-- chat_ediscovery_message_json is STABLE + SECURITY DEFINER + worker-owned:
-- it reaches chat_message_revisions/chat_poll_*/chat_message_attachments,
-- every one FORCE-RLS member-scoped tables an eDiscovery officer is
-- deliberately NOT a member of (DES-008) — an invoker-rights read would see
-- 0 rows for every joined table and silently under-report the record.
--
-- chat_ediscovery_read is DELIBERATELY unscoped by membership (DES-008, the
-- same posture as chat_ediscovery_search): NO chat_member_role check, NO
-- deleted_at filter on the messages window — a soft-deleted message's
-- retained body is expanded, not a tombstone stub.
--
-- last_purged_seq / purgeActs (L8): a RECORD FLOOR, never a replayable
-- cursor — seq is re-stamped on edit (V126 §A comment is the authority).
-- The manifest/console MUST NOT claim this proves a specific held message
-- survived destruction; it only bounds what has been purged.
--
-- Every invocation persists a kind='read' chat_ediscovery_searches row and
-- writes exactly ONE search.run act (range payload) on the read channel's
-- chain — interactive reads map onto the existing search.run act type
-- (contract #1/L9), no new act type.
CREATE OR REPLACE FUNCTION chat_ediscovery_message_json(p_message_id BIGINT) RETURNS JSONB
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT jsonb_build_object(
    'messageId', m.id, 'channelId', m.channel_id, 'authorId', m.author_id,
    -- Pillar C1 Task 4 (N1 fix): a federated inbound row (federation_apply_
    -- chat) has author_id NULL — federatedSenderAddr is the attribution for
    -- those rows (NULL for every ordinary local message, unchanged).
    'federatedSenderAddr', m.federated_sender_addr,
    'seq', m.seq, 'createdAt', m.created_at, 'editedAt', m.edited_at,
    'deletedAt', m.deleted_at, 'msgType', m.msg_type, 'body', m.body, 'payload', m.payload,
    'revisions', COALESCE((SELECT jsonb_agg(jsonb_build_object(
                   'id', rv.id, 'priorBody', rv.prior_body,
                   'editedBy', rv.edited_by, 'createdAt', rv.created_at) ORDER BY rv.id)
                   FROM chat_message_revisions rv WHERE rv.message_id = m.id), '[]'::jsonb),
    'reactions', COALESCE((SELECT jsonb_agg(jsonb_build_object('emoji', r.emoji, 'userId', r.user_id))
                   FROM chat_message_reactions r WHERE r.message_id = m.id), '[]'::jsonb),
    'attachments', COALESCE((SELECT jsonb_agg(jsonb_build_object(
                   'id', a.id, 'filename', a.filename, 'contentType', a.content_type,
                   'sizeBytes', a.size_bytes, 'fileNodeId', a.file_node_id,
                   'versionId', a.version_id,
                   'sha256', (SELECT v.content_sha256 FROM drive_file_versions v WHERE v.id = a.version_id)
                 ) ORDER BY a.ordinal)
                   FROM chat_message_attachments a WHERE a.message_id = m.id), '[]'::jsonb),
    'poll', (SELECT jsonb_build_object(
               'question', p.question, 'multi', p.multi, 'closesAt', p.closes_at,
               'options', COALESCE((SELECT jsonb_agg(jsonb_build_object(
                            'id', o.id, 'ordinal', o.ordinal, 'label', o.label) ORDER BY o.ordinal)
                            FROM chat_poll_options o WHERE o.poll_id = p.id), '[]'::jsonb),
               'votes', COALESCE((SELECT jsonb_agg(jsonb_build_object(
                            'optionId', v.option_id, 'userId', v.user_id, 'createdAt', v.created_at))
                            FROM chat_poll_votes v WHERE v.poll_id = p.id), '[]'::jsonb))
               FROM chat_polls p WHERE p.message_id = m.id)
  ) FROM chat_messages m WHERE m.id = p_message_id
$$;
SELECT apply_worker_ownership('chat_ediscovery_message_json(BIGINT)'::regprocedure);

CREATE OR REPLACE FUNCTION chat_ediscovery_read(
    p_actor BIGINT, p_case_id BIGINT, p_channel_id BIGINT,
    p_before_id BIGINT DEFAULT NULL, p_limit INT DEFAULT 100
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_status          TEXT;
  v_lim             INT;
  v_messages        JSONB;
  v_sched           JSONB;
  v_purge_acts      JSONB;
  v_last_purged_seq BIGINT;
  v_count           INT;
  v_search_id       BIGINT;
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
  SELECT last_purged_seq INTO v_last_purged_seq FROM chat_channels WHERE id = p_channel_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'channel % not found', p_channel_id USING ERRCODE='BZ197',
      HINT='{"type":"invalidArguments","detail":"channel not found"}';
  END IF;
  v_lim := LEAST(GREATEST(COALESCE(p_limit, 100), 1), 500);

  -- The window must be limited BEFORE aggregation — LIMIT on the outer
  -- aggregate query would apply to the single aggregated row, not the input
  -- rows, so the id-keyset window is a subquery.
  SELECT COALESCE(jsonb_agg(chat_ediscovery_message_json(sub.id) ORDER BY sub.id DESC), '[]'::jsonb)
    INTO v_messages
    FROM (
      SELECT m.id FROM chat_messages m
       WHERE m.channel_id = p_channel_id
         AND (p_before_id IS NULL OR m.id < p_before_id)
       ORDER BY m.id DESC
       LIMIT v_lim
    ) sub;
  v_count := jsonb_array_length(v_messages);

  v_sched := '[]'::jsonb;
  IF p_before_id IS NULL THEN
    -- review F9: clamped to v_lim, the SAME cap the message window uses
    -- (previously unbounded).
    SELECT COALESCE(jsonb_agg(jsonb_build_object(
             'scheduledActionId', sub.id, 'channelId', p_channel_id,
             'authorId', sub.author_id,
             'status', sub.status, 'fireAt', sub.fire_at,
             'body', sub.body) ORDER BY sub.id DESC), '[]'::jsonb)
      INTO v_sched
      FROM (
        SELECT sa.id, (sa.payload->>'userId')::bigint AS author_id,
               sa.status, sa.fire_at, sa.payload->>'body' AS body
          FROM scheduled_actions sa
         WHERE sa.action_kind = 'chat_send'
           AND sa.status IN ('pending', 'failed')          -- contract #7
           AND (sa.payload->>'channelId')::bigint = p_channel_id
         ORDER BY sa.id DESC
         LIMIT v_lim
      ) sub;
  END IF;

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
           'actId', pa.id, 'idFrom', (pa.after_state->>'idFrom')::bigint,
           'idTo', (pa.after_state->>'idTo')::bigint,
           'purgedCount', (pa.after_state->>'purgedCount')::int) ORDER BY pa.id), '[]'::jsonb)
    INTO v_purge_acts
    FROM chat_audit_log pa
   WHERE pa.channel_id = p_channel_id AND pa.action = 'purge.execute';

  INSERT INTO chat_ediscovery_searches (case_id, kind, query, result_count, executed_by)
  VALUES (p_case_id, 'read',
          jsonb_build_object('channelId', p_channel_id, 'beforeId', p_before_id, 'limit', v_lim),
          v_count, p_actor)
  RETURNING id INTO v_search_id;

  PERFORM chat_access_audit(p_actor, p_channel_id, 'search.run', 'channel', p_channel_id, NULL,
    jsonb_build_object('caseId', p_case_id, 'searchId', v_search_id,
                       'range', jsonb_build_object('beforeId', p_before_id, 'limit', v_lim),
                       'resultCount', v_count),
    NULL, NULL);

  RETURN jsonb_build_object('channelId', p_channel_id, 'lastPurgedSeq', v_last_purged_seq,
                            'purgeActs', v_purge_acts, 'scheduledRows', v_sched,
                            'messages', v_messages);
END;
$$;

SELECT apply_worker_ownership('chat_ediscovery_read(BIGINT, BIGINT, BIGINT, BIGINT, INT)'::regprocedure);
