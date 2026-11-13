-- chat_ediscovery_search.sql — Chat A4b Task 3: case-scoped, org-wide
-- eDiscovery search (spec §6.1). deps: chat_access_audit
--
-- DELIBERATELY unscoped (DES-008: a distinct, permission-gated authority
-- plane, not a membership bypass for members): NO membership join, NO
-- deleted_at filter. Four content legs — live+soft-deleted bodies, revision
-- prior_body, scheduled chat_send payload bodies (pending AND failed,
-- contract #7), attachment FILENAMES (content search stays deferred, §15).
-- Query technique verbatim from chat_search.sql:57-60 (tsquery/trgm CASE,
-- global-id keyset). Persists the chat_ediscovery_searches row + writes one
-- search.run act per hit channel IN THE SAME TXN (L6). Scheduled hits ride a
-- separate first-page-only array — a different id-space cannot share the
-- message-id keyset (plan delta 3).
-- ponytail: legs b/c (revision prior_body / scheduled payload, tsvector on
-- the fly) AND the attachment-filename leg (plain ILIKE) all run without a
-- supporting index — seq scan at admin invocation frequency; index if a real
-- corpus ever drags.
--
-- review F5: result_count/chat_ediscovery_searches.result_count is a
-- PER-PAGE count (this call's v_lim-capped message hits + this call's
-- first-page-only scheduled hits), never a total-matches-across-all-pages
-- count — paging further (p_before_id) writes its OWN search row with its
-- own page-scoped count.
-- review F9: scheduled hits are clamped to the SAME v_lim as message hits
-- (previously unbounded).
CREATE OR REPLACE FUNCTION chat_ediscovery_search(
    p_actor BIGINT, p_case_id BIGINT, p_query JSONB,
    p_before_id BIGINT DEFAULT NULL,
    p_use_trgm BOOLEAN DEFAULT FALSE,
    p_limit INT DEFAULT 50
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_status TEXT; v_terms TEXT; v_lim INT;
  v_channel_ids BIGINT[]; v_author BIGINT; v_from TIMESTAMPTZ; v_to TIMESTAMPTZ;
  v_hits JSONB; v_sched JSONB; v_count INT := 0; v_search_id BIGINT; v_rec RECORD;
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
  v_terms := btrim(coalesce(p_query->>'terms', ''));
  IF v_terms = '' THEN
    RAISE EXCEPTION 'query terms required' USING ERRCODE='BZ197',
      HINT='{"type":"invalidArguments","detail":"query terms required"}';
  END IF;
  IF p_query ? 'channelIds' THEN
    v_channel_ids := ARRAY(SELECT jsonb_array_elements_text(p_query->'channelIds')::bigint);
  END IF;
  v_author := (p_query->>'authorId')::bigint;
  v_from   := (p_query->>'dateFrom')::timestamptz;
  v_to     := (p_query->>'dateTo')::timestamptz;
  v_lim    := LEAST(GREATEST(COALESCE(p_limit, 50), 1), 200);

  -- Pillar C1 Task 4 (N1 eDiscovery-attribution fix): every leg now also
  -- carries federated_sender_addr — a federated inbound row (Task 4's
  -- federation_apply_chat) has author_id NULL, so without this the hit would
  -- silently attribute to nobody. authorId itself was ALREADY null-safe
  -- (jsonb_build_object projects a SQL NULL as JSON null with no CASE
  -- needed) — the actual gap was the missing federated identity, not a
  -- crash risk in this file.
  WITH matched AS (
    SELECT m.id, m.channel_id, m.author_id, m.federated_sender_addr, m.created_at,
           (m.deleted_at IS NOT NULL) AS is_deleted, m.body AS matched_text,
           'body' AS matched_in
      FROM chat_messages m
     WHERE (CASE WHEN p_use_trgm THEN m.body ILIKE '%' || v_terms || '%'
                 ELSE m.search_tsv @@ plainto_tsquery('simple', v_terms) END)
    UNION ALL
    SELECT m.id, m.channel_id, m.author_id, m.federated_sender_addr, m.created_at,
           (m.deleted_at IS NOT NULL), rv.prior_body, 'revision'
      FROM chat_message_revisions rv
      JOIN chat_messages m ON m.id = rv.message_id
     WHERE (CASE WHEN p_use_trgm THEN rv.prior_body ILIKE '%' || v_terms || '%'
                 ELSE to_tsvector('simple', rv.prior_body) @@ plainto_tsquery('simple', v_terms) END)
    UNION ALL
    SELECT m.id, m.channel_id, m.author_id, m.federated_sender_addr, m.created_at,
           (m.deleted_at IS NOT NULL), a.filename, 'filename'
      FROM chat_message_attachments a
      JOIN chat_messages m ON m.id = a.message_id
     WHERE a.filename ILIKE '%' || v_terms || '%'
  ), filtered AS (
    SELECT * FROM matched
     WHERE (v_channel_ids IS NULL OR channel_id = ANY(v_channel_ids))
       AND (v_author IS NULL OR author_id = v_author)
       AND (v_from IS NULL OR created_at >= v_from)
       AND (v_to   IS NULL OR created_at <= v_to)
       AND (p_before_id IS NULL OR id < p_before_id)
  ), grouped AS (
    -- review F6: array_agg(matched_text) had no ORDER BY — [1] picked
    -- whichever leg's row the planner happened to visit first, a
    -- nondeterministic excerpt for a message matched on multiple legs.
    -- ORDER BY matched_in makes it stable ('body' < 'filename' < 'revision').
    SELECT id, channel_id, author_id, federated_sender_addr, created_at, is_deleted,
           array_agg(DISTINCT matched_in) AS matched_in,
           (array_agg(matched_text ORDER BY matched_in))[1] AS excerpt
      FROM filtered
     GROUP BY id, channel_id, author_id, federated_sender_addr, created_at, is_deleted
     ORDER BY id DESC
     LIMIT v_lim
  )
  SELECT COALESCE(jsonb_agg(jsonb_build_object(
           'messageId', id, 'channelId', channel_id, 'authorId', author_id,
           'federatedSenderAddr', federated_sender_addr,
           'createdAt', created_at, 'deleted', is_deleted,
           'matchedIn', to_jsonb(matched_in), 'excerpt', left(excerpt, 300)
         ) ORDER BY id DESC), '[]'::jsonb),
         COALESCE(count(*), 0)
    INTO v_hits, v_count
    FROM grouped;

  v_sched := '[]'::jsonb;
  IF p_before_id IS NULL THEN
    -- review F9: clamped to v_lim, the SAME cap message hits use (previously
    -- unbounded — a busy scheduler could jsonb_agg an unbounded row set).
    SELECT COALESCE(jsonb_agg(jsonb_build_object(
             'scheduledActionId', sub.id,
             'channelId', sub.channel_id,
             'authorId',  sub.author_id,
             'status', sub.status, 'fireAt', sub.fire_at,
             'excerpt', left(sub.body, 300)) ORDER BY sub.id DESC), '[]'::jsonb)
      INTO v_sched
      FROM (
        SELECT sa.id, (sa.payload->>'channelId')::bigint AS channel_id,
               (sa.payload->>'userId')::bigint AS author_id,
               sa.status, sa.fire_at, sa.payload->>'body' AS body
          FROM scheduled_actions sa
         WHERE sa.action_kind = 'chat_send'
           AND sa.status IN ('pending', 'failed')          -- contract #7
           AND (CASE WHEN p_use_trgm THEN sa.payload->>'body' ILIKE '%' || v_terms || '%'
                     ELSE to_tsvector('simple', sa.payload->>'body') @@ plainto_tsquery('simple', v_terms) END)
           AND (v_channel_ids IS NULL OR (sa.payload->>'channelId')::bigint = ANY(v_channel_ids))
           AND (v_author IS NULL OR (sa.payload->>'userId')::bigint = v_author)
         ORDER BY sa.id DESC
         LIMIT v_lim
      ) sub;
  END IF;

  v_count := v_count + jsonb_array_length(v_sched);
  INSERT INTO chat_ediscovery_searches (case_id, kind, query, result_count, executed_by)
  VALUES (p_case_id, 'search', p_query, v_count, p_actor)
  RETURNING id INTO v_search_id;

  FOR v_rec IN
    SELECT DISTINCT (e->>'channelId')::bigint AS channel_id
      FROM jsonb_array_elements(v_hits || v_sched) e
  LOOP
    PERFORM chat_access_audit(p_actor, v_rec.channel_id, 'search.run', 'channel',
      v_rec.channel_id, NULL,
      jsonb_build_object('caseId', p_case_id, 'searchId', v_search_id,
                         'query', p_query, 'resultCount', v_count),
      NULL, NULL);
  END LOOP;

  RETURN jsonb_build_object('searchId', v_search_id, 'hits', v_hits,
                            'scheduledHits', v_sched, 'resultCount', v_count);
END;
$$;

SELECT apply_worker_ownership('chat_ediscovery_search(BIGINT, BIGINT, JSONB, BIGINT, BOOLEAN, INT)'::regprocedure);
