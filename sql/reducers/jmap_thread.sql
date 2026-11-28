-- JMAP Thread/* reducers (RFC 8621 §3)

-- jmap_thread_get: return Thread objects grouped by thread_id.
CREATE OR REPLACE FUNCTION jmap_thread_get(
  p_mailbox_id BIGINT,
  p_ids        TEXT[]
) RETURNS JSONB AS $$
DECLARE
  v_result    JSONB := '[]'::JSONB;
  v_thread_id TEXT;
  v_email_ids BIGINT[];
  v_state     BIGINT;
  v_found     TEXT[] := ARRAY[]::TEXT[];
BEGIN
  SELECT jmap_email_state INTO v_state
  FROM mailboxes WHERE id = p_mailbox_id;
  IF v_state IS NULL THEN
    RAISE EXCEPTION 'Account not found'
      USING ERRCODE = 'BZ006', HINT = '{"type":"accountNotFound"}';
  END IF;

  FOREACH v_thread_id IN ARRAY p_ids
  LOOP
    SELECT array_agg(id ORDER BY received_at DESC)
    INTO v_email_ids
    FROM messages
    WHERE mailbox_id = p_mailbox_id
      AND thread_id = v_thread_id
      AND NOT is_deleted;

    IF v_email_ids IS NOT NULL THEN
      v_result := v_result || jsonb_build_object(
        'id', v_thread_id,
        'emailIds', (SELECT array_agg(x::TEXT) FROM unnest(v_email_ids) AS x)
      );
      v_found := v_found || v_thread_id;
    END IF;
  END LOOP;

  RETURN build_jmap_get_response(p_mailbox_id, v_state, v_result, v_found, p_ids);
END;
$$ LANGUAGE plpgsql;

-- jmap_thread_changes: return thread ids that changed since p_since_state.
CREATE OR REPLACE FUNCTION jmap_thread_changes(
  p_mailbox_id   BIGINT,
  p_since_state  TEXT
) RETURNS JSONB AS $$
DECLARE
  v_current BIGINT;
BEGIN
  -- Read the SAME counter jmap_thread_get returns (jmap_email_state), not the
  -- never-bumped jmap_thread_state. A thread's content changes exactly when its
  -- emails do, so thread state tracks the email counter. Reading the dead
  -- jmap_thread_state here (its former value) desynced get≠changes: get handed the
  -- client jmap_email_state (bumped), changes compared against jmap_thread_state
  -- (always 0), so an up-to-date client's sinceState could NEVER equal v_current
  -- and Thread/changes raised BZ011 on EVERY call — permanent forced resync.
  SELECT jmap_email_state INTO v_current
  FROM mailboxes WHERE id = p_mailbox_id;
  IF v_current IS NULL THEN
    RAISE EXCEPTION 'Account not found'
      USING ERRCODE = 'BZ006', HINT = '{"type":"accountNotFound"}';
  END IF;

  -- No thread journal yet (real per-thread delta deferred to F11): an up-to-date
  -- client (since == current) falls through to an empty delta; any advance forces
  -- a full resync via BZ011 (correct — coarse but never silently stale).
  IF p_since_state::BIGINT != v_current THEN
    RAISE EXCEPTION 'Cannot calculate changes'
      USING ERRCODE = 'BZ011', HINT = '{"type":"cannotCalculateChanges"}';
  END IF;

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'oldState', p_since_state,
    'newState', v_current::TEXT,
    'hasMoreChanges', false,
    'created', '[]'::JSONB,
    'updated', '[]'::JSONB,
    'destroyed', '[]'::JSONB
  );
END;
$$ LANGUAGE plpgsql;

-- jmap_search_snippet_get: return highlighted snippets for a query.
CREATE OR REPLACE FUNCTION jmap_search_snippet_get(
  p_mailbox_id BIGINT,
  p_filter     JSONB,
  p_email_ids  BIGINT[]
) RETURNS JSONB AS $$
DECLARE
  v_result    JSONB := '[]'::JSONB;
  v_row       RECORD;
  v_query     TEXT;
BEGIN
  -- Extract text query from filter
  IF p_filter ? 'text' THEN
    v_query := p_filter->>'text';
  ELSIF p_filter ? 'subject' THEN
    v_query := p_filter->>'subject';
  ELSIF p_filter ? 'body' THEN
    v_query := p_filter->>'body';
  END IF;

  IF v_query IS NULL OR v_query = '' THEN
    RAISE EXCEPTION 'SearchSnippet/get requires a text/subject/body filter'
      USING ERRCODE = 'BZ040', HINT = '{"type":"invalidArguments"}';
  END IF;

  FOR v_row IN
    SELECT id, body_text, subject
    FROM messages
    WHERE mailbox_id = p_mailbox_id
      AND id = ANY(p_email_ids)
      AND NOT is_deleted
  LOOP
    -- Plain GIN/tsquery revert (2026-07-04 queue-B #2): paradedb.snippet threw
    -- on every deployment (ParadeDB never installed). ts_headline is the plain-
    -- PostgreSQL equivalent; NULL body_text (encrypted messages) still falls
    -- through to the left()/subject fallback, unchanged.
    v_result := v_result || jsonb_build_object(
      'emailId', v_row.id::TEXT,
      'subject', COALESCE(ts_headline('simple', v_row.subject, websearch_to_tsquery('simple', v_query),
        'StartSel=<mark>, StopSel=</mark>, MaxWords=20, MinWords=5'), v_row.subject),
      'preview', COALESCE(ts_headline('simple', v_row.body_text, websearch_to_tsquery('simple', v_query),
        'StartSel=<mark>, StopSel=</mark>, MaxWords=35, MinWords=15, MaxFragments=1'), left(v_row.body_text, 200))
    );
  END LOOP;

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'list', v_result,
    'notFound', CASE WHEN p_email_ids IS NOT NULL THEN
      (SELECT array_agg(x::TEXT) FROM unnest(p_email_ids) AS x
       WHERE NOT EXISTS (
         SELECT 1 FROM messages
         WHERE id = x AND mailbox_id = p_mailbox_id AND NOT is_deleted
       ))
    END
  );
END;
$$ LANGUAGE plpgsql;
