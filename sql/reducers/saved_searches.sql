-- saved_searches.sql — saved-search folders: named per-mailbox persisted queries
-- a user can re-run (mirrors the quick_steps user-object rail). The RAW query
-- string is stored VERBATIM (the webmail re-parses it at click time — never a
-- resolved filter), so re-running a saved search always reflects the live index.
--
-- R4 / DATABASE_SECURITY: every statement filters by p_mailbox_id from the auth
-- context (R1/R3); the INSERT sets mailbox_id from the parameter, never req.* (R2).

CREATE OR REPLACE FUNCTION saved_search_list(p_mailbox_id BIGINT) RETURNS JSONB AS $$
  SELECT COALESCE(jsonb_agg(jsonb_build_object(
    'id', id::TEXT, 'name', name, 'query', query,
    'position', position) ORDER BY position, created_at, id), '[]'::JSONB)
  FROM saved_searches WHERE mailbox_id = p_mailbox_id;            -- R1: filter by mailbox
$$ LANGUAGE sql STABLE;

CREATE OR REPLACE FUNCTION saved_search_set(
  p_mailbox_id BIGINT, p_name TEXT, p_query TEXT
) RETURNS JSONB AS $$
DECLARE
  v_row saved_searches;
BEGIN
  IF p_name IS NULL OR length(trim(p_name)) = 0 THEN
    RAISE EXCEPTION 'saved search name required'
      USING ERRCODE = 'BZ040', HINT = '{"type":"invalidArguments"}';
  END IF;
  IF p_query IS NULL OR length(trim(p_query)) = 0 THEN
    RAISE EXCEPTION 'saved search query required'
      USING ERRCODE = 'BZ040', HINT = '{"type":"invalidArguments"}';
  END IF;

  -- R2: mailbox_id comes from the parameter (auth context), never req.*. Store
  -- p_query verbatim; the next free position appends to the mailbox's list.
  INSERT INTO saved_searches (mailbox_id, name, query, position)
  VALUES (p_mailbox_id, p_name, p_query,
          COALESCE((SELECT max(position) + 1 FROM saved_searches WHERE mailbox_id = p_mailbox_id), 0))
  RETURNING * INTO v_row;

  RETURN jsonb_build_object('id', v_row.id::TEXT, 'name', v_row.name,
                            'query', v_row.query, 'position', v_row.position);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION saved_search_delete(p_mailbox_id BIGINT, p_id BIGINT) RETURNS JSONB AS $$
DECLARE
  v_deleted BIGINT;
BEGIN
  DELETE FROM saved_searches
   WHERE id = p_id AND mailbox_id = p_mailbox_id                  -- R3: ownership in WHERE
  RETURNING id INTO v_deleted;
  RETURN jsonb_build_object('deleted', v_deleted IS NOT NULL, 'id', p_id::TEXT);
END;
$$ LANGUAGE plpgsql;
