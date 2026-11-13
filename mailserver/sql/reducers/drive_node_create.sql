-- mailserver/sql/reducers/drive_node_create.sql
-- Creates a folder or file node. Shared preamble genre (spelled out per file,
-- exact parent/root capability checks preserve the 404/403 oracle boundary.
CREATE OR REPLACE FUNCTION drive_node_create(
  p_user_id      BIGINT,
  p_space_id     BIGINT,
  p_parent_id    BIGINT,
  p_kind         TEXT,
  p_name         TEXT,
  p_content_type TEXT DEFAULT NULL
) RETURNS BIGINT AS $$
DECLARE
  v_parent_kind  TEXT;
  v_parent_space BIGINT;
  v_deny         JSONB;
  v_ext          TEXT;
  v_id           BIGINT;
BEGIN
  IF p_parent_id IS NULL THEN
    PERFORM public.drive_require_space_root_capability(
      p_user_id,p_space_id,'create_child');
  ELSE
    PERFORM public.drive_require_node_capability(
      p_user_id,p_parent_id,'create_child');
  END IF;
  -- Meet B2 (spec §4 §D (1)): node creation in a meeting-bound space is
  -- worker-context-only — user writes have no legitimate purpose there.
  -- Plane detection: every user drive route runs under dbscope.RunUserScoped
  -- (GUC set); the ingest worker runs on the GUC-less workerPool.
  IF NULLIF(current_setting('app.current_user_id', true), '') IS NOT NULL
     AND EXISTS (SELECT 1 FROM drive_spaces WHERE id = p_space_id AND meeting_id IS NOT NULL) THEN
    RAISE EXCEPTION 'meeting recording space is server-managed' USING ERRCODE='BZ175',
      HINT='{"type":"forbidden","detail":"recordings are ingested by the server; user writes are not accepted"}';
  END IF;
  IF p_kind NOT IN ('folder','file') THEN
    RAISE EXCEPTION 'invalid kind' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"kind must be folder|file"}';
  END IF;

  -- Serialize the parent snapshot and closure write with every move in this
  -- space. The helper is transaction-scoped, so rollback releases it.
  PERFORM drive_tree_lock(p_space_id);

  IF p_parent_id IS NOT NULL THEN
    SELECT kind, space_id INTO v_parent_kind, v_parent_space
      FROM drive_nodes WHERE id = p_parent_id AND deleted_at IS NULL;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'parent not found' USING ERRCODE='BZ139',
        HINT='{"type":"notFound","detail":"parent not found"}';
    END IF;
    IF v_parent_kind <> 'folder' OR v_parent_space <> p_space_id THEN
      RAISE EXCEPTION 'parent must be a folder in this space' USING ERRCODE='BZ141',
        HINT='{"type":"invalidArguments","detail":"parent must be a folder in this space"}';
    END IF;
  END IF;

  IF p_kind = 'file' THEN
    v_ext  := lower(substring(p_name from '\.([^.]+)$'));
    v_deny := drive_policy_resolve(p_space_id)->'upload_ext_deny';
    IF v_ext IS NOT NULL AND v_deny IS NOT NULL AND v_deny ? v_ext THEN
      RAISE EXCEPTION 'file type not allowed' USING ERRCODE='BZ148',
        HINT='{"type":"overQuota","detail":"file type not allowed in this space"}';
    END IF;
  END IF;

  BEGIN
    INSERT INTO drive_nodes (space_id, parent_id, kind, name, created_by)
    VALUES (p_space_id, p_parent_id, p_kind, p_name, p_user_id)
    RETURNING id INTO v_id;
  EXCEPTION
    WHEN unique_violation THEN
      RAISE EXCEPTION 'name unavailable' USING ERRCODE='BZ260',
        HINT='{"type":"nameUnavailable","detail":"name unavailable"}';
    WHEN check_violation THEN
      RAISE EXCEPTION 'invalid name' USING ERRCODE='BZ141',
        HINT='{"type":"invalidArguments","detail":"invalid node name"}';
  END;

  PERFORM drive_closure_insert_node(p_space_id, v_id, p_parent_id);

  IF p_kind = 'file' THEN
    INSERT INTO drive_files (node_id, space_id, content_type) VALUES (v_id, p_space_id, p_content_type);
  END IF;

  PERFORM drive_access_audit(p_user_id, p_space_id, 'node.create', 'node', v_id, NULL,
    jsonb_build_object('name', p_name, 'kind', p_kind, 'parentId', p_parent_id), NULL, NULL);
  PERFORM drive_notify_change(p_space_id, v_id, 'create');
  RETURN v_id;
END;
$$ LANGUAGE plpgsql;
