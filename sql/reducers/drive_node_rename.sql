-- mailserver/sql/reducers/drive_node_rename.sql
-- Chat A2 Task 5b (DES-009 D4, BZ175): a node referenced by
-- chat_message_attachments is an immutable point-in-time chat record —
-- renaming it is done only via chat message-delete, never the Drive app.
-- Meet B2 Task 3 parity: a node referenced by meeting_recordings is an
-- immutable point-in-time meeting record — same guard, same code.
CREATE OR REPLACE FUNCTION drive_node_rename(
  p_user_id BIGINT, p_node_id BIGINT, p_new_name TEXT
) RETURNS VOID AS $$
DECLARE
  v_space    BIGINT;
  v_kind     TEXT;
  v_old_name TEXT;
  v_role     TEXT;
  v_deny     JSONB;
  v_ext      TEXT;
BEGIN
  SELECT space_id, kind, name INTO v_space, v_kind, v_old_name
    FROM drive_nodes WHERE id = p_node_id AND deleted_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'node not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"node not found"}';
  END IF;
  PERFORM public.drive_tree_lock(v_space);
  SELECT space_id,kind,name INTO v_space,v_kind,v_old_name
    FROM public.drive_nodes WHERE id=p_node_id AND deleted_at IS NULL FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'node not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"node not found"}';
  END IF;
  PERFORM public.drive_require_node_mutation_capability(
    p_user_id,p_node_id,'rename');
  IF EXISTS (SELECT 1 FROM chat_message_attachments WHERE file_node_id = p_node_id)
     OR EXISTS (SELECT 1 FROM meeting_recordings WHERE file_node_id = p_node_id) THEN
    RAISE EXCEPTION 'immutable record via Drive' USING ERRCODE='BZ175',
      HINT='{"type":"forbidden","detail":"chat attachments and meeting recordings are immutable point-in-time records"}';
  END IF;

  IF v_kind = 'file' THEN
    v_ext  := lower(substring(p_new_name from '\.([^.]+)$'));
    v_deny := drive_policy_resolve(v_space)->'upload_ext_deny';
    IF v_ext IS NOT NULL AND v_deny IS NOT NULL AND v_deny ? v_ext THEN
      RAISE EXCEPTION 'file type not allowed' USING ERRCODE='BZ148',
        HINT='{"type":"overQuota","detail":"file type not allowed in this space"}';
    END IF;
  END IF;

  BEGIN
    UPDATE drive_nodes SET name = p_new_name WHERE id = p_node_id;
  EXCEPTION
    WHEN unique_violation THEN
      RAISE EXCEPTION 'name unavailable' USING ERRCODE='BZ260',
        HINT='{"type":"nameUnavailable","detail":"name unavailable"}';
    WHEN check_violation THEN
      RAISE EXCEPTION 'invalid name' USING ERRCODE='BZ141',
        HINT='{"type":"invalidArguments","detail":"invalid node name"}';
  END;

  PERFORM drive_access_audit(p_user_id, v_space, 'node.rename', 'node', p_node_id,
    jsonb_build_object('name', v_old_name), jsonb_build_object('name', p_new_name), NULL, NULL);
  PERFORM drive_notify_change(v_space, p_node_id, 'rename');
END;
$$ LANGUAGE plpgsql;
