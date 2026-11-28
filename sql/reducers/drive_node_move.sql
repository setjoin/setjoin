-- mailserver/sql/reducers/drive_node_move.sql
-- I-3: cross-space move rejected (BZ143). V184 replaces the recursive walk
-- with the closure authority and serializes structural changes per space.
-- Chat A2 Task 5b (DES-009 D4, BZ175): a node referenced by
-- chat_message_attachments is an immutable point-in-time chat record —
-- moving it is done only via chat message-delete, never the Drive app.
-- Meet B2 Task 3 parity: a node referenced by meeting_recordings is an
-- immutable point-in-time meeting record — same guard, same code.
CREATE OR REPLACE FUNCTION drive_node_move(
  p_user_id BIGINT, p_node_id BIGINT, p_new_parent_id BIGINT
) RETURNS VOID AS $$
DECLARE
  v_space        BIGINT;
  v_old_parent   BIGINT;
  v_parent_space BIGINT;
  v_parent_kind  TEXT;
BEGIN
  SELECT space_id, parent_id INTO v_space, v_old_parent
    FROM drive_nodes WHERE id = p_node_id AND deleted_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'node not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"node not found"}';
  END IF;
  PERFORM drive_tree_lock(v_space);
  -- Re-read under the structural lock and hold the node row through commit.
  SELECT space_id, parent_id INTO v_space, v_old_parent
    FROM drive_nodes WHERE id = p_node_id AND deleted_at IS NULL FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'node not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"node not found"}';
  END IF;
  PERFORM public.drive_require_node_mutation_capability(
    p_user_id,p_node_id,'move');
  IF EXISTS (SELECT 1 FROM chat_message_attachments WHERE file_node_id = p_node_id)
     OR EXISTS (SELECT 1 FROM meeting_recordings WHERE file_node_id = p_node_id) THEN
    RAISE EXCEPTION 'immutable record via Drive' USING ERRCODE='BZ175',
      HINT='{"type":"forbidden","detail":"chat attachments and meeting recordings are immutable point-in-time records"}';
  END IF;

  IF p_new_parent_id = p_node_id THEN
    RAISE EXCEPTION 'cannot move a node under itself' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"cannot move a node under itself"}';
  END IF;

  IF p_new_parent_id IS NOT NULL THEN
    SELECT space_id, kind INTO v_parent_space, v_parent_kind
      FROM drive_nodes WHERE id = p_new_parent_id AND deleted_at IS NULL FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'new parent not found' USING ERRCODE='BZ139',
        HINT='{"type":"notFound","detail":"new parent not found"}';
    END IF;
    IF v_parent_kind <> 'folder' THEN
      RAISE EXCEPTION 'move target must be a folder' USING ERRCODE='BZ141',
        HINT='{"type":"invalidArguments","detail":"move target must be a folder"}';
    END IF;
    IF v_parent_space <> v_space THEN
      RAISE EXCEPTION 'move must stay within the space' USING ERRCODE='BZ143',
        HINT='{"type":"crossSpace","detail":"move must stay within the space"}';
    END IF;
    PERFORM public.drive_require_node_mutation_capability(
      p_user_id,p_new_parent_id,'create_child');
    IF EXISTS (
      SELECT 1 FROM drive_node_closure
       WHERE space_id = v_space AND ancestor_id = p_node_id
         AND descendant_id = p_new_parent_id
    ) THEN
      RAISE EXCEPTION 'move target is a descendant of the node' USING ERRCODE='BZ141',
        HINT='{"type":"invalidArguments","detail":"move target is a descendant of the node"}';
    END IF;
  ELSE
    PERFORM public.drive_require_space_root_mutation_capability(
      p_user_id,v_space,'create_child');
  END IF;

  BEGIN
    PERFORM drive_closure_move_subtree(v_space, p_node_id, p_new_parent_id);
  EXCEPTION
    WHEN unique_violation THEN
      RAISE EXCEPTION 'name unavailable' USING ERRCODE='BZ260',
        HINT='{"type":"nameUnavailable","detail":"name unavailable"}';
  END;

  PERFORM drive_access_audit(p_user_id, v_space, 'node.move', 'node', p_node_id,
    jsonb_build_object('parentId', v_old_parent), jsonb_build_object('parentId', p_new_parent_id), NULL, NULL);
  PERFORM drive_acl_bump(v_space, 'all', NULL, p_node_id, 'tree_move');
  PERFORM drive_notify_change(v_space, p_node_id, 'move');
END;
$$ LANGUAGE plpgsql;
