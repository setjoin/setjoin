-- mailserver/sql/reducers/drive_node_trash.sql
-- Soft-delete: USER trash tier only (ADMIN purge tier is V117 — §2.4).
-- Recurses over the live subtree (folders and files alike).
-- Chat A2 Task 5b (DES-009 D4, BZ175): a node referenced by
-- chat_message_attachments is an immutable point-in-time chat record —
-- trashing it is done only via chat message-delete, never the Drive app.
-- Meet B2 Task 3 parity: a node referenced by meeting_recordings is an
-- immutable point-in-time meeting record — same guard, same code.
CREATE OR REPLACE FUNCTION drive_node_trash(
  p_user_id BIGINT, p_node_id BIGINT
) RETURNS VOID AS $$
DECLARE v_space BIGINT;
BEGIN
  SELECT space_id INTO v_space FROM drive_nodes WHERE id = p_node_id AND deleted_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'node not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"node not found"}';
  END IF;
  PERFORM public.drive_require_node_capability(p_user_id,p_node_id,'delete');
  PERFORM drive_tree_lock(v_space);
  IF EXISTS (SELECT 1 FROM chat_message_attachments WHERE file_node_id = p_node_id)
     OR EXISTS (SELECT 1 FROM meeting_recordings WHERE file_node_id = p_node_id) THEN
    RAISE EXCEPTION 'immutable record via Drive' USING ERRCODE='BZ175',
      HINT='{"type":"forbidden","detail":"chat attachments and meeting recordings are immutable point-in-time records"}';
  END IF;

  UPDATE drive_nodes SET deleted_at = now()
   WHERE id IN (SELECT node_id FROM drive_closure_subtree(v_space, p_node_id))
     AND deleted_at IS NULL;

  PERFORM drive_access_audit(p_user_id, v_space, 'node.trash', 'node', p_node_id, NULL, NULL, NULL, NULL);
  PERFORM drive_notify_change(v_space, p_node_id, 'trash');
END;
$$ LANGUAGE plpgsql;
