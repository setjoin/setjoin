-- mailserver/sql/reducers/drive_node_restore.sql
-- Un-trashes the subtree. Colliding with a live re-created name → the opaque
-- BZ260 nameUnavailable response; the
-- client may retry with a G4-suffixed name (spec §6.2).
CREATE OR REPLACE FUNCTION drive_node_restore(
  p_user_id BIGINT, p_node_id BIGINT
) RETURNS VOID AS $$
DECLARE v_space BIGINT; v_parent BIGINT;
BEGIN
  SELECT space_id,parent_id INTO v_space,v_parent FROM drive_nodes
   WHERE id=p_node_id AND deleted_at IS NOT NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'node not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"node not found or not trashed"}';
  END IF;
  PERFORM public.drive_tree_lock(v_space);
  SELECT space_id,parent_id INTO v_space,v_parent FROM public.drive_nodes
   WHERE id=p_node_id AND deleted_at IS NOT NULL FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'node not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"node not found or not trashed"}';
  END IF;
  PERFORM public.drive_require_node_mutation_capability(
    p_user_id,p_node_id,'delete');
  IF v_parent IS NULL THEN
    PERFORM public.drive_require_space_root_mutation_capability(
      p_user_id,v_space,'create_child');
  ELSE
    PERFORM public.drive_require_node_mutation_capability(
      p_user_id,v_parent,'create_child');
  END IF;

  BEGIN
    UPDATE drive_nodes SET deleted_at = NULL
     WHERE id IN (SELECT node_id FROM drive_closure_subtree(v_space, p_node_id))
       AND deleted_at IS NOT NULL;
  EXCEPTION
    WHEN unique_violation THEN
      RAISE EXCEPTION 'name unavailable' USING ERRCODE='BZ260',
        HINT='{"type":"nameUnavailable","detail":"name unavailable"}';
  END;

  PERFORM drive_access_audit(p_user_id, v_space, 'node.restore', 'node', p_node_id, NULL, NULL, NULL, NULL);
  PERFORM drive_notify_change(v_space, p_node_id, 'restore');
END;
$$ LANGUAGE plpgsql;
