-- Reparents one subtree after the caller has completed its capability checks.
-- This helper repeats the tree lock and structural checks so no invoker can
-- bypass cycle/cross-space safety by calling it directly.
CREATE OR REPLACE FUNCTION drive_closure_move_subtree(
  p_space_id BIGINT, p_node_id BIGINT, p_new_parent_id BIGINT DEFAULT NULL
) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  PERFORM public.drive_tree_lock(p_space_id);

  PERFORM 1 FROM public.drive_nodes
   WHERE id = p_node_id AND space_id = p_space_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'node not found' USING ERRCODE='BZ252',
      HINT='{"type":"driveAclInvalid","field":"nodeId"}';
  END IF;

  IF p_new_parent_id IS NOT NULL THEN
    PERFORM 1 FROM public.drive_nodes
     WHERE id = p_new_parent_id AND space_id = p_space_id
       AND kind = 'folder' AND deleted_at IS NULL
     FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'new parent not found' USING ERRCODE='BZ252',
        HINT='{"type":"driveAclInvalid","field":"newParentId"}';
    END IF;
    IF EXISTS (
      SELECT 1 FROM public.drive_node_closure
       WHERE space_id = p_space_id
         AND ancestor_id = p_node_id
         AND descendant_id = p_new_parent_id
    ) THEN
      RAISE EXCEPTION 'move target is inside the subtree' USING ERRCODE='BZ252',
        HINT='{"type":"driveAclInvalid","field":"newParentId","reason":"cycle"}';
    END IF;
  END IF;

  -- Remove only ancestors outside the moving subtree. Internal ancestry is
  -- unchanged by a reparent.
  DELETE FROM public.drive_node_closure c
   WHERE c.space_id = p_space_id
     AND c.descendant_id IN (
       SELECT descendant_id FROM public.drive_node_closure
        WHERE space_id = p_space_id AND ancestor_id = p_node_id
     )
     AND c.ancestor_id NOT IN (
       SELECT descendant_id FROM public.drive_node_closure
        WHERE space_id = p_space_id AND ancestor_id = p_node_id
     );

  IF p_new_parent_id IS NOT NULL THEN
    INSERT INTO public.drive_node_closure
      (space_id, ancestor_id, descendant_id, depth)
    SELECT p_space_id, parent_anc.ancestor_id, subtree.descendant_id,
           parent_anc.depth + 1 + subtree.depth
      FROM public.drive_node_closure parent_anc
      CROSS JOIN public.drive_node_closure subtree
     WHERE parent_anc.space_id = p_space_id
       AND parent_anc.descendant_id = p_new_parent_id
       AND subtree.space_id = p_space_id
       AND subtree.ancestor_id = p_node_id
    ON CONFLICT (space_id, ancestor_id, descendant_id)
    DO UPDATE SET depth = EXCLUDED.depth;
  END IF;

  UPDATE public.drive_nodes
     SET parent_id = p_new_parent_id
   WHERE id = p_node_id AND space_id = p_space_id;
END;
$$;
SELECT apply_worker_ownership('drive_closure_move_subtree(BIGINT, BIGINT, BIGINT)'::regprocedure);
