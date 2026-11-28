-- Adds the self row and every parent ancestor for a newly inserted node.
CREATE OR REPLACE FUNCTION drive_closure_insert_node(
  p_space_id BIGINT, p_node_id BIGINT, p_parent_id BIGINT DEFAULT NULL
) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.drive_nodes
     WHERE id = p_node_id AND space_id = p_space_id
  ) THEN
    RAISE EXCEPTION 'node not found' USING ERRCODE='BZ252',
      HINT='{"type":"driveAclInvalid","field":"nodeId"}';
  END IF;

  INSERT INTO public.drive_node_closure
    (space_id, ancestor_id, descendant_id, depth)
  VALUES (p_space_id, p_node_id, p_node_id, 0)
  ON CONFLICT (space_id, ancestor_id, descendant_id)
  DO UPDATE SET depth = EXCLUDED.depth;

  IF p_parent_id IS NULL THEN
    RETURN;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM public.drive_nodes
     WHERE id = p_parent_id AND space_id = p_space_id AND kind = 'folder'
  ) THEN
    RAISE EXCEPTION 'parent not found' USING ERRCODE='BZ252',
      HINT='{"type":"driveAclInvalid","field":"parentId"}';
  END IF;

  INSERT INTO public.drive_node_closure
    (space_id, ancestor_id, descendant_id, depth)
  SELECT p_space_id, c.ancestor_id, p_node_id, c.depth + 1
    FROM public.drive_node_closure c
   WHERE c.space_id = p_space_id AND c.descendant_id = p_parent_id
  ON CONFLICT (space_id, ancestor_id, descendant_id)
  DO UPDATE SET depth = EXCLUDED.depth;
END;
$$;
SELECT apply_worker_ownership('drive_closure_insert_node(BIGINT, BIGINT, BIGINT)'::regprocedure);
