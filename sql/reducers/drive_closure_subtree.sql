-- Closure-backed subtree facts remain available to authorized reducers even
-- after drive_nodes RLS narrows to node visibility in A2.
CREATE OR REPLACE FUNCTION drive_closure_subtree(
  p_space_id BIGINT, p_anchor_id BIGINT
) RETURNS TABLE(node_id BIGINT, depth INTEGER)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT c.descendant_id, c.depth
    FROM public.drive_node_closure c
   WHERE c.space_id = p_space_id AND c.ancestor_id = p_anchor_id
   ORDER BY c.depth, c.descendant_id
$$;
SELECT apply_worker_ownership('drive_closure_subtree(BIGINT, BIGINT)'::regprocedure);
