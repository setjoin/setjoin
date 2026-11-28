-- Returns self through root in deterministic order.
CREATE OR REPLACE FUNCTION drive_closure_ancestors(
  p_space_id BIGINT, p_node_id BIGINT
) RETURNS TABLE(node_id BIGINT, depth INTEGER)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT c.ancestor_id, c.depth
    FROM public.drive_node_closure c
   WHERE c.space_id = p_space_id AND c.descendant_id = p_node_id
   ORDER BY c.depth, c.ancestor_id
$$;
SELECT apply_worker_ownership('drive_closure_ancestors(BIGINT, BIGINT)'::regprocedure);
