-- V184 closure-backed replacement for V115's recursive ancestor walk.
CREATE OR REPLACE FUNCTION drive_subtree_admin(
  p_user_id BIGINT, p_node_id BIGINT
) RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT EXISTS (
    SELECT 1
      FROM public.drive_nodes n
      JOIN public.drive_node_closure c
        ON c.space_id = n.space_id AND c.descendant_id = n.id
      JOIN public.drive_folder_admins fa
        ON fa.space_id = c.space_id AND fa.node_id = c.ancestor_id
     WHERE n.id = p_node_id AND fa.user_id = p_user_id
  )
$$;
SELECT apply_worker_ownership('drive_subtree_admin(BIGINT, BIGINT)'::regprocedure);
