CREATE OR REPLACE FUNCTION drive_acl_epoch(p_space_id BIGINT)
RETURNS BIGINT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT g.epoch FROM public.drive_acl_generations g WHERE g.space_id = p_space_id
$$;
SELECT apply_worker_ownership('drive_acl_epoch(BIGINT)'::regprocedure);
