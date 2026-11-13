CREATE OR REPLACE FUNCTION drive_acl_capabilities_valid(p_capabilities TEXT[])
RETURNS BOOLEAN
LANGUAGE sql IMMUTABLE PARALLEL SAFE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
  SELECT p_capabilities IS NOT NULL
     AND cardinality(p_capabilities) > 0
     AND cardinality(p_capabilities) = (
       SELECT count(DISTINCT v) FROM unnest(p_capabilities) AS u(v)
     )
     AND NOT EXISTS (
       SELECT 1 FROM unnest(p_capabilities) AS u(v)
        WHERE v IS NULL OR NOT (v = ANY(public.drive_acl_capability_catalog()))
     )
$$;
SELECT apply_worker_ownership('drive_acl_capabilities_valid(TEXT[])'::regprocedure);
