-- Serializes every structural mutation within one Drive space. Cross-space
-- moves are forbidden, so one lock key is sufficient and cannot deadlock with
-- a destination-space lock.
CREATE OR REPLACE FUNCTION drive_tree_lock(p_space_id BIGINT)
RETURNS VOID
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended('setjoin:drive-tree:' || p_space_id::text, 0)
  )
$$;
SELECT apply_worker_ownership('drive_tree_lock(BIGINT)'::regprocedure);
