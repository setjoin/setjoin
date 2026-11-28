-- mailserver/sql/reducers/drive_search_nodes.sql
-- P6 Task 6 (spec §6.4): RLS-scoped name search. ILIKE over live node names;
-- content FTS stays deferred (TODOS.md). Invoker rights: the membership
-- filter below is R1's own authorization (never a bare req.spaceId trust),
-- and it is ALSO what the caller's own drive_nodes_read RLS policy would
-- enforce as backstop — belt and suspenders, same shape as every other P1
-- read reducer in this file set.
CREATE OR REPLACE FUNCTION drive_search_nodes(
  p_user_id  bigint,
  p_space_id bigint,
  p_q        text,
  p_max      int DEFAULT 100
) RETURNS jsonb AS $$
DECLARE
  v_q text;
BEGIN
  IF p_q IS NULL OR length(btrim(p_q)) = 0 THEN
    RAISE EXCEPTION 'drive: empty search query' USING ERRCODE = 'BZ141',
      HINT = '{"type":"invalidArguments","detail":"search query must not be empty"}';
  END IF;
  -- literal match: escape ILIKE metacharacters so user input is never a
  -- pattern (a name containing '%'/'_' searches for itself, not a wildcard).
  v_q := '%' || replace(replace(replace(btrim(p_q), '\', '\\'), '%', '\%'), '_', '\_') || '%';

  -- Candidate names are grouped by space, then one set-oriented authorization
  -- call filters each group.  Never restore a per-row exact-check N+1 here.
  -- A pg_trgm index remains the later name-scan optimization at million-node
  -- scale; authorization cost is bounded independently by this batch seam.
  RETURN COALESCE((
    WITH candidates AS MATERIALIZED (
      SELECT n.space_id,array_agg(n.id ORDER BY n.id) AS node_ids
        FROM public.drive_nodes n
       WHERE n.deleted_at IS NULL AND n.purged_at IS NULL
         AND n.name ILIKE v_q ESCAPE '\'
         AND (p_space_id IS NULL OR n.space_id=p_space_id)
       GROUP BY n.space_id
    ), readable AS MATERIALIZED (
      SELECT DISTINCT c.space_id,x.node_id
        FROM candidates c
        CROSS JOIN LATERAL public.drive_runtime_capability_sources_set(
          p_user_id,c.space_id,c.node_ids,'read_metadata') x
    )
    SELECT jsonb_agg(jsonb_build_object(
             'id', n.id, 'spaceId', n.space_id, 'parentId', n.parent_id,
             'kind', n.kind, 'name', n.name,
             'sizeBytes', f.size_bytes, 'contentType', f.content_type,
             'createdAt', n.created_at) ORDER BY lower(n.name), n.id)
      FROM (
        SELECT n.* FROM readable r
        JOIN public.drive_nodes n
          ON n.space_id=r.space_id AND n.id=r.node_id
         ORDER BY lower(n.name), n.id
         LIMIT LEAST(GREATEST(COALESCE(p_max, 100), 1), 500)
      ) n
      LEFT JOIN drive_files f ON f.node_id = n.id
  ), '[]'::jsonb);
  -- A p_space_id the caller isn't a member of yields '[]' (same no-oracle
  -- posture as BZ139 elsewhere) rather than a membership probe/exception —
  -- search across a foreign space just looks like zero hits.
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public;
SELECT apply_worker_ownership(
  'drive_search_nodes(bigint,bigint,text,integer)'::regprocedure);
