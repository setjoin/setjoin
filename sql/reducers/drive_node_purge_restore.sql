-- mailserver/sql/reducers/drive_node_purge_restore.sql
-- Admin tier-2 restore + the admin-bin read (P6 two-level trash, V117).
-- SECURITY DEFINER pair (colocated write+read, the V037 drive_access_audit
-- precedent): members never see tier-2 rows (V117 drive_nodes_read/write
-- exclude purged_at IS NOT NULL rows), so both functions verify drive.manage
-- THEMSELVES and read/write with owner rights.
-- AUTOPLAN batch-2 BLOCKER #3: needs the P1 ownership-transfer footer or
-- this returns/finds nothing once FORCE binds post-flip — setjoin_owner is
-- NOBYPASSRLS, so an owner-owned DEFINER function does NOT bypass FORCE RLS.
-- R1: every statement is scoped by the verified caller's authority, never
-- req-supplied trust.
CREATE OR REPLACE FUNCTION drive_node_purge_restore(p_user_id bigint, p_node_id bigint)
RETURNS void
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_space_id  bigint;
  v_parent_id bigint;
  v_name      text;
  v_ext       text;
  v_base      text;
  v_n         int := 1;
  v_candidate text;
BEGIN
  IF NOT public.drive_has_admin_perm(p_user_id, 'drive.manage') THEN
    RAISE EXCEPTION 'drive.manage required' USING ERRCODE='BZ140',
      HINT='{"type":"forbidden","detail":"drive.manage required"}';
  END IF;

  SELECT space_id, parent_id, name INTO v_space_id, v_parent_id, v_name
    FROM drive_nodes WHERE id = p_node_id AND purged_at IS NOT NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'node not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"node not found or not purged"}';
  END IF;
  PERFORM drive_tree_lock(v_space_id);

  -- G4 collision suffix (drive_branch_resolve.sql / drive_file_put_version.sql
  -- convention): ' -2', ' -3', ... before the extension. Auto-suffix rather
  -- than BZ147 -- unlike tier-1 drive_node_restore, there is no interactive
  -- user at the console to retry a collision (spec §6.2, self-review notes).
  v_ext  := CASE WHEN position('.' IN v_name) > 0
                 THEN '.' || reverse(split_part(reverse(v_name), '.', 1)) ELSE '' END;
  v_base := CASE WHEN v_ext <> '' THEN left(v_name, length(v_name) - length(v_ext)) ELSE v_name END;
  v_candidate := v_name;
  WHILE EXISTS (
    SELECT 1 FROM drive_nodes n2
     WHERE n2.space_id = v_space_id AND n2.parent_id IS NOT DISTINCT FROM v_parent_id
       AND n2.deleted_at IS NULL AND n2.id <> p_node_id
       AND lower(n2.name) = lower(v_candidate)
  ) LOOP
    v_n := v_n + 1;
    v_candidate := v_base || ' -' || v_n || v_ext;
  END LOOP;

  UPDATE drive_nodes n
     SET purged_at = NULL, purged_by = NULL, deleted_at = NULL,
         name = CASE WHEN n.id = p_node_id THEN v_candidate ELSE n.name END
   WHERE n.id IN (
     SELECT node_id FROM drive_closure_subtree(v_space_id, p_node_id)
   );

  PERFORM drive_access_audit(p_user_id, v_space_id, 'trash.adminRestore', 'node', p_node_id,
    NULL, jsonb_build_object('name', v_candidate), NULL, NULL);
  PERFORM drive_notify_change(v_space_id, p_node_id, 'restore');
END;
$$ LANGUAGE plpgsql;

-- Companion read: tier-2 ROOTS per space (rows whose parent isn't itself
-- purged -- the console restores subtrees from their root). drive.manage
-- only.
CREATE OR REPLACE FUNCTION drive_trash_admin_list(p_user_id bigint, p_space_id bigint)
RETURNS jsonb
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_out jsonb;
BEGIN
  IF NOT public.drive_has_admin_perm(p_user_id, 'drive.manage') THEN
    RAISE EXCEPTION 'drive.manage required' USING ERRCODE='BZ140',
      HINT='{"type":"forbidden","detail":"drive.manage required"}';
  END IF;

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
           'id', n.id, 'name', n.name, 'kind', n.kind,
           'purgedAt', n.purged_at, 'purgedBy', u.email,   -- NULL email = 30-day aged out
           'deletedAt', n.deleted_at,
           'sizeBytes', (SELECT COALESCE(SUM(v.size_bytes), 0)
                           FROM drive_file_versions v WHERE v.file_node_id = n.id)
         ) ORDER BY n.purged_at DESC), '[]'::jsonb)
    INTO v_out
    FROM drive_nodes n
    LEFT JOIN users u ON u.id = n.purged_by
   WHERE n.space_id = p_space_id AND n.purged_at IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM drive_nodes p
                      WHERE p.id = n.parent_id AND p.purged_at IS NOT NULL);
  RETURN v_out;
END;
$$ LANGUAGE plpgsql STABLE;

SELECT apply_worker_ownership('drive_node_purge_restore(bigint, bigint)'::regprocedure);
SELECT apply_worker_ownership('drive_trash_admin_list(bigint, bigint)'::regprocedure);
