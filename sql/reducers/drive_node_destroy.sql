-- mailserver/sql/reducers/drive_node_destroy.sql
-- P6 (V117) flip: destroy = tier-2 purge, NOT physical delete (spec §3.5,
-- AUTOPLAN contradiction #7 — was P1-P5 hard delete). Manager-only; node
-- must already be trashed (BZ141 — not BZ139, since the node itself is
-- found, just not eligible yet).
--
-- Bytes/versions/branches/locks/labels all SURVIVE — they stay exactly as
-- trashed for the 30-day admin grace window (drive_node_purge_restore /
-- drive_trash_admin_list, drive_node_destroy_hard.sql). used_bytes is NOT
-- decremented here: tier-2 bytes are still physically stored, so they still
-- count against quota until the grace expires — deliberate, surfaced in the
-- admin UI (I-14 delta, see drive_quota.pg).
--
-- The old P1/P4 hard-delete body (FK unwind: locks, branch_id,
-- drive_file_branches, merged_from_version_id, head_version_id,
-- drive_file_versions, drive_export_grants, drive_spaces.used_bytes)
-- relocates verbatim-adapted to drive_node_destroy_hard.sql (worker-only,
-- no p_user_id) — the sweep's grace-expiry verb (P6 Task 4).
--
-- drive_node_purge_mark: SECURITY DEFINER choke point (Locked-resolution-R2
-- shape, same genre as drive_notify_change/drive_space_quota_charge),
-- REQUIRED because of a real PostgreSQL RLS UPDATE mechanic (verified
-- empirically via EXPLAIN + isolated ALTER POLICY probes, PG 17): for an
-- UPDATE under FORCE RLS, the NEW row must satisfy the table's applicable
-- SELECT policy TOO, in addition to the UPDATE policy's own WITH CHECK —
-- this is enforced regardless of what the UPDATE policy's WITH CHECK says.
-- Purging sets purged_at, which V117's drive_nodes_read USING clause
-- (purged_at IS NULL) deliberately excludes, so the plain invoker-rights
-- UPDATE that used to live here 42501s once the native-RLS DSN flip binds
-- setjoin_app. drive_node_destroy still performs its OWN full authorization
-- (BZ139/BZ140/BZ141) below before calling this — R1 holds; this is a
-- mechanical RLS-transition workaround, not an authorization bypass.
CREATE OR REPLACE FUNCTION drive_node_purge_mark(p_node_id BIGINT, p_user_id BIGINT)
RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  UPDATE drive_nodes n
     SET purged_at = now(), purged_by = p_user_id
   WHERE n.id IN (
     SELECT node_id FROM public.drive_closure_subtree(
       (SELECT space_id FROM public.drive_nodes WHERE id = p_node_id), p_node_id
     )
   ) AND n.purged_at IS NULL;
END;
$$;
SELECT apply_worker_ownership('drive_node_purge_mark(BIGINT, BIGINT)'::regprocedure);

CREATE OR REPLACE FUNCTION drive_node_destroy(
  p_user_id BIGINT, p_node_id BIGINT
) RETURNS VOID AS $$
DECLARE
  v_space    BIGINT;
  v_deleted  TIMESTAMPTZ;
BEGIN
  SELECT space_id, deleted_at INTO v_space, v_deleted FROM drive_nodes WHERE id = p_node_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'node not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"node not found"}';
  END IF;
  IF NOT drive_has_admin_perm(p_user_id, 'drive.manage') THEN
    PERFORM public.drive_require_node_capability(p_user_id,p_node_id,'delete');
    PERFORM public.drive_require_node_capability(p_user_id,p_node_id,'manage_acl');
  END IF;
  IF v_deleted IS NULL THEN
    RAISE EXCEPTION 'node must be trashed first' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"node must be trashed before it can be destroyed"}';
  END IF;
  PERFORM drive_tree_lock(v_space);

  -- One journal row per ROOT (unchanged P1 shape) — AUTOPLAN batch-2 #9:
  -- Task 4's tier-1 aging sweep journals per aged row instead (a deliberate
  -- divergence noted there, not here).
  PERFORM drive_node_purge_mark(p_node_id, p_user_id);

  PERFORM drive_access_audit(p_user_id, v_space, 'node.destroy', 'node', p_node_id,
    NULL, NULL, NULL, NULL);
  PERFORM drive_notify_change(v_space, p_node_id, 'destroy');
END;
$$ LANGUAGE plpgsql;
