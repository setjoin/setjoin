-- mailserver/sql/reducers/drive_lock_list.sql
-- Read reducer: live (unexpired) lock rows for a space, with holder display
-- name. SECURITY DEFINER (LR-12): the admin console reads this for a
-- drive.view admin who is NOT a space member -- drive_file_locks' own RLS
-- SELECT policy is member-only, so an invoker-rights read would see nothing.
CREATE OR REPLACE FUNCTION drive_lock_list(p_user_id bigint, p_space_id bigint) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_admin boolean;
BEGIN
  v_admin := drive_has_admin_perm(p_user_id, 'drive.view');
  IF NOT public.drive_user_has_space_access(p_user_id,p_space_id) AND NOT v_admin THEN
    RAISE EXCEPTION 'space not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"space not found"}';
  END IF;
  RETURN jsonb_build_object('locks', COALESCE((
    SELECT jsonb_agg(jsonb_build_object(
             'nodeId', l.node_id, 'name', n.name, 'holderId', l.user_id,
             'holderName', m.display_name, 'mode', l.mode, 'branchId', l.branch_id,
             'acquiredAt', l.acquired_at, 'expiresAt', l.expires_at,
             'deviceLabel', l.device_label) ORDER BY l.acquired_at)
      FROM drive_file_locks l
      JOIN drive_nodes n ON n.id = l.node_id
      LEFT JOIN mailboxes m ON m.user_id = l.user_id AND m.is_primary
     WHERE l.space_id = p_space_id AND l.expires_at > now()
       AND (v_admin OR public.drive_runtime_has_node_capability(
             p_user_id,l.node_id,'read_metadata'))
  ), '[]'::jsonb));
END;
$$;

SELECT apply_worker_ownership('drive_lock_list(BIGINT, BIGINT)'::regprocedure);
