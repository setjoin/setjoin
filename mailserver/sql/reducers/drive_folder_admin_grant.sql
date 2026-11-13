-- mailserver/sql/reducers/drive_folder_admin_grant.sql
-- Manager-only (§5.5 v1-lite: delegation itself is not delegable — only a
-- space manager appoints a folder admin). Thin invoker-rights reducer; the
-- V115 drive_folder_admins_write RLS policy (manager-only) is the backstop.
CREATE OR REPLACE FUNCTION drive_folder_admin_grant(
  p_user_id BIGINT, p_folder_node_id BIGINT, p_grantee BIGINT
) RETURNS VOID AS $$
DECLARE v_space BIGINT; v_kind TEXT; v_deleted TIMESTAMPTZ; v_role TEXT;
BEGIN
  SELECT space_id, kind, deleted_at INTO v_space, v_kind, v_deleted
    FROM drive_nodes WHERE id = p_folder_node_id;
  IF v_space IS NULL THEN
    RAISE EXCEPTION 'folder not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"folder not found"}';
  END IF;
  IF NOT public.drive_user_has_space_access(p_user_id,v_space) THEN
    RAISE EXCEPTION 'space not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"space not found"}';
  END IF;
  IF NOT public.drive_runtime_has_node_capability(
       p_user_id,p_folder_node_id,'manage_acl') THEN
    RAISE EXCEPTION 'manager role required' USING ERRCODE='BZ140',
      HINT='{"type":"forbidden","detail":"manager role required"}';
  END IF;
  IF v_kind <> 'folder' OR v_deleted IS NOT NULL THEN
    RAISE EXCEPTION 'target must be a live folder' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"target must be a live (non-trashed) folder"}';
  END IF;
  IF NOT public.drive_user_has_space_access(p_grantee,v_space) THEN
    RAISE EXCEPTION 'grantee is not a space member' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"grantee must already be a space member"}';
  END IF;

  INSERT INTO drive_folder_admins (node_id, space_id, user_id, granted_by)
  VALUES (p_folder_node_id, v_space, p_grantee, p_user_id)
  ON CONFLICT (node_id, user_id) DO UPDATE SET granted_by = EXCLUDED.granted_by, granted_at = now();

  IF (SELECT acl_mode='acl' FROM public.drive_spaces WHERE id=v_space) THEN
    PERFORM public.drive_acl_bump(
      v_space,'user',p_grantee,p_folder_node_id,'grant');
  END IF;

  PERFORM drive_access_audit(p_user_id, v_space, 'folderadmin.grant', 'node', p_folder_node_id,
    NULL, jsonb_build_object('userId', p_grantee), NULL, NULL);
  PERFORM drive_notify_change(v_space, p_folder_node_id, 'update');
END;
$$ LANGUAGE plpgsql;
