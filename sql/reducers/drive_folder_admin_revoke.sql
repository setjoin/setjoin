-- mailserver/sql/reducers/drive_folder_admin_revoke.sql
-- Manager-only symmetric revoke.
CREATE OR REPLACE FUNCTION drive_folder_admin_revoke(
  p_user_id BIGINT, p_folder_node_id BIGINT, p_grantee BIGINT
) RETURNS VOID AS $$
DECLARE v_space BIGINT; v_role TEXT;
BEGIN
  SELECT space_id INTO v_space FROM drive_nodes WHERE id = p_folder_node_id;
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

  DELETE FROM drive_folder_admins WHERE node_id = p_folder_node_id AND user_id = p_grantee;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'folder admin not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"folder admin not found"}';
  END IF;

  IF (SELECT acl_mode='acl' FROM public.drive_spaces WHERE id=v_space) THEN
    PERFORM public.drive_acl_bump(
      v_space,'user',p_grantee,p_folder_node_id,'revoke');
  END IF;

  PERFORM drive_access_audit(p_user_id, v_space, 'folderadmin.revoke', 'node', p_folder_node_id,
    NULL, jsonb_build_object('userId', p_grantee), NULL, NULL);
  PERFORM drive_notify_change(v_space, p_folder_node_id, 'update');
END;
$$ LANGUAGE plpgsql;
