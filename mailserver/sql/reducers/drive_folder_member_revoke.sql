-- mailserver/sql/reducers/drive_folder_member_revoke.sql
-- Symmetric delegated revoke (§5.5). SECURITY DEFINER for the same reason as
-- drive_folder_member_grant. A manager row (including the owner, who is
-- always a manager — V114) is never touchable via delegation.
CREATE OR REPLACE FUNCTION drive_folder_member_revoke(
  p_user_id BIGINT, p_space_id BIGINT, p_folder_node_id BIGINT, p_grantee BIGINT
) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_node_space BIGINT; v_role TEXT;
BEGIN
  IF EXISTS(SELECT 1 FROM public.drive_spaces s
             WHERE s.id=p_space_id AND s.acl_mode='acl') THEN
    PERFORM public.drive_acl_compat_folder_member_revoke(
      p_user_id,p_space_id,p_folder_node_id,p_grantee);
    RETURN;
  END IF;
  IF NOT drive_subtree_admin(p_user_id, p_folder_node_id) THEN
    RAISE EXCEPTION 'folder-admin rights required' USING ERRCODE='BZ140',
      HINT='{"type":"forbidden","detail":"folder-admin rights required on this folder or an ancestor"}';
  END IF;
  SELECT space_id INTO v_node_space FROM drive_nodes WHERE id = p_folder_node_id;
  IF v_node_space IS NULL OR v_node_space <> p_space_id THEN
    RAISE EXCEPTION 'invalid folder' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"folder must belong to this space"}';
  END IF;
  v_role := drive_member_role(p_space_id, p_grantee);
  IF v_role = 'manager' THEN
    RAISE EXCEPTION 'cannot modify a manager via folder delegation' USING ERRCODE='BZ140',
      HINT='{"type":"forbidden","detail":"a manager''s membership cannot be changed via folder delegation"}';
  END IF;

  DELETE FROM drive_space_members WHERE space_id = p_space_id AND user_id = p_grantee;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'member not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"member not found"}';
  END IF;

  PERFORM drive_access_audit(p_user_id, p_space_id, 'member.revoke', 'member', p_grantee, NULL,
    jsonb_build_object('userId', p_grantee), NULL, 'folder-admin');
  PERFORM drive_notify_change(p_space_id, 0, 'member');
END;
$$;

SELECT apply_worker_ownership('drive_folder_member_revoke(BIGINT, BIGINT, BIGINT, BIGINT)'::regprocedure);
