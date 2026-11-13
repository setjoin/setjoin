-- mailserver/sql/reducers/drive_member_revoke.sql
-- Manager may remove anyone but the owner row; a member may remove
-- themselves (leave) at any role.
CREATE OR REPLACE FUNCTION drive_member_revoke(
  p_user_id BIGINT, p_space_id BIGINT, p_grantee BIGINT
) RETURNS VOID AS $$
DECLARE v_role TEXT; v_acl_mode text; v_bump record;
BEGIN
  SELECT acl_mode INTO v_acl_mode FROM public.drive_spaces WHERE id=p_space_id;
  IF NOT public.drive_user_has_space_access(p_user_id,p_space_id) THEN
    RAISE EXCEPTION 'space not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"space not found"}';
  END IF;
  IF NOT public.drive_runtime_has_space_root_capability(
       p_user_id,p_space_id,'manage_acl') AND p_grantee <> p_user_id THEN
    RAISE EXCEPTION 'manager role required' USING ERRCODE='BZ140',
      HINT='{"type":"forbidden","detail":"manager role required to remove another member"}';
  END IF;
  IF p_grantee = drive_space_owner(p_space_id) THEN
    RAISE EXCEPTION 'the owner row cannot be revoked' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"the owner row cannot be revoked"}';
  END IF;
  PERFORM public.drive_tree_lock(p_space_id);
  IF NOT public.drive_user_has_space_access(p_user_id,p_space_id) THEN
    RAISE EXCEPTION 'space not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"space not found"}';
  END IF;
  IF p_grantee<>p_user_id THEN
    PERFORM public.drive_require_space_root_mutation_capability(
      p_user_id,p_space_id,'manage_acl');
  ELSIF v_acl_mode='acl' THEN
    PERFORM 1 FROM public.drive_acl_generations
     WHERE space_id=p_space_id FOR SHARE;
  END IF;
  DELETE FROM drive_space_members WHERE space_id = p_space_id AND user_id = p_grantee;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'member not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"member not found"}';
  END IF;
  PERFORM drive_access_audit(p_user_id, p_space_id, 'member.revoke', 'member', p_grantee, NULL,
    jsonb_build_object('userId', p_grantee), NULL, NULL);
  IF v_acl_mode='acl' THEN
    SELECT * INTO v_bump FROM public.drive_acl_bump(
      p_space_id,'user',p_grantee,NULL,'member_revoke');
  END IF;
  PERFORM drive_notify_change(p_space_id, 0, 'member');
END;
$$ LANGUAGE plpgsql;
