-- mailserver/sql/reducers/drive_folder_member_grant.sql
-- The delegated half of §5.5: a folder admin adds editors/viewers within
-- their OWN subtree — never manager (that stays a space-manager-only power,
-- drive_member_grant). SECURITY DEFINER (§6.3 locked): the caller re-checks
-- its own authority via drive_subtree_admin, then must cross the
-- drive_space_members_write RLS policy (manager-only ∨ self), which a
-- non-manager folder admin does not otherwise satisfy.
CREATE OR REPLACE FUNCTION drive_folder_member_grant(
  p_user_id BIGINT, p_space_id BIGINT, p_folder_node_id BIGINT,
  p_grantee BIGINT, p_role TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_node_space BIGINT; v_kind TEXT; v_deleted TIMESTAMPTZ; v_cur_role TEXT;
BEGIN
  IF EXISTS(SELECT 1 FROM public.drive_spaces s
             WHERE s.id=p_space_id AND s.acl_mode='acl') THEN
    RETURN public.drive_acl_compat_folder_member_set(
      p_user_id,p_space_id,p_folder_node_id,p_grantee,p_role);
  END IF;
  IF NOT drive_subtree_admin(p_user_id, p_folder_node_id) THEN
    RAISE EXCEPTION 'folder-admin rights required' USING ERRCODE='BZ140',
      HINT='{"type":"forbidden","detail":"folder-admin rights required on this folder or an ancestor"}';
  END IF;
  SELECT space_id, kind, deleted_at INTO v_node_space, v_kind, v_deleted
    FROM drive_nodes WHERE id = p_folder_node_id;
  IF v_node_space IS NULL OR v_node_space <> p_space_id OR v_kind <> 'folder' OR v_deleted IS NOT NULL THEN
    RAISE EXCEPTION 'invalid folder' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"folder must be a live folder in this space"}';
  END IF;
  IF p_role NOT IN ('editor','viewer') THEN
    RAISE EXCEPTION 'folder admins may only grant editor or viewer' USING ERRCODE='BZ140',
      HINT='{"type":"forbidden","detail":"folder admins may only grant editor or viewer, never manager"}';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM users WHERE id = p_grantee) THEN
    RAISE EXCEPTION 'grantee not found' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"grantee does not exist"}';
  END IF;
  -- Guest door (guest-accounts G0, codex C-3): no explicit Drive grant may
  -- name a guest. Guest Drive reach remains derived live from chat/meeting
  -- scope after G4; ad-hoc grants stay closed.
  IF is_guest_account(p_grantee) THEN
    RAISE EXCEPTION 'guest accounts cannot be granted drive space membership'
      USING ERRCODE='BZ215', HINT='{"type":"forbidden","detail":"guest accounts cannot receive direct Drive grants"}';
  END IF;
  -- A manager row is space-manager territory only — a delegated grant must
  -- never touch it, even to re-affirm the same role (no silent downgrade path).
  v_cur_role := drive_member_role(p_space_id, p_grantee);
  IF v_cur_role = 'manager' THEN
    RAISE EXCEPTION 'cannot modify a manager via folder delegation' USING ERRCODE='BZ140',
      HINT='{"type":"forbidden","detail":"a manager''s membership cannot be changed via folder delegation"}';
  END IF;

  INSERT INTO drive_space_members (space_id, user_id, role, granted_by)
  VALUES (p_space_id, p_grantee, p_role, p_user_id)
  ON CONFLICT (space_id, user_id) DO UPDATE SET role = EXCLUDED.role, granted_by = EXCLUDED.granted_by;

  PERFORM drive_access_audit(p_user_id, p_space_id, 'member.grant', 'member', p_grantee, NULL,
    jsonb_build_object('userId', p_grantee, 'role', p_role), NULL, 'folder-admin');
  PERFORM drive_notify_change(p_space_id, 0, 'member');
  RETURN jsonb_build_object('status', 'granted');
END;
$$;

SELECT apply_worker_ownership('drive_folder_member_grant(BIGINT, BIGINT, BIGINT, BIGINT, TEXT)'::regprocedure);
