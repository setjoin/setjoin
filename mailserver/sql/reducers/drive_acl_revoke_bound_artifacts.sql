-- Revoke derived, user-bound artifacts after an ACL fact changes.  Candidate
-- rows are narrowed by principal and subtree, then CURRENT effective access
-- is rechecked so a widening mutation or a still-effective alternate grant
-- never destroys a valid watch/token/lease/upload authorization.
CREATE OR REPLACE FUNCTION drive_acl_revoke_bound_artifacts(
  p_space_id bigint,
  p_principal_kind text,
  p_principal_id bigint DEFAULT NULL,
  p_principal_group_id bigint DEFAULT NULL,
  p_anchor_node_id bigint DEFAULT NULL,
  p_reason text DEFAULT 'access_changed'
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_watches int:=0; v_locks int:=0; v_exports int:=0;
  v_leases int:=0; v_uploads int:=0;
BEGIN
  IF p_principal_kind NOT IN ('user','group','all') THEN
    RAISE EXCEPTION 'invalid invalidation principal' USING ERRCODE='BZ252',
      HINT='{"type":"drive_acl_invalid","field":"principal"}';
  END IF;

  WITH affected_nodes AS MATERIALIZED (
    SELECT n.id FROM public.drive_nodes n
     WHERE n.space_id=p_space_id AND (
       p_anchor_node_id IS NULL OR n.id IN (
         SELECT c.descendant_id FROM public.drive_node_closure c
          WHERE c.space_id=p_space_id AND c.ancestor_id=p_anchor_node_id))
  ), candidate_users AS MATERIALIZED (
    SELECT p_principal_id AS user_id WHERE p_principal_kind='user'
    UNION ALL
    SELECT m.user_id FROM public.directory_group_members m
     WHERE p_principal_kind='group' AND m.group_id=p_principal_group_id
  )
  DELETE FROM public.drive_watches w
   USING affected_nodes n
   WHERE w.node_id=n.id
     AND (p_principal_kind='all' OR w.user_id IN (SELECT user_id FROM candidate_users))
     AND NOT public.drive_runtime_has_node_capability(w.user_id,w.node_id,'read_metadata');
  GET DIAGNOSTICS v_watches=ROW_COUNT;

  WITH affected_nodes AS MATERIALIZED (
    SELECT n.id FROM public.drive_nodes n
     WHERE n.space_id=p_space_id AND (
       p_anchor_node_id IS NULL OR n.id IN (
         SELECT c.descendant_id FROM public.drive_node_closure c
          WHERE c.space_id=p_space_id AND c.ancestor_id=p_anchor_node_id))
  ), candidate_users AS MATERIALIZED (
    SELECT p_principal_id AS user_id WHERE p_principal_kind='user'
    UNION ALL SELECT m.user_id FROM public.directory_group_members m
     WHERE p_principal_kind='group' AND m.group_id=p_principal_group_id
  )
  DELETE FROM public.drive_file_locks l
   USING affected_nodes n
   WHERE l.node_id=n.id
     AND (p_principal_kind='all' OR l.user_id IN (SELECT user_id FROM candidate_users))
     AND NOT public.drive_runtime_has_node_capability(
       l.user_id,l.node_id,'modify_content');
  GET DIAGNOSTICS v_locks=ROW_COUNT;

  WITH affected_nodes AS MATERIALIZED (
    SELECT n.id FROM public.drive_nodes n
     WHERE n.space_id=p_space_id AND (
       p_anchor_node_id IS NULL OR n.id IN (
         SELECT c.descendant_id FROM public.drive_node_closure c
          WHERE c.space_id=p_space_id AND c.ancestor_id=p_anchor_node_id))
  ), candidate_users AS MATERIALIZED (
    SELECT p_principal_id AS user_id WHERE p_principal_kind='user'
    UNION ALL SELECT m.user_id FROM public.directory_group_members m
     WHERE p_principal_kind='group' AND m.group_id=p_principal_group_id
  )
  UPDATE public.drive_export_grants g SET
    revoked_at=clock_timestamp(),revoked_reason=left(COALESCE(p_reason,'access_changed'),200)
   FROM public.drive_file_versions v,affected_nodes n
   WHERE g.version_id=v.id AND v.file_node_id=n.id
     AND g.consumed_at IS NULL AND g.revoked_at IS NULL
     AND (p_principal_kind='all' OR g.grantee IN (SELECT user_id FROM candidate_users))
     AND NOT public.drive_runtime_has_node_capability(g.grantee,n.id,'download');
  GET DIAGNOSTICS v_exports=ROW_COUNT;

  WITH affected_nodes AS MATERIALIZED (
    SELECT n.id FROM public.drive_nodes n
     WHERE n.space_id=p_space_id AND (
       p_anchor_node_id IS NULL OR n.id IN (
         SELECT c.descendant_id FROM public.drive_node_closure c
          WHERE c.space_id=p_space_id AND c.ancestor_id=p_anchor_node_id))
  ), candidate_users AS MATERIALIZED (
    SELECT p_principal_id AS user_id WHERE p_principal_kind='user'
    UNION ALL SELECT m.user_id FROM public.directory_group_members m
     WHERE p_principal_kind='group' AND m.group_id=p_principal_group_id
  )
  UPDATE public.drive_access_use_leases l SET state='abandoned'
   FROM public.drive_acl_grants g,affected_nodes n
   WHERE l.grant_id=g.id AND g.node_id=n.id AND l.state='reserved'
     AND (p_principal_kind='all' OR l.user_id IN (SELECT user_id FROM candidate_users))
     AND NOT public.drive_runtime_has_node_capability(l.user_id,n.id,l.capability);
  GET DIAGNOSTICS v_leases=ROW_COUNT;

  WITH affected_nodes AS MATERIALIZED (
    SELECT n.id,n.kind FROM public.drive_nodes n
     WHERE n.space_id=p_space_id AND (
       p_anchor_node_id IS NULL OR n.id IN (
         SELECT c.descendant_id FROM public.drive_node_closure c
          WHERE c.space_id=p_space_id AND c.ancestor_id=p_anchor_node_id))
  ), candidate_users AS MATERIALIZED (
    SELECT p_principal_id AS user_id WHERE p_principal_kind='user'
    UNION ALL SELECT m.user_id FROM public.directory_group_members m
     WHERE p_principal_kind='group' AND m.group_id=p_principal_group_id
  )
  DELETE FROM public.drive_upload_authorizations a
   USING affected_nodes n
   WHERE a.target_node_id=n.id
     AND (p_principal_kind='all' OR a.user_id IN (SELECT user_id FROM candidate_users))
     AND NOT public.drive_runtime_has_node_capability(
       a.user_id,n.id,CASE WHEN n.kind='folder' THEN 'create_child' ELSE 'modify_content' END);
  GET DIAGNOSTICS v_uploads=ROW_COUNT;

  RETURN jsonb_build_object('watches',v_watches,'locks',v_locks,'exports',v_exports,
    'leases',v_leases,'uploads',v_uploads);
END;
$$;
SELECT apply_worker_ownership(
  'drive_acl_revoke_bound_artifacts(bigint,text,bigint,bigint,bigint,text)'::regprocedure);
