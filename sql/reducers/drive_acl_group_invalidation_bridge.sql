-- Deepest bridge from normalized directory-group generation events into the
-- Drive ACL journal.  User-specific membership changes stay exact; broad
-- group/source changes conservatively target all current space users.  The
-- artifact helper rechecks current authority, so widening events are no-ops.
CREATE OR REPLACE FUNCTION trg_drive_acl_group_invalidate()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_grant record; v_epoch bigint; v_cursor bigint; v_principal_kind text;
BEGIN
  FOR v_grant IN
    SELECT DISTINCT g.space_id,g.node_id
      FROM public.drive_acl_grants g
     WHERE g.subject_kind='group' AND g.subject_group_id=NEW.group_id
       AND g.state='active'
  LOOP
    UPDATE public.drive_acl_generations
       SET epoch=epoch+1,updated_at=clock_timestamp()
     WHERE space_id=v_grant.space_id RETURNING epoch INTO v_epoch;
    v_principal_kind:=CASE WHEN NEW.user_id IS NULL THEN 'all' ELSE 'user' END;
    INSERT INTO public.drive_access_invalidations(
      space_id,principal_kind,principal_id,anchor_node_id,resulting_epoch,reason
    ) VALUES(v_grant.space_id,v_principal_kind,NEW.user_id,v_grant.node_id,
             v_epoch,'group_membership') RETURNING cursor INTO v_cursor;
    PERFORM public.drive_acl_revoke_bound_artifacts(
      v_grant.space_id,v_principal_kind,NEW.user_id,NULL,v_grant.node_id,
      'group_membership:'||NEW.reason);
    PERFORM public.app_notify('drive_access',json_build_object(
      'spaceId',v_grant.space_id::text,'epoch',v_epoch::text,
      'cursor',v_cursor::text,'principalKind',v_principal_kind)::text);
  END LOOP;
  RETURN NEW;
END;
$$;
SELECT apply_worker_ownership('trg_drive_acl_group_invalidate()'::regprocedure);
