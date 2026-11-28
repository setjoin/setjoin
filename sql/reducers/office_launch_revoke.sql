CREATE OR REPLACE FUNCTION office_launch_revoke(
  p_user_id bigint,p_file_node_id bigint,p_launch_id uuid
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_launch public.office_editor_launches%ROWTYPE;
BEGIN
  SELECT * INTO v_launch FROM public.office_editor_launches
   WHERE id=p_launch_id AND file_node_id=p_file_node_id FOR UPDATE;
  IF NOT FOUND OR (v_launch.actor_user_id<>p_user_id
      AND NOT public.drive_has_admin_perm(p_user_id,'office.manage')) THEN
    RAISE EXCEPTION 'Office launch unavailable' USING ERRCODE='BZ321',
      HINT='{"type":"notFound","detail":"Office launch unavailable"}';
  END IF;
  IF v_launch.revoked_at IS NULL THEN
    UPDATE public.office_editor_launches
       SET revoked_at=now(),revocation_generation=revocation_generation+1
     WHERE id=p_launch_id;
    UPDATE public.office_editor_sessions
       SET fence_generation=fence_generation+1,status='revoked',terminal_reason='launch revoked',updated_at=now()
     WHERE id=v_launch.session_id;
    DELETE FROM public.office_wopi_locks WHERE session_id=v_launch.session_id;
    PERFORM public.drive_access_audit(p_user_id,v_launch.space_id,'office.revoke','file',p_file_node_id,
      NULL,jsonb_build_object('launchId',p_launch_id,'sessionId',v_launch.session_id),NULL,NULL);
    PERFORM public.drive_notify_change(v_launch.space_id,p_file_node_id,'update');
  END IF;
  RETURN jsonb_build_object('revoked',true,'launchId',p_launch_id);
END;
$$;
SELECT apply_worker_ownership('office_launch_revoke(bigint,bigint,uuid)'::regprocedure);
