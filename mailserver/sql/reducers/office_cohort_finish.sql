CREATE OR REPLACE FUNCTION office_cohort_finish(
  p_user_id bigint,p_session_id uuid,p_outcome text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_session public.office_editor_sessions%ROWTYPE;
BEGIN
  IF p_outcome NOT IN ('closed','failed','expired') THEN
    RAISE EXCEPTION 'invalid Office finish outcome' USING ERRCODE='BZ322',
      HINT='{"type":"invalidArguments","detail":"invalid Office finish outcome"}';
  END IF;
  SELECT * INTO v_session FROM public.office_editor_sessions WHERE id=p_session_id FOR UPDATE;
  IF NOT FOUND OR (NOT EXISTS (SELECT 1 FROM public.office_editor_launches
      WHERE session_id=p_session_id AND actor_user_id=p_user_id)
      AND NOT public.drive_has_admin_perm(p_user_id,'office.manage')) THEN
    RAISE EXCEPTION 'Office session unavailable' USING ERRCODE='BZ321',
      HINT='{"type":"notFound","detail":"Office session unavailable"}';
  END IF;
  IF v_session.status NOT IN ('closed','failed','expired','revoked') THEN
    UPDATE public.office_editor_sessions SET status=p_outcome,terminal_reason=p_outcome,
      fence_generation=fence_generation+1,updated_at=now() WHERE id=p_session_id;
    DELETE FROM public.office_wopi_locks WHERE session_id=p_session_id;
    PERFORM public.drive_access_audit(p_user_id,v_session.space_id,'office.cohort.finish','file',v_session.file_node_id,
      NULL,jsonb_build_object('sessionId',p_session_id,'outcome',p_outcome),NULL,NULL);
    PERFORM public.drive_notify_change(v_session.space_id,v_session.file_node_id,'update');
  END IF;
  RETURN jsonb_build_object('sessionId',p_session_id,'status',p_outcome);
END;
$$;
SELECT apply_worker_ownership('office_cohort_finish(bigint,uuid,text)'::regprocedure);
