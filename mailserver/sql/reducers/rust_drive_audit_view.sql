-- Frozen content.go auditDedup, after the HTTP download capability admission.
-- Keep its snapshot-visible 15-minute check and audit in one transaction; do
-- not add a uniqueness constraint or change concurrent-view behavior.
CREATE OR REPLACE FUNCTION rust_drive_audit_view(
  p_actor BIGINT, p_space_id BIGINT, p_version_id BIGINT
) RETURNS VOID LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
BEGIN
  IF p_actor IS DISTINCT FROM NULLIF(current_setting('app.current_user_id',true),'')::bigint THEN
    RAISE EXCEPTION 'actor does not match authenticated context' USING ERRCODE='42501';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM public.drive_audit_log a
     WHERE a.space_id=p_space_id AND a.user_id=p_actor AND a.action='view'
       AND a.target_id=p_version_id AND a.occurred_at>now()-interval '15 minutes'
  ) THEN
    PERFORM public.drive_access_audit(p_actor,p_space_id,'view','version',p_version_id,NULL,NULL,NULL,NULL);
  END IF;
END;
$$;
