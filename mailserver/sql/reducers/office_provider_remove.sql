CREATE OR REPLACE FUNCTION office_provider_remove(
  p_user_id bigint,p_provider_id text,p_reason text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_before jsonb;
BEGIN
  IF NOT public.drive_has_admin_perm(p_user_id,'office.manage') THEN
    RAISE EXCEPTION 'Office management forbidden' USING ERRCODE='BZ323',
      HINT='{"type":"forbidden","detail":"Office management permission required"}';
  END IF;
  IF NULLIF(btrim(p_reason),'') IS NULL THEN
    RAISE EXCEPTION 'removal reason required' USING ERRCODE='BZ322',
      HINT='{"type":"invalidArguments","detail":"provider removal requires an audit reason"}';
  END IF;
  SELECT to_jsonb(p)-'config' INTO v_before
    FROM public.office_provider_policies p WHERE provider_id=p_provider_id FOR UPDATE;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('providerId',p_provider_id,'removed',true,'alreadyAbsent',true);
  END IF;
  UPDATE public.office_editor_sessions SET status='revoked',terminal_reason='provider_removed',
    fence_generation=fence_generation+1,updated_at=now()
   WHERE provider_id=p_provider_id AND status IN ('launching','active','saving','draining');
  UPDATE public.office_editor_launches l SET revoked_at=COALESCE(revoked_at,now()),revocation_generation=revocation_generation+1
   WHERE EXISTS (SELECT 1 FROM public.office_editor_sessions s WHERE s.id=l.session_id AND s.provider_id=p_provider_id)
     AND l.revoked_at IS NULL;
  DELETE FROM public.office_wopi_locks l
   WHERE EXISTS (SELECT 1 FROM public.office_editor_sessions s WHERE s.id=l.session_id AND s.provider_id=p_provider_id);
  UPDATE public.office_provider_policies SET enabled=false,draining=false,config='{}'::jsonb,
    entitlement_state='not_permitted',build_id=NULL,generation=generation+1,
    removed_at=now(),updated_by=p_user_id,updated_at=now()
   WHERE provider_id=p_provider_id;
  PERFORM public.audit_write(p_user_id,'office.provider.remove','office_provider',NULL,
    v_before,(SELECT to_jsonb(p)-'config' FROM public.office_provider_policies p WHERE provider_id=p_provider_id),
    NULL,p_reason,'core');
  RETURN jsonb_build_object('providerId',p_provider_id,'removed',true,'alreadyAbsent',false);
END;
$$;
SELECT apply_worker_ownership('office_provider_remove(bigint,text,text)'::regprocedure);
