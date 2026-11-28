CREATE OR REPLACE FUNCTION office_provider_qualification_target(
  p_user_id bigint,p_provider_id text,p_expected_generation bigint
) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_provider office_provider_policies%ROWTYPE;
BEGIN
  IF NOT public.drive_has_admin_perm(p_user_id,'office.manage') THEN
    RAISE EXCEPTION 'Office management forbidden' USING ERRCODE='BZ323';
  END IF;
  SELECT * INTO v_provider FROM public.office_provider_policies
   WHERE provider_id=p_provider_id AND removed_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Office provider unavailable' USING ERRCODE='BZ327';
  END IF;
  IF v_provider.generation<>p_expected_generation THEN
    RAISE EXCEPTION 'Office provider generation changed' USING ERRCODE='BZ324';
  END IF;
  RETURN jsonb_build_object(
    'providerId',v_provider.provider_id,'generation',v_provider.generation,
    'configSha256',v_provider.config_sha256,
    'profile',COALESCE(v_provider.config->>'profile','existing-provider'),
    'proofDiscoveryUrl',v_provider.config->>'proofDiscoveryUrl',
    'wopiPublicBaseUrl',v_provider.config->>'wopiPublicBaseUrl',
    'editorUrl',v_provider.config->>'editorUrl',
    'privateAllowHosts',COALESCE(v_provider.config->'privateAllowHosts','[]'::jsonb),
    'privateAllowCidrs',COALESCE(v_provider.config->'privateAllowCidrs','[]'::jsonb),
    'buildId',v_provider.build_id);
END;
$$;
SELECT apply_worker_ownership('office_provider_qualification_target(bigint,text,bigint)'::regprocedure);
