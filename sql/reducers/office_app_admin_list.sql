CREATE OR REPLACE FUNCTION office_app_admin_list(p_user_id bigint)
RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE
  v_provider jsonb;
  v_allowed_actions jsonb;
BEGIN
  IF NOT (public.drive_has_admin_perm(p_user_id,'apps.view')
          OR public.drive_has_admin_perm(p_user_id,'apps.manage')) THEN
    RAISE EXCEPTION 'application management forbidden' USING ERRCODE='BZ323';
  END IF;
  SELECT jsonb_build_object('providerId',p.provider_id,'generation',p.generation,
      'ready',p.route_state IN ('connected_inactive','fenced'),'state',p.route_state,
      'remedy',CASE WHEN p.route_state IN ('connected_inactive','fenced') THEN NULL
        ELSE 'Configure an inactive Office provider before installing Collabora CODE' END)
    INTO v_provider
    FROM public.office_provider_policies p
   WHERE p.provider_id='collabora' AND p.removed_at IS NULL;
  v_allowed_actions:=CASE WHEN
      COALESCE((SELECT enabled FROM public.feature_toggles
                 WHERE key='feature.office_managed_delivery'),false)
      AND v_provider IS NOT NULL AND COALESCE((v_provider->>'ready')::boolean,false)
      AND NOT EXISTS (SELECT 1 FROM public.office_app_revisions
                       WHERE app_id='collabora-code' AND state NOT IN ('removed','failed'))
      AND NOT EXISTS (SELECT 1 FROM public.office_app_operations
                       WHERE app_id='collabora-code' AND state IN (
                         'requested','claimed','preflight','pulling','verifying','staging',
                         'starting','qualifying','disabling_launches','draining',
                         'blocked_drain','rolling_back','paused_recoverable'))
    THEN '["install"]'::jsonb ELSE '[]'::jsonb END;
  RETURN jsonb_build_object(
    'app',jsonb_build_object(
      'appId','collabora-code','name','Collabora CODE','channel','test',
      'allowedActions',v_allowed_actions,'providerReadiness',v_provider,
      'managedDeliveryEnabled',COALESCE((SELECT enabled FROM public.feature_toggles
        WHERE key='feature.office_managed_delivery'),false)),
    'revisions',COALESCE((SELECT jsonb_agg(jsonb_build_object(
      'revisionId',r.id::text,'revision',r.revision,'providerId',r.provider_id,
      'state',r.state,'imageReference',r.image_reference,'imageDigest',r.image_digest,
      'artifactReceipt',r.artifact_receipt,'runtimeConfig',r.runtime_config,
      'createdAt',r.created_at,'updatedAt',r.updated_at) ORDER BY r.revision DESC)
      FROM public.office_app_revisions r),'[]'::jsonb),
    'operations',COALESCE((SELECT jsonb_agg(jsonb_build_object(
      'operationId',o.id::text,'kind',o.kind,'state',o.state,
      'stateGeneration',o.state_generation,'phase',o.phase,'progress',o.progress,
      'error',o.error,'providerId',o.request->>'providerId',
      'allowedActions',CASE WHEN o.state='paused_recoverable'
        THEN jsonb_build_array('recover') ELSE '[]'::jsonb END,
      'recovery',CASE WHEN o.state='paused_recoverable' THEN jsonb_build_object(
        'problem','Managed application state is uncertain after interruption',
        'effect','No new launch is enabled and foreign resources remain untouched',
        'remedy','Restore Docker and database access, then recover this operation')
        ELSE NULL END,
      'createdAt',o.created_at,'updatedAt',o.updated_at) ORDER BY o.created_at DESC)
      FROM public.office_app_operations o
      WHERE o.created_at>statement_timestamp()-interval '30 days'),'[]'::jsonb));
END;
$$;
SELECT apply_worker_ownership('office_app_admin_list(bigint)'::regprocedure);
