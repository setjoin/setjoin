CREATE OR REPLACE FUNCTION office_admin_list(p_user_id bigint)
RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
BEGIN
  IF NOT (public.drive_has_admin_perm(p_user_id,'office.view')
          OR public.drive_has_admin_perm(p_user_id,'office.manage')) THEN
    RAISE EXCEPTION 'Office management forbidden' USING ERRCODE='BZ323',
      HINT='{"type":"forbidden","detail":"Office view permission required"}';
  END IF;
  RETURN jsonb_build_object(
    'providers',COALESCE((SELECT jsonb_agg(jsonb_build_object(
      'providerId',provider_id,'enabled',enabled,'draining',draining,
      'generation',generation,'routeState',route_state,'configSha256',config_sha256,
      'activeQualificationId',active_qualification_id::text,
      'allowedClassifications',allowed_classifications,
      'allowedPlatforms',allowed_platforms,'allowedFileFamilies',allowed_file_families,
      'entitlementState',entitlement_state,'entitlementRef',entitlement_ref,
      'buildId',build_id,
      'proofDiscoveryUrl',NULLIF(config->>'proofDiscoveryUrl',''),
      'wopiPublicBaseUrl',NULLIF(config->>'wopiPublicBaseUrl',''),
      'editorUrl',NULLIF(config->>'editorUrl',''),
	  'removedAt',removed_at,
      'updatedAt',updated_at) ORDER BY provider_id)
      FROM public.office_provider_policies),'[]'::jsonb),
    'qualifications',COALESCE((SELECT jsonb_agg(jsonb_build_object(
      'qualificationId',q.id::text,'providerId',q.provider_id,
      'providerGeneration',q.provider_generation,'configSha256',q.config_sha256,
      'status',q.status,'profile',q.profile,'checks',q.checks,
      'buildDigest',q.build_digest,'routeRevision',q.route_revision,
      'createdAt',q.created_at,'expiresAt',q.expires_at)
      ORDER BY q.created_at DESC)
      FROM public.office_provider_qualifications q
      WHERE q.created_at>statement_timestamp()-interval '30 days'),'[]'::jsonb),
    'health',COALESCE((SELECT jsonb_agg(row_to_json(h)) FROM (
      SELECT DISTINCT ON (provider_id) provider_id AS "providerId",
        provider_generation AS "providerGeneration",state,
        capacity_state AS "capacityState",facts,observed_at AS "observedAt",
        expires_at AS "expiresAt"
      FROM public.office_provider_health_observations
      ORDER BY provider_id,observed_at DESC,id DESC) h),'[]'::jsonb),
    'operations',COALESCE((SELECT jsonb_agg(jsonb_build_object(
      'operationId',o.id::text,'appId',o.app_id,'kind',o.kind,'state',o.state,
      'stateGeneration',o.state_generation,'phase',o.phase,'progress',o.progress,
      'error',o.error,
      'allowedActions',CASE WHEN o.state='paused_recoverable'
        THEN jsonb_build_array('recover') ELSE '[]'::jsonb END,
      'recovery',CASE WHEN o.state='paused_recoverable' THEN jsonb_build_object(
        'problem',COALESCE(o.error->>'code','EXECUTION_INTERRUPTED'),
        'effect','provider routing remains unchanged',
        'remedy','run the guarded recovery action after inspecting runtime state')
        ELSE NULL END,
      'createdAt',o.created_at,'updatedAt',o.updated_at)
      ORDER BY o.created_at DESC)
      FROM public.office_app_operations o
      WHERE o.created_at>statement_timestamp()-interval '30 days'),'[]'::jsonb),
    'features',jsonb_build_object(
      'driveHistory',COALESCE((SELECT enabled FROM public.feature_toggles WHERE key='feature.drive_history'),false),
      'officeEditing',COALESCE((SELECT enabled FROM public.feature_toggles WHERE key='feature.office_editing'),false),
      'officeLocalOpen',COALESCE((SELECT enabled FROM public.feature_toggles WHERE key='feature.office_local_open'),false),
      'officeManagedDelivery',COALESCE((SELECT enabled FROM public.feature_toggles WHERE key='feature.office_managed_delivery'),false))
  );
END;
$$;
SELECT apply_worker_ownership('office_admin_list(bigint)'::regprocedure);
