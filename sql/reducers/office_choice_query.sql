-- Authorized Office choices for one Drive file. Provider policy is deliberately
-- projected through this reducer so callers cannot enumerate disabled providers.
CREATE OR REPLACE FUNCTION office_choice_query(
  p_user_id bigint,
  p_file_node_id bigint,
  p_platform text
) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE
  v_family text;
  v_classification text;
  v_choices jsonb;
BEGIN
  IF p_platform NOT IN ('web','electron') THEN
    RAISE EXCEPTION 'invalid Office platform' USING ERRCODE='BZ322',
      HINT='{"type":"invalidArguments","detail":"platform must be web or electron"}';
  END IF;
  IF NOT COALESCE((SELECT enabled FROM public.feature_toggles WHERE key='feature.drive'),false)
     OR NOT (COALESCE((SELECT enabled FROM public.feature_toggles WHERE key='feature.office_editing'),false)
          OR (p_platform='electron' AND COALESCE((SELECT enabled FROM public.feature_toggles WHERE key='feature.office_local_open'),false))) THEN
    RAISE EXCEPTION 'Office editing is unavailable' USING ERRCODE='BZ321',
      HINT='{"type":"notFound","detail":"Office editing is unavailable"}';
  END IF;

  SELECT public.office_file_family(n.name),
         s.classification
    INTO v_family,v_classification
    FROM public.drive_nodes n
    JOIN public.drive_files f ON f.node_id=n.id
    JOIN public.drive_spaces s ON s.id=n.space_id
   WHERE n.id=p_file_node_id AND n.deleted_at IS NULL AND n.purged_at IS NULL
     AND public.drive_runtime_has_node_capability(p_user_id,n.id,'read_metadata');
  IF NOT FOUND OR v_family IS NULL THEN
    RAISE EXCEPTION 'Office file unavailable' USING ERRCODE='BZ321',
      HINT='{"type":"notFound","detail":"Office file unavailable"}';
  END IF;

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
           'providerId',p.provider_id,
           'mode','edit_online',
           'fileFamily',v_family,
           'available',true,
           'buildId',p.build_id
         ) ORDER BY p.provider_id),'[]'::jsonb)
    INTO v_choices
    FROM public.office_provider_policies p
   WHERE COALESCE((SELECT enabled FROM public.feature_toggles WHERE key='feature.office_editing'),false)
     AND public.office_provider_accepts_new_launch(
           p.provider_id,p_platform,v_family,v_classification);

  RETURN jsonb_build_object(
    'fileFamily',v_family,
    'platform',p_platform,
    'localOpenAllowed',p_platform='electron' AND COALESCE((SELECT enabled FROM public.feature_toggles WHERE key='feature.office_local_open'),false),
    'choices',v_choices
  );
END;
$$;
SELECT apply_worker_ownership('office_choice_query(bigint,bigint,text)'::regprocedure);
