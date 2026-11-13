CREATE OR REPLACE FUNCTION office_local_open_accept(
  p_user_id bigint,p_file_node_id bigint,p_app_id text,p_device_id text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_space_id bigint; v_version_id bigint;
BEGIN
  IF p_app_id NOT IN ('microsoft-office','wps-office','libreoffice','collabora-office')
     OR p_device_id IS NULL OR length(p_device_id) NOT BETWEEN 1 AND 200 THEN
    RAISE EXCEPTION 'invalid local Office open' USING ERRCODE='BZ322',
      HINT='{"type":"invalidArguments","detail":"invalid local Office application or device"}';
  END IF;
  IF NOT COALESCE((SELECT enabled FROM public.feature_toggles WHERE key='feature.drive'),false)
     OR NOT COALESCE((SELECT enabled FROM public.feature_toggles WHERE key='feature.office_local_open'),false) THEN
    RAISE EXCEPTION 'local Office open unavailable' USING ERRCODE='BZ321',
      HINT='{"type":"notFound","detail":"local Office open unavailable"}';
  END IF;
  PERFORM public.drive_require_node_mutation_capability(p_user_id,p_file_node_id,'modify_content');
  SELECT n.space_id,f.head_version_id INTO v_space_id,v_version_id
    FROM public.drive_nodes n JOIN public.drive_files f ON f.node_id=n.id
   WHERE n.id=p_file_node_id AND n.deleted_at IS NULL AND n.purged_at IS NULL
     AND lower(n.name) ~ '\.(doc|docx|odt|rtf|xls|xlsx|ods|csv|ppt|pptx|odp)$';
  IF NOT FOUND OR v_version_id IS NULL THEN
    RAISE EXCEPTION 'Office file unavailable' USING ERRCODE='BZ321',
      HINT='{"type":"notFound","detail":"Office file unavailable"}';
  END IF;
  PERFORM public.drive_access_audit(p_user_id,v_space_id,'office.local_open','file',p_file_node_id,
    NULL,jsonb_build_object('appId',p_app_id,'deviceId',p_device_id,'baseVersionId',v_version_id),NULL,NULL);
  RETURN jsonb_build_object('accepted',true,'baseVersionId',v_version_id);
END;
$$;
SELECT apply_worker_ownership('office_local_open_accept(bigint,bigint,text,text)'::regprocedure);
