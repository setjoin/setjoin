-- Begin or join an editor cohort. Authorization and provider policy are checked
-- in the same transaction that mints the durable launch record.
CREATE OR REPLACE FUNCTION office_launch_begin(
  p_user_id bigint,
  p_file_node_id bigint,
  p_base_version_id bigint,
  p_provider_id text,
  p_device_id text,
  p_cohort_key text,
  p_token_hash text,
  p_lease_seconds integer DEFAULT 28800
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE
  v_space_id bigint;
  v_classification text;
	v_family text;
	v_editor_url text;
	v_wopi_public_base_url text;
	v_test_transport boolean:=public.office_test_transport_enabled();
  v_session public.office_editor_sessions%ROWTYPE;
  v_launch_id uuid;
BEGIN
  IF p_device_id IS NULL OR length(p_device_id) NOT BETWEEN 1 AND 200
     OR p_cohort_key IS NULL OR length(p_cohort_key) NOT BETWEEN 1 AND 200
     OR p_token_hash !~ '^[0-9a-f]{64}$'
     OR p_lease_seconds NOT BETWEEN 60 AND 28800 THEN
    RAISE EXCEPTION 'invalid Office launch' USING ERRCODE='BZ322',
      HINT='{"type":"invalidArguments","detail":"invalid Office launch arguments"}';
  END IF;
  IF NOT COALESCE((SELECT enabled FROM public.feature_toggles WHERE key='feature.drive'),false)
     OR NOT COALESCE((SELECT enabled FROM public.feature_toggles WHERE key='feature.office_editing'),false) THEN
    RAISE EXCEPTION 'Office editing is unavailable' USING ERRCODE='BZ321',
      HINT='{"type":"notFound","detail":"Office editing is unavailable"}';
  END IF;

  PERFORM public.drive_require_node_mutation_capability(p_user_id,p_file_node_id,'modify_content');
  SELECT n.space_id,s.classification,public.office_file_family(n.name)
	INTO v_space_id,v_classification,v_family
    FROM public.drive_nodes n JOIN public.drive_files f ON f.node_id=n.id
    JOIN public.drive_spaces s ON s.id=n.space_id
   WHERE n.id=p_file_node_id AND n.deleted_at IS NULL AND n.purged_at IS NULL;
  IF NOT FOUND OR NOT EXISTS (
       SELECT 1 FROM public.drive_file_versions v
        WHERE v.id=p_base_version_id AND v.file_node_id=p_file_node_id) THEN
    RAISE EXCEPTION 'Office file unavailable' USING ERRCODE='BZ321',
      HINT='{"type":"notFound","detail":"Office file unavailable"}';
  END IF;
	SELECT p.config->>'editorUrl',p.config->>'wopiPublicBaseUrl'
	  INTO v_editor_url,v_wopi_public_base_url
	  FROM public.office_provider_policies p
	 WHERE p.provider_id=p_provider_id
	   AND public.office_provider_accepts_new_launch(
	         p.provider_id,'web',v_family,v_classification);
	IF NOT FOUND OR NOT (
	  (v_editor_url ~ '^https://' AND v_wopi_public_base_url ~ '^https://')
	  OR (v_test_transport
	      AND v_editor_url ~ '^http://127[.]0[.]0[.]1:[0-9]{2,5}/browser/'
	      AND v_wopi_public_base_url ~ '^http://(host[.]docker[.]internal|127[.]0[.]0[.]1):[0-9]{2,5}$')
	) THEN
    RAISE EXCEPTION 'Office provider unavailable' USING ERRCODE='BZ327',
      HINT='{"type":"conflict","detail":"Office provider unavailable"}';
	END IF;

  -- A partial unique index protects the active cohort, but it would turn two
  -- simultaneous first launches into a user-visible unique violation because
  -- SELECT FOR UPDATE cannot lock a row that does not exist. Serialize only
  -- this file/provider/cohort decision so both callers deterministically join
  -- the same session.
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'office-session:'||p_file_node_id::text||':'||p_provider_id||':'||p_cohort_key,0));
  SELECT * INTO v_session FROM public.office_editor_sessions
   WHERE file_node_id=p_file_node_id AND provider_id=p_provider_id
     AND cohort_key=p_cohort_key AND status IN ('launching','active','saving','draining')
   FOR UPDATE;
  IF NOT FOUND THEN
    INSERT INTO public.office_editor_sessions(
      space_id,file_node_id,base_version_id,provider_id,cohort_key,status,lease_expires_at)
    VALUES(v_space_id,p_file_node_id,p_base_version_id,p_provider_id,p_cohort_key,
           'active',now()+make_interval(secs=>p_lease_seconds))
    RETURNING * INTO v_session;
  ELSIF v_session.lease_expires_at<=now() OR v_session.status IN ('closed','revoked','expired','failed') THEN
    RAISE EXCEPTION 'Office session expired' USING ERRCODE='BZ324',
      HINT='{"type":"stateMismatch","detail":"Office session expired; reopen the file"}';
  END IF;

  INSERT INTO public.office_editor_launches(
    session_id,space_id,file_node_id,actor_user_id,device_id,action,token_hash,
    fence_generation,expires_at)
  VALUES(v_session.id,v_space_id,p_file_node_id,p_user_id,p_device_id,'edit_online',p_token_hash,
         v_session.fence_generation,v_session.lease_expires_at)
  RETURNING id INTO v_launch_id;
  PERFORM public.drive_access_audit(p_user_id,v_space_id,'office.launch','file',p_file_node_id,
    NULL,jsonb_build_object('launchId',v_launch_id,'sessionId',v_session.id,
      'providerId',p_provider_id,'baseVersionId',p_base_version_id),NULL,NULL);
  PERFORM public.drive_notify_change(v_space_id,p_file_node_id,'update');
  RETURN jsonb_build_object('launchId',v_launch_id,'sessionId',v_session.id,
    'fenceGeneration',v_session.fence_generation,'expiresAt',v_session.lease_expires_at,
	'editorUrl',v_editor_url,'wopiPublicBaseUrl',v_wopi_public_base_url,
	'testTransport',v_test_transport AND v_editor_url ~ '^http://');
END;
$$;
SELECT apply_worker_ownership('office_launch_begin(bigint,bigint,bigint,text,text,text,text,integer)'::regprocedure);
