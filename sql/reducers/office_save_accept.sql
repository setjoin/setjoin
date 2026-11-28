-- Accept a provider save exactly once. The existing Drive write reducer remains
-- the sole creator of versions and conflict branches.
CREATE OR REPLACE FUNCTION office_save_accept(
  p_launch_id uuid,p_token_hash text,p_operation_key text,p_expected_base_id bigint,
  p_content_sha256 text,p_size bigint,p_content_type text,p_manifest jsonb,
  p_lock_hash text DEFAULT NULL
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE
  v_launch public.office_editor_launches%ROWTYPE;
  v_session public.office_editor_sessions%ROWTYPE;
  v_receipt public.office_save_receipts%ROWTYPE;
  v_lock public.office_wopi_locks%ROWTYPE;
  v_result jsonb;
  v_class text;
BEGIN
  IF p_operation_key IS NULL OR length(p_operation_key) NOT BETWEEN 1 AND 200
     OR p_token_hash !~ '^[0-9a-f]{64}$' OR p_content_sha256 !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'invalid Office save' USING ERRCODE='BZ322',
      HINT='{"type":"invalidArguments","detail":"invalid Office save arguments"}';
  END IF;
  SELECT * INTO v_launch FROM public.office_editor_launches
   WHERE id=p_launch_id AND token_hash=p_token_hash AND revoked_at IS NULL AND expires_at>now()
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Office launch unavailable' USING ERRCODE='BZ321',
      HINT='{"type":"notFound","detail":"Office launch unavailable"}';
  END IF;
  SELECT * INTO v_session FROM public.office_editor_sessions WHERE id=v_launch.session_id FOR UPDATE;
  IF NOT public.office_wopi_callback_allowed(p_launch_id,p_token_hash,'modify_content') THEN
    RAISE EXCEPTION 'Office save forbidden' USING ERRCODE='BZ323',
      HINT='{"type":"forbidden","detail":"Office write authority is no longer current"}';
  END IF;
  SELECT * INTO v_receipt FROM public.office_save_receipts
   WHERE provider_id=v_session.provider_id AND session_id=v_session.id AND operation_key=p_operation_key;
  IF FOUND THEN
    -- The first accepted save advances the session base. A transport retry is
    -- consequently projected against that newer base even though it carries
    -- the same provider operation key and bytes. The durable operation key is
    -- scoped to this provider session, so content identity is the replay fence;
    -- requiring the now-advanced projection base would make successful saves
    -- non-idempotent at the WOPI edge.
    IF v_receipt.content_sha256<>p_content_sha256 THEN
      RAISE EXCEPTION 'Office save replay mismatch' USING ERRCODE='BZ326',
        HINT='{"type":"stateMismatch","detail":"operation key was already used for different content"}';
    END IF;
    RETURN jsonb_build_object('versionId',v_receipt.result_version_id,
      'branchId',v_receipt.result_branch_id,'conflict',v_receipt.response_class='branched','replayed',true);
  END IF;
  IF v_session.status NOT IN ('active','saving','draining') OR v_session.lease_expires_at<=now()
     OR v_launch.fence_generation<>v_session.fence_generation THEN
    RAISE EXCEPTION 'Office session fenced' USING ERRCODE='BZ324',
      HINT='{"type":"stateMismatch","detail":"Office session is no longer current"}';
  END IF;
  SELECT * INTO v_lock FROM public.office_wopi_locks WHERE session_id=v_session.id AND expires_at>now();
  IF FOUND AND (p_lock_hash IS NULL OR v_lock.opaque_lock_hash<>p_lock_hash
      OR v_lock.fence_generation<>v_session.fence_generation) THEN
    RAISE EXCEPTION 'WOPI lock mismatch' USING ERRCODE='BZ325',
      HINT='{"type":"conflict","detail":"WOPI lock mismatch"}';
  END IF;

  UPDATE public.office_editor_sessions SET status='saving',updated_at=now() WHERE id=v_session.id;
  v_result := public.drive_file_put_version(v_launch.actor_user_id,v_session.file_node_id,
    p_content_sha256,p_size,p_content_type,p_expected_base_id,p_manifest,
    'Office save via '||v_session.provider_id,'office:'||v_session.provider_id,v_session.branch_id);
  v_class := CASE WHEN COALESCE((v_result->>'conflict')::boolean,false) THEN 'branched' ELSE 'accepted' END;
  INSERT INTO public.office_save_receipts(session_id,space_id,file_node_id,provider_id,
    operation_key,expected_base_id,content_sha256,result_version_id,result_branch_id,response_class)
  VALUES(v_session.id,v_session.space_id,v_session.file_node_id,v_session.provider_id,
    p_operation_key,p_expected_base_id,p_content_sha256,(v_result->>'versionId')::bigint,
    NULLIF(v_result->>'branchId','')::bigint,v_class);
  UPDATE public.office_editor_sessions SET base_version_id=(v_result->>'versionId')::bigint,
    branch_id=NULLIF(v_result->>'branchId','')::bigint,status='active',updated_at=now()
   WHERE id=v_session.id;
  PERFORM public.drive_access_audit(v_launch.actor_user_id,v_session.space_id,'office.save','file',v_session.file_node_id,
    NULL,jsonb_build_object('sessionId',v_session.id,'providerId',v_session.provider_id,
      'versionId',v_result->>'versionId','branchId',v_result->'branchId','responseClass',v_class),NULL,NULL);
  RETURN v_result || jsonb_build_object('replayed',false,'responseClass',v_class);
END;
$$;
SELECT apply_worker_ownership('office_save_accept(uuid,text,text,bigint,text,bigint,text,jsonb,text)'::regprocedure);
