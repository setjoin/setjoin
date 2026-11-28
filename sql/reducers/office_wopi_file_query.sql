-- Token-authenticated WOPI file projection. Every callback revalidates current
-- Drive authority and the cohort fence; storage refs never leave the gateway.
CREATE OR REPLACE FUNCTION office_wopi_file_query(
  p_file_node_id bigint,p_token_hash text
) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_out jsonb;
BEGIN
  IF p_token_hash !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'Office launch unavailable' USING ERRCODE='BZ321',
      HINT='{"type":"notFound","detail":"Office launch unavailable"}';
  END IF;
  SELECT jsonb_build_object(
      'launchId',l.id,'sessionId',s.id,'actorUserId',l.actor_user_id,
      'spaceId',s.space_id,'fileNodeId',s.file_node_id,'versionId',s.base_version_id,
      'fenceGeneration',s.fence_generation,'aclMode',sp.acl_mode,'aclEpoch',g.epoch,
      'name',n.name,'size',v.size_bytes,'contentType',v.content_type,
      'contentSha256',v.content_sha256,
	  'providerId',s.provider_id,
	  'proofMode',COALESCE(p.config->>'proofMode','required'),
	  'proofDiscoveryUrl',COALESCE(p.config->>'proofDiscoveryUrl',''),
	  'wopiPublicBaseUrl',COALESCE(p.config->>'wopiPublicBaseUrl',''),
      'canWrite',public.drive_runtime_has_node_capability(l.actor_user_id,s.file_node_id,'modify_content'),
      'manifest',COALESCE((SELECT jsonb_agg(jsonb_build_object(
          'storageRef',c.storage_ref,'sha256',c.sha256,'size',c.size_bytes) ORDER BY vc.ordinal)
        FROM public.drive_version_chunks vc
        JOIN public.drive_chunks c ON c.scope_key=vc.scope_key AND c.sha256=vc.chunk_sha256
        WHERE vc.version_id=s.base_version_id AND vc.stream='content'),'[]'::jsonb)
    ) INTO v_out
    FROM public.office_editor_launches l
    JOIN public.office_editor_sessions s ON s.id=l.session_id
    JOIN public.drive_nodes n ON n.id=s.file_node_id
    JOIN public.drive_file_versions v ON v.id=s.base_version_id AND v.file_node_id=s.file_node_id
    JOIN public.drive_spaces sp ON sp.id=s.space_id
	JOIN public.office_provider_policies p ON p.provider_id=s.provider_id
    JOIN public.drive_acl_generations g ON g.space_id=s.space_id
   WHERE s.file_node_id=p_file_node_id AND l.token_hash=p_token_hash
     AND public.office_wopi_callback_allowed(l.id,p_token_hash,'download');
  IF v_out IS NULL THEN
    RAISE EXCEPTION 'Office launch unavailable' USING ERRCODE='BZ321',
      HINT='{"type":"notFound","detail":"Office launch unavailable"}';
  END IF;
  RETURN v_out;
END;
$$;
SELECT apply_worker_ownership('office_wopi_file_query(bigint,text)'::regprocedure);
