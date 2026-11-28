CREATE OR REPLACE FUNCTION exchange_assessment_artifact_commit(
  p_actor_id bigint, p_run_id bigint, p_expected_generation bigint,
  p_sha256 text, p_object_key text, p_crypto_profile text, p_key_id text,
  p_ciphertext_size bigint, p_nonce bytea, p_wrapped_dek bytea,
  p_aad_sha256 text, p_retention_until timestamptz
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_run exchange_assessment_runs%ROWTYPE; v_artifact exchange_assessment_artifacts%ROWTYPE;
BEGIN
  SELECT r.* INTO v_run FROM exchange_assessment_runs r JOIN exchange_assessment_projects p ON p.id=r.project_id
  WHERE r.id=p_run_id AND exchange_assessment_domain_authorized(p_actor_id,p.domain_id,'exchange.assessment.run')
  FOR UPDATE OF r;
  IF NOT FOUND THEN RAISE EXCEPTION 'Exchange assessment run not found' USING ERRCODE='BZ317'; END IF;
  IF p_sha256 !~ '^[0-9a-f]{64}$'
     OR p_aad_sha256 !~ '^[0-9a-f]{64}$' OR p_object_key IS NULL OR octet_length(p_object_key) NOT BETWEEN 1 AND 1024
     OR p_crypto_profile NOT IN ('standard','smx','hybrid') OR p_key_id IS NULL OR octet_length(p_key_id) NOT BETWEEN 1 AND 128
     OR p_ciphertext_size NOT BETWEEN 1 AND 1073741952 OR octet_length(p_nonce) NOT BETWEEN 12 AND 32
     OR octet_length(p_wrapped_dek) NOT BETWEEN 32 AND 4096 THEN
    RAISE EXCEPTION 'Invalid Exchange assessment artifact' USING ERRCODE='BZ316';
  END IF;
  SELECT * INTO v_artifact FROM exchange_assessment_artifacts
    WHERE run_id=p_run_id AND kind='bundle' AND sha256=p_sha256;
  IF FOUND THEN
    IF v_artifact.object_key=p_object_key AND v_artifact.crypto_profile=p_crypto_profile
       AND v_artifact.key_id=p_key_id AND v_artifact.aad_sha256=p_aad_sha256 THEN
      RETURN to_jsonb(v_artifact)||jsonb_build_object('replayed',true,'runGeneration',v_run.generation);
    END IF;
    RAISE EXCEPTION 'Conflicting Exchange assessment artifact replay' USING ERRCODE='BZ319';
  END IF;
  IF v_run.generation<>p_expected_generation THEN RAISE EXCEPTION 'Exchange assessment generation is stale' USING ERRCODE='BZ318'; END IF;
  IF v_run.state NOT IN ('created','preflight','uploading') THEN
    RAISE EXCEPTION 'Exchange assessment artifact cannot be committed in this state' USING ERRCODE='BZ319';
  END IF;
  INSERT INTO exchange_assessment_artifacts(run_id,kind,object_key,sha256,crypto_profile,key_id,
    disposition,ciphertext_size,nonce,wrapped_dek,aad_sha256,retention_until)
  VALUES(p_run_id,'bundle',p_object_key,p_sha256,p_crypto_profile,p_key_id,'active',
    p_ciphertext_size,p_nonce,p_wrapped_dek,p_aad_sha256,p_retention_until)
  RETURNING * INTO v_artifact;
  UPDATE exchange_assessment_runs SET state='validating',generation=generation+1,
    updated_at=statement_timestamp() WHERE id=p_run_id;
  PERFORM audit_write(p_actor_id,'exchange.assessment.artifact.commit','exchange_assessment_artifact',v_artifact.id,
    NULL,jsonb_build_object('sha256',p_sha256,'cryptoProfile',p_crypto_profile,'objectKeyDigest',encode(digest(p_object_key,'sha256'),'hex')),NULL,NULL,'core');
  PERFORM app_notify('exchange_assessment_changed',jsonb_build_object('runId',p_run_id,'artifactId',v_artifact.id,'state','validating')::text);
  RETURN to_jsonb(v_artifact)||jsonb_build_object('runGeneration',v_run.generation+1);
END;
$$;
