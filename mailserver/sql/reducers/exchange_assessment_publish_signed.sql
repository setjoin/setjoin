CREATE OR REPLACE FUNCTION exchange_assessment_publish_signed(
  p_actor_id bigint, p_run_id bigint, p_projection_digest text,
  p_receipt_sha256 text, p_object_key text, p_crypto_profile text, p_key_id text,
  p_ciphertext_size bigint, p_nonce bytea, p_wrapped_dek bytea, p_aad_sha256 text,
  p_receipt jsonb, p_signature_algorithm text, p_signing_key_id text, p_signature bytea
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE
  v_run exchange_assessment_runs%ROWTYPE;
  v_snapshot exchange_assessment_claim_snapshots%ROWTYPE;
  v_artifact exchange_assessment_artifacts%ROWTYPE;
  v_publication exchange_assessment_publications%ROWTYPE;
BEGIN
  SELECT r.* INTO v_run FROM exchange_assessment_runs r
  JOIN exchange_assessment_projects p ON p.id=r.project_id
  WHERE r.id=p_run_id AND exchange_assessment_domain_authorized(p_actor_id,p.domain_id,'exchange.assessment.publish')
  FOR UPDATE OF r;
  IF NOT FOUND THEN RAISE EXCEPTION 'Exchange assessment run not found' USING ERRCODE='BZ317'; END IF;

  SELECT * INTO v_publication FROM exchange_assessment_publications
  WHERE run_id=p_run_id AND projection_digest=p_projection_digest AND revoked_at IS NULL;
  IF FOUND THEN RETURN to_jsonb(v_publication)||'{"replayed":true}'::jsonb; END IF;

  SELECT * INTO v_snapshot FROM exchange_assessment_claim_snapshots
  WHERE run_id=p_run_id AND projection_digest=p_projection_digest AND invalidated_at IS NULL;
  IF NOT FOUND OR v_snapshot.run_generation<>v_run.generation OR v_run.state<>'ready'
     OR v_snapshot.projection->>'supportCellStale'='true'
     OR EXISTS(SELECT 1 FROM jsonb_array_elements(v_snapshot.projection->'rows') row
       WHERE row->>'claimState' IN ('unassessed','stale')) THEN
    RAISE EXCEPTION 'Exchange assessment publication evidence is incomplete' USING ERRCODE='BZ320',HINT='{"type":"evidenceIncomplete"}';
  END IF;
  IF EXISTS(SELECT 1 FROM exchange_assessment_decisions d
    WHERE d.run_id=p_run_id AND d.actor_id=p_actor_id AND d.decision='waived') THEN
    RAISE EXCEPTION 'Waiver decider cannot publish the dependent claim' USING ERRCODE='BZ320',HINT='{"type":"separation_of_duties"}';
  END IF;
  IF p_projection_digest !~ '^[0-9a-f]{64}$' OR p_receipt_sha256 !~ '^[0-9a-f]{64}$'
     OR p_aad_sha256 !~ '^[0-9a-f]{64}$' OR octet_length(p_object_key) NOT BETWEEN 1 AND 1024
     OR p_crypto_profile NOT IN ('standard','smx','hybrid') OR octet_length(p_key_id) NOT BETWEEN 1 AND 128
     OR p_ciphertext_size NOT BETWEEN 1 AND 1073741952 OR octet_length(p_nonce) NOT BETWEEN 12 AND 32
     OR octet_length(p_wrapped_dek) NOT BETWEEN 32 AND 4096
     OR jsonb_typeof(p_receipt)<>'object' OR p_receipt#>>'{claims,kind}'<>'publication'
     OR p_receipt#>>'{claims,subjectSha256}'<>p_projection_digest
     OR p_signature_algorithm<>'ed25519' OR octet_length(p_signing_key_id) NOT BETWEEN 1 AND 128
     OR octet_length(p_signature)<>64 THEN
    RAISE EXCEPTION 'Invalid signed Exchange publication receipt' USING ERRCODE='BZ316';
  END IF;

  INSERT INTO exchange_assessment_artifacts(run_id,kind,object_key,sha256,crypto_profile,key_id,
    disposition,ciphertext_size,nonce,wrapped_dek,aad_sha256)
  VALUES(p_run_id,'receipt',p_object_key,p_receipt_sha256,p_crypto_profile,p_key_id,'active',
    p_ciphertext_size,p_nonce,p_wrapped_dek,p_aad_sha256) RETURNING * INTO v_artifact;
  INSERT INTO exchange_assessment_receipts(run_id,kind,subject_digest,receipt,
    signature_algorithm,signing_key_id,signature,created_by)
  VALUES(p_run_id,'publication',p_projection_digest,p_receipt,p_signature_algorithm,
    p_signing_key_id,p_signature,p_actor_id);
  INSERT INTO exchange_assessment_publications(run_id,projection_digest,receipt_artifact_id,published_by)
  VALUES(p_run_id,p_projection_digest,v_artifact.id,p_actor_id) RETURNING * INTO v_publication;
  PERFORM audit_write(p_actor_id,'exchange.assessment.publish','exchange_assessment_run',p_run_id,NULL,
    jsonb_build_object('projectionDigest',p_projection_digest,'receiptArtifactId',v_artifact.id),NULL,NULL,'core');
  PERFORM app_notify('exchange_assessment',jsonb_build_object('event','publication.created','runId',p_run_id)::text);
  RETURN to_jsonb(v_publication)||jsonb_build_object('receiptArtifactId',v_artifact.id);
END;
$$;
SELECT apply_worker_ownership('exchange_assessment_publish_signed(bigint,bigint,text,text,text,text,text,bigint,bytea,bytea,text,jsonb,text,text,bytea)'::regprocedure);
