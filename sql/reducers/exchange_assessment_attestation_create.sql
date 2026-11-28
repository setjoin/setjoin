CREATE OR REPLACE FUNCTION exchange_assessment_attestation_create(
  p_actor_id bigint, p_run_id bigint, p_kind text, p_subject_digest text, p_statement jsonb
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_run exchange_assessment_runs%ROWTYPE; v_row exchange_assessment_attestations%ROWTYPE;
BEGIN
  SELECT r.* INTO v_run FROM exchange_assessment_runs r
  JOIN exchange_assessment_projects p ON p.id=r.project_id
  WHERE r.id=p_run_id AND exchange_assessment_domain_authorized(p_actor_id,p.domain_id,'exchange.assessment.attest')
  FOR SHARE OF r;
  IF NOT FOUND THEN RAISE EXCEPTION 'Exchange assessment run not found' USING ERRCODE='BZ317'; END IF;
  IF p_kind NOT IN ('collection_zero','completeness','handling','backup_expiry')
     OR p_subject_digest !~ '^[0-9a-f]{64}$' OR p_statement IS NULL OR jsonb_typeof(p_statement)<>'object'
     OR octet_length(p_statement::text)>65536 THEN RAISE EXCEPTION 'Invalid Exchange assessment attestation' USING ERRCODE='BZ316'; END IF;
  IF p_kind='collection_zero' AND p_actor_id=v_run.created_by THEN
    RAISE EXCEPTION 'Collector cannot attest the same zero result' USING ERRCODE='BZ320',HINT='{"type":"separation_of_duties"}';
  END IF;
  INSERT INTO exchange_assessment_attestations(run_id,kind,subject_digest,statement,actor_id)
  VALUES(p_run_id,p_kind,p_subject_digest,p_statement,p_actor_id)
  ON CONFLICT(run_id,kind,subject_digest) DO NOTHING RETURNING * INTO v_row;
  IF NOT FOUND THEN SELECT * INTO v_row FROM exchange_assessment_attestations WHERE run_id=p_run_id AND kind=p_kind AND subject_digest=p_subject_digest; END IF;
  PERFORM audit_write(p_actor_id,'exchange.assessment.attestation.create','exchange_assessment_run',p_run_id,NULL,to_jsonb(v_row),NULL,NULL,'core');
  PERFORM app_notify('exchange_assessment',jsonb_build_object('event','attestation.created','runId',p_run_id,'kind',p_kind)::text);
  RETURN to_jsonb(v_row);
END;
$$;
SELECT apply_worker_ownership('exchange_assessment_attestation_create(bigint,bigint,text,text,jsonb)'::regprocedure);
