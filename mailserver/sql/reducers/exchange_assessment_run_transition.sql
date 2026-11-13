CREATE OR REPLACE FUNCTION exchange_assessment_run_transition(
  p_actor_id bigint, p_run_id bigint, p_expected_generation bigint,
  p_to_state text, p_error_code text DEFAULT NULL
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_run exchange_assessment_runs%ROWTYPE; v_allowed boolean;
BEGIN
  SELECT r.* INTO v_run
  FROM exchange_assessment_runs r JOIN exchange_assessment_projects p ON p.id=r.project_id
  WHERE r.id=p_run_id AND exchange_assessment_domain_authorized(p_actor_id,p.domain_id,'exchange.assessment.run')
  FOR UPDATE OF r;
  IF NOT FOUND THEN RAISE EXCEPTION 'Exchange assessment run not found' USING ERRCODE='BZ317', HINT='{"type":"notFound"}'; END IF;
  IF v_run.generation<>p_expected_generation THEN RAISE EXCEPTION 'Exchange assessment generation is stale' USING ERRCODE='BZ318', HINT='{"type":"stateMismatch"}'; END IF;
  v_allowed := CASE v_run.state
    WHEN 'created' THEN p_to_state IN ('preflight','cancelled','deletion_pending')
    WHEN 'preflight' THEN p_to_state IN ('uploading','blocked','failed','cancelled')
    WHEN 'uploading' THEN p_to_state IN ('validating','failed','cancelled')
    WHEN 'validating' THEN p_to_state IN ('processing','blocked','failed','cancelled')
    WHEN 'processing' THEN p_to_state IN ('partial','blocked','ready','failed','cancelled')
    WHEN 'partial' THEN p_to_state IN ('processing','ready','expired','deletion_pending')
    WHEN 'blocked' THEN p_to_state IN ('processing','expired','deletion_pending')
    WHEN 'ready' THEN p_to_state IN ('expired','deletion_pending')
    WHEN 'failed' THEN p_to_state IN ('preflight','deletion_pending')
    WHEN 'cancelled' THEN p_to_state='deletion_pending'
    WHEN 'expired' THEN p_to_state='deletion_pending'
    WHEN 'deletion_pending' THEN p_to_state='deleted'
    ELSE false END;
  IF NOT v_allowed OR ((p_to_state IN ('failed','blocked'))<>(p_error_code IS NOT NULL)) THEN
    RAISE EXCEPTION 'Illegal Exchange assessment transition' USING ERRCODE='BZ319', HINT='{"type":"stateMismatch"}';
  END IF;
  UPDATE exchange_assessment_runs SET state=p_to_state,generation=generation+1,error_code=p_error_code,
    updated_at=statement_timestamp(),completed_at=CASE WHEN p_to_state IN ('ready','failed','cancelled','deleted') THEN statement_timestamp() ELSE completed_at END
  WHERE id=p_run_id RETURNING * INTO v_run;
  PERFORM audit_write(p_actor_id,'exchange.assessment.run.transition','exchange_assessment_run',p_run_id,NULL,to_jsonb(v_run),NULL,NULL,'core');
  PERFORM app_notify('exchange_assessment',jsonb_build_object('event','run.transition','runId',p_run_id,'state',p_to_state)::text);
  RETURN to_jsonb(v_run);
END;
$$;
SELECT apply_worker_ownership('exchange_assessment_run_transition(bigint,bigint,bigint,text,text)'::regprocedure);
