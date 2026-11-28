CREATE OR REPLACE FUNCTION exchange_assessment_decision_set(
  p_actor_id bigint, p_run_id bigint, p_expected_generation bigint,
  p_capability_id text, p_outcome_mapping text, p_decision text,
  p_reason text, p_waiver_expires_at timestamptz DEFAULT NULL
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_run exchange_assessment_runs%ROWTYPE; v_row exchange_assessment_decisions%ROWTYPE;
BEGIN
  SELECT r.* INTO v_run FROM exchange_assessment_runs r
  JOIN exchange_assessment_projects p ON p.id=r.project_id
  WHERE r.id=p_run_id AND exchange_assessment_domain_authorized(p_actor_id,p.domain_id,'exchange.assessment.decide')
  FOR UPDATE OF r;
  IF NOT FOUND THEN RAISE EXCEPTION 'Exchange assessment run not found' USING ERRCODE='BZ317'; END IF;
  IF v_run.generation<>p_expected_generation THEN RAISE EXCEPTION 'Exchange assessment generation is stale' USING ERRCODE='BZ318'; END IF;
  IF v_run.state NOT IN ('partial','blocked','ready') OR p_capability_id IS NULL
     OR p_outcome_mapping NOT IN ('native','transformed','alternative','none')
     OR p_decision NOT IN ('pending','accepted','rejected','waived')
     OR (p_decision IN ('accepted','rejected','waived') AND (p_reason IS NULL OR octet_length(btrim(p_reason)) NOT BETWEEN 1 AND 2048))
     OR ((p_decision='waived')<>(p_waiver_expires_at IS NOT NULL)) THEN
    RAISE EXCEPTION 'Invalid Exchange assessment decision' USING ERRCODE='BZ316';
  END IF;
  INSERT INTO exchange_assessment_decisions(run_id,capability_id,outcome_mapping,decision,reason,waiver_expires_at,actor_id)
  VALUES(p_run_id,p_capability_id,p_outcome_mapping,p_decision,btrim(p_reason),p_waiver_expires_at,p_actor_id)
  ON CONFLICT(run_id,capability_id) DO UPDATE SET outcome_mapping=excluded.outcome_mapping,decision=excluded.decision,
    reason=excluded.reason,waiver_expires_at=excluded.waiver_expires_at,actor_id=excluded.actor_id,decided_at=statement_timestamp()
  RETURNING * INTO v_row;
  UPDATE exchange_assessment_runs SET generation=generation+1,updated_at=statement_timestamp() WHERE id=p_run_id;
  UPDATE exchange_assessment_claim_snapshots SET invalidated_at=statement_timestamp(),invalidation_reason='decision_changed'
    WHERE run_id=p_run_id AND invalidated_at IS NULL;
  PERFORM audit_write(p_actor_id,'exchange.assessment.decision.set','exchange_assessment_run',p_run_id,NULL,to_jsonb(v_row),NULL,p_reason,'core');
  PERFORM app_notify('exchange_assessment',jsonb_build_object('event','decision.set','runId',p_run_id,'capabilityId',p_capability_id)::text);
  RETURN to_jsonb(v_row);
END;
$$;
SELECT apply_worker_ownership('exchange_assessment_decision_set(bigint,bigint,bigint,text,text,text,text,timestamptz)'::regprocedure);
