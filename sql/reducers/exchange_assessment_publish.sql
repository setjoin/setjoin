CREATE OR REPLACE FUNCTION exchange_assessment_publish(
  p_actor_id bigint, p_run_id bigint, p_projection_digest text, p_receipt_artifact_id bigint
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_run exchange_assessment_runs%ROWTYPE; v_snapshot exchange_assessment_claim_snapshots%ROWTYPE; v_row exchange_assessment_publications%ROWTYPE;
BEGIN
  SELECT r.* INTO v_run FROM exchange_assessment_runs r JOIN exchange_assessment_projects p ON p.id=r.project_id
  WHERE r.id=p_run_id AND exchange_assessment_domain_authorized(p_actor_id,p.domain_id,'exchange.assessment.publish') FOR UPDATE OF r;
  IF NOT FOUND THEN RAISE EXCEPTION 'Exchange assessment run not found' USING ERRCODE='BZ317'; END IF;
  SELECT * INTO v_snapshot FROM exchange_assessment_claim_snapshots WHERE run_id=p_run_id AND projection_digest=p_projection_digest AND invalidated_at IS NULL;
  IF NOT FOUND OR v_snapshot.run_generation<>v_run.generation OR v_run.state<>'ready'
     OR v_snapshot.projection->>'supportCellStale'='true'
     OR EXISTS(SELECT 1 FROM jsonb_array_elements(v_snapshot.projection->'rows') r WHERE r->>'claimState' IN ('unassessed','stale')) THEN
    RAISE EXCEPTION 'Exchange assessment publication evidence is incomplete' USING ERRCODE='BZ320',HINT='{"type":"evidenceIncomplete"}';
  END IF;
  IF EXISTS(SELECT 1 FROM exchange_assessment_decisions d WHERE d.run_id=p_run_id AND d.actor_id=p_actor_id AND d.decision='waived') THEN
    RAISE EXCEPTION 'Waiver decider cannot publish the dependent claim' USING ERRCODE='BZ320',HINT='{"type":"separation_of_duties"}';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM exchange_assessment_artifacts a WHERE a.id=p_receipt_artifact_id AND a.run_id=p_run_id AND a.kind='receipt') THEN
    RAISE EXCEPTION 'Publication receipt artifact not found' USING ERRCODE='BZ317';
  END IF;
  INSERT INTO exchange_assessment_publications(run_id,projection_digest,receipt_artifact_id,published_by)
  VALUES(p_run_id,p_projection_digest,p_receipt_artifact_id,p_actor_id)
  ON CONFLICT(run_id,projection_digest) DO UPDATE SET revoked_at=NULL RETURNING * INTO v_row;
  PERFORM audit_write(p_actor_id,'exchange.assessment.publish','exchange_assessment_run',p_run_id,NULL,to_jsonb(v_row),NULL,NULL,'core');
  PERFORM app_notify('exchange_assessment',jsonb_build_object('event','publication.created','runId',p_run_id)::text);
  RETURN to_jsonb(v_row);
END;
$$;
SELECT apply_worker_ownership('exchange_assessment_publish(bigint,bigint,text,bigint)'::regprocedure);
