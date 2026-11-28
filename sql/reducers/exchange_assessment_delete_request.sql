CREATE OR REPLACE FUNCTION exchange_assessment_delete_request(
  p_actor_id bigint, p_project_id bigint, p_scope text, p_run_id bigint,
  p_artifact_id bigint, p_reason text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_row exchange_assessment_deletion_requests%ROWTYPE;
BEGIN
  IF NOT EXISTS(SELECT 1 FROM exchange_assessment_projects p WHERE p.id=p_project_id
    AND exchange_assessment_domain_authorized(p_actor_id,p.domain_id,'exchange.assessment.delete')) THEN
    RAISE EXCEPTION 'Exchange assessment project not found' USING ERRCODE='BZ317';
  END IF;
  IF p_scope NOT IN ('artifact','run','project') OR p_reason IS NULL OR octet_length(btrim(p_reason)) NOT BETWEEN 1 AND 1024
     OR (p_run_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM exchange_assessment_runs r WHERE r.id=p_run_id AND r.project_id=p_project_id))
     OR (p_artifact_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM exchange_assessment_artifacts a WHERE a.id=p_artifact_id AND a.run_id=p_run_id)) THEN
    RAISE EXCEPTION 'Invalid Exchange assessment deletion request' USING ERRCODE='BZ316';
  END IF;
  INSERT INTO exchange_assessment_deletion_requests(project_id,run_id,artifact_id,scope,reason,requested_by)
  VALUES(p_project_id,p_run_id,p_artifact_id,p_scope,btrim(p_reason),p_actor_id) RETURNING * INTO v_row;
  UPDATE exchange_assessment_projects SET state='deletion_pending',updated_at=statement_timestamp() WHERE id=p_project_id AND p_scope='project';
  UPDATE exchange_assessment_runs SET state='deletion_pending',generation=generation+1,updated_at=statement_timestamp() WHERE id=p_run_id AND p_scope='run';
  UPDATE exchange_assessment_artifacts SET disposition='backup_expiry_pending' WHERE id=p_artifact_id AND p_scope='artifact';
  PERFORM audit_write(p_actor_id,'exchange.assessment.delete.request','exchange_assessment_project',p_project_id,NULL,to_jsonb(v_row),NULL,p_reason,'core');
  PERFORM app_notify('exchange_assessment',jsonb_build_object('event','deletion.requested','projectId',p_project_id,'scope',p_scope)::text);
  RETURN to_jsonb(v_row);
END;
$$;
SELECT apply_worker_ownership('exchange_assessment_delete_request(bigint,bigint,text,bigint,bigint,text)'::regprocedure);
