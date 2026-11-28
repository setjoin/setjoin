CREATE OR REPLACE FUNCTION exchange_assessment_run_create(
  p_actor_id bigint, p_project_id bigint, p_support_cell_id text,
  p_support_cell_digest text, p_registry_version integer,
  p_registry_digest text, p_catalog_version integer, p_collector_version text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_project exchange_assessment_projects%ROWTYPE; v_run exchange_assessment_runs%ROWTYPE; v_generation bigint;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.exchange_replacement_assessment'),false) THEN
    RAISE EXCEPTION 'Exchange assessment is disabled' USING ERRCODE='BZ319', HINT='{"type":"stateMismatch"}';
  END IF;
  IF p_support_cell_id IS NULL OR octet_length(p_support_cell_id) NOT BETWEEN 1 AND 128
     OR p_support_cell_digest !~ '^[0-9a-f]{64}$' OR p_registry_digest !~ '^[0-9a-f]{64}$'
     OR p_registry_version<1 OR p_catalog_version<1 OR p_collector_version IS NULL
     OR octet_length(p_collector_version) NOT BETWEEN 1 AND 64 THEN
    RAISE EXCEPTION 'Invalid Exchange assessment run' USING ERRCODE='BZ316', HINT='{"type":"invalidArguments"}';
  END IF;
  SELECT p.* INTO v_project FROM exchange_assessment_projects p
  WHERE p.id=p_project_id AND p.state='active'
    AND exchange_assessment_domain_authorized(p_actor_id,p.domain_id,'exchange.assessment.run')
  FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Exchange assessment project not found' USING ERRCODE='BZ317', HINT='{"type":"notFound"}'; END IF;
  IF NOT EXISTS(
    SELECT 1 FROM exchange_registry_snapshots s
    CROSS JOIN LATERAL jsonb_array_elements(s.projection->'supportCells') cell
    WHERE s.registry_version=p_registry_version AND s.source_digest=p_registry_digest
      AND (cell->>'id')=p_support_cell_id AND (cell->>'digest')=p_support_cell_digest
      AND (cell->>'catalogVersion')::integer=p_catalog_version
      AND (cell->>'collectorVersion')=p_collector_version
  ) THEN
    RAISE EXCEPTION 'Registry or support-cell version and digest do not match' USING ERRCODE='BZ316', HINT='{"type":"invalidArguments"}';
  END IF;
  SELECT COALESCE(max(generation),0)+1 INTO v_generation FROM exchange_assessment_runs WHERE project_id=p_project_id;
  INSERT INTO exchange_assessment_runs(project_id,generation,support_cell_id,support_cell_digest,
    registry_version,registry_digest,catalog_version,collector_version,created_by)
  VALUES(p_project_id,v_generation,p_support_cell_id,p_support_cell_digest,p_registry_version,
    p_registry_digest,p_catalog_version,p_collector_version,p_actor_id) RETURNING * INTO v_run;
  PERFORM audit_write(p_actor_id,'exchange.assessment.run.create','exchange_assessment_run',v_run.id,NULL,to_jsonb(v_run),NULL,NULL,'core');
  PERFORM app_notify('exchange_assessment',jsonb_build_object('event','run.created','projectId',p_project_id,'runId',v_run.id)::text);
  RETURN to_jsonb(v_run);
END;
$$;
SELECT apply_worker_ownership('exchange_assessment_run_create(bigint,bigint,text,text,integer,text,integer,text)'::regprocedure);
