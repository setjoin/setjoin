CREATE OR REPLACE FUNCTION exchange_assessment_project_create(
  p_actor_id bigint, p_domain_id bigint, p_name text,
  p_retention_until timestamptz DEFAULT NULL
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_project exchange_assessment_projects%ROWTYPE;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.exchange_replacement_assessment'),false) THEN
    RAISE EXCEPTION 'Exchange assessment is disabled' USING ERRCODE='BZ319', HINT='{"type":"stateMismatch"}';
  END IF;
  IF p_name IS NULL OR p_name<>btrim(p_name) OR octet_length(p_name) NOT BETWEEN 1 AND 128
     OR p_retention_until IS NOT NULL AND p_retention_until<=statement_timestamp() THEN
    RAISE EXCEPTION 'Invalid Exchange assessment project' USING ERRCODE='BZ316', HINT='{"type":"invalidArguments"}';
  END IF;
  IF NOT exchange_assessment_domain_authorized(p_actor_id,p_domain_id,'exchange.assessment.run') THEN
    RAISE EXCEPTION 'Exchange assessment project not found' USING ERRCODE='BZ317', HINT='{"type":"notFound"}';
  END IF;
  INSERT INTO exchange_assessment_projects(domain_id,name,retention_until,created_by)
  VALUES(p_domain_id,p_name,p_retention_until,p_actor_id) RETURNING * INTO v_project;
  PERFORM audit_write(p_actor_id,'exchange.assessment.project.create','exchange_assessment_project',v_project.id,
    NULL,to_jsonb(v_project),NULL,NULL,'core');
  PERFORM app_notify('exchange_assessment',jsonb_build_object('event','project.created','projectId',v_project.id)::text);
  RETURN to_jsonb(v_project);
END;
$$;
SELECT apply_worker_ownership('exchange_assessment_project_create(bigint,bigint,text,timestamptz)'::regprocedure);
