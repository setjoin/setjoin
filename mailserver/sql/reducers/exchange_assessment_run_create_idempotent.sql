CREATE OR REPLACE FUNCTION exchange_assessment_run_create_idempotent(
  p_actor_id bigint,p_idempotency_key uuid,p_payload_sha256 text,p_project_id bigint,
  p_support_cell_id text,p_support_cell_digest text,p_registry_version integer,
  p_registry_digest text,p_catalog_version integer,p_collector_version text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_existing exchange_assessment_idempotency%ROWTYPE; v_result jsonb;
BEGIN
  IF p_idempotency_key IS NULL OR p_payload_sha256 !~ '^[0-9a-f]{64}$' THEN RAISE EXCEPTION 'Invalid idempotency contract' USING ERRCODE='BZ316'; END IF;
  SELECT * INTO v_existing FROM exchange_assessment_idempotency WHERE idempotency_key=p_idempotency_key FOR UPDATE;
  IF FOUND THEN
    IF v_existing.actor_id=p_actor_id AND v_existing.operation='run.create' AND v_existing.payload_sha256=p_payload_sha256 THEN RETURN v_existing.result||'{"replayed":true}'::jsonb; END IF;
    RAISE EXCEPTION 'Conflicting idempotency replay' USING ERRCODE='BZ319';
  END IF;
  v_result:=exchange_assessment_run_create(p_actor_id,p_project_id,p_support_cell_id,p_support_cell_digest,p_registry_version,p_registry_digest,p_catalog_version,p_collector_version);
  INSERT INTO exchange_assessment_idempotency(idempotency_key,actor_id,operation,payload_sha256,result) VALUES(p_idempotency_key,p_actor_id,'run.create',p_payload_sha256,v_result);
  RETURN v_result;
END;
$$;
