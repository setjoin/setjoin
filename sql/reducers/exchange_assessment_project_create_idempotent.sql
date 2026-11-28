CREATE OR REPLACE FUNCTION exchange_assessment_project_create_idempotent(
  p_actor_id bigint,p_idempotency_key uuid,p_payload_sha256 text,
  p_domain_id bigint,p_name text,p_retention_until timestamptz
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_existing exchange_assessment_idempotency%ROWTYPE; v_result jsonb;
BEGIN
  IF p_idempotency_key IS NULL OR p_payload_sha256 !~ '^[0-9a-f]{64}$' THEN RAISE EXCEPTION 'Invalid idempotency contract' USING ERRCODE='BZ316'; END IF;
  SELECT * INTO v_existing FROM exchange_assessment_idempotency WHERE idempotency_key=p_idempotency_key FOR UPDATE;
  IF FOUND THEN
    IF v_existing.actor_id=p_actor_id AND v_existing.operation='project.create' AND v_existing.payload_sha256=p_payload_sha256 THEN RETURN v_existing.result||'{"replayed":true}'::jsonb; END IF;
    RAISE EXCEPTION 'Conflicting idempotency replay' USING ERRCODE='BZ319';
  END IF;
  v_result:=exchange_assessment_project_create(p_actor_id,p_domain_id,p_name,p_retention_until);
  INSERT INTO exchange_assessment_idempotency(idempotency_key,actor_id,operation,payload_sha256,result) VALUES(p_idempotency_key,p_actor_id,'project.create',p_payload_sha256,v_result);
  RETURN v_result;
END;
$$;
