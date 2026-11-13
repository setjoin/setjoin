CREATE OR REPLACE FUNCTION exchange_assessment_probe_put(
  p_run_id bigint, p_fencing_token bigint, p_root_id text, p_probe_id text,
  p_capability_id text, p_stable_instance_id text, p_terminal_state text,
  p_diagnostic_id text, p_facts jsonb, p_observed_at timestamptz
) RETURNS jsonb LANGUAGE plpgsql VOLATILE
SET search_path=pg_catalog,public AS $$
DECLARE v_result exchange_assessment_probe_results%ROWTYPE; v_existing exchange_assessment_probe_results%ROWTYPE;
BEGIN
  IF p_root_id IS NULL OR p_probe_id IS NULL OR p_capability_id IS NULL OR p_stable_instance_id IS NULL
     OR p_terminal_state NOT IN ('collected','unknown_value','permission_denied','collection_failed','unsupported_source','not_applicable')
     OR p_facts IS NULL OR jsonb_typeof(p_facts)<>'object' OR octet_length(p_facts::text)>1048576
     OR p_observed_at IS NULL THEN
    RAISE EXCEPTION 'Invalid Exchange assessment probe result' USING ERRCODE='BZ316', HINT='{"type":"invalidArguments"}';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM exchange_assessment_leases WHERE run_id=p_run_id AND fencing_token=p_fencing_token AND expires_at>statement_timestamp()) THEN
    RAISE EXCEPTION 'Exchange assessment fencing token is stale' USING ERRCODE='BZ318', HINT='{"type":"stateMismatch"}';
  END IF;
  SELECT * INTO v_existing FROM exchange_assessment_probe_results
  WHERE run_id=p_run_id AND probe_id=p_probe_id AND stable_instance_id=p_stable_instance_id;
  IF FOUND THEN
    IF v_existing.root_id=p_root_id AND v_existing.capability_id=p_capability_id
       AND v_existing.terminal_state=p_terminal_state AND v_existing.facts=p_facts
       AND v_existing.diagnostic_id IS NOT DISTINCT FROM p_diagnostic_id THEN
      RETURN to_jsonb(v_existing)||'{"replayed":true}'::jsonb;
    END IF;
    RAISE EXCEPTION 'Conflicting Exchange assessment probe replay' USING ERRCODE='BZ319', HINT='{"type":"stateMismatch"}';
  END IF;
  INSERT INTO exchange_assessment_probe_results(run_id,root_id,probe_id,capability_id,stable_instance_id,
    terminal_state,diagnostic_id,facts,observed_at)
  VALUES(p_run_id,p_root_id,p_probe_id,p_capability_id,p_stable_instance_id,p_terminal_state,p_diagnostic_id,p_facts,p_observed_at)
  RETURNING * INTO v_result;
  UPDATE exchange_assessment_runs SET updated_at=statement_timestamp() WHERE id=p_run_id;
  RETURN to_jsonb(v_result);
END;
$$;
