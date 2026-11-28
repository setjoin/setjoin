CREATE OR REPLACE FUNCTION office_app_operation_advance(
  p_operation_id uuid,
  p_expected_generation bigint,
  p_executor_id text,
  p_lease_id uuid,
  p_next_state text,
  p_phase text,
  p_progress jsonb,
  p_error jsonb DEFAULT NULL
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE
  v_op office_app_operations%ROWTYPE;
  v_allowed boolean:=false;
  v_generation bigint;
BEGIN
  IF p_operation_id IS NULL OR COALESCE(p_expected_generation,0)<=0
     OR p_executor_id IS NULL OR p_executor_id !~ '^[A-Za-z0-9._:-]{1,128}$'
     OR p_lease_id IS NULL OR NULLIF(btrim(p_phase),'') IS NULL
     OR octet_length(p_phase)>64 OR p_progress IS NULL
     OR jsonb_typeof(p_progress)<>'object' OR octet_length(p_progress::text)>65536
     OR (p_error IS NOT NULL AND (jsonb_typeof(p_error)<>'object' OR octet_length(p_error::text)>65536)) THEN
    RAISE EXCEPTION 'invalid managed Office progress' USING ERRCODE='BZ322';
  END IF;
  SELECT * INTO v_op FROM public.office_app_operations WHERE id=p_operation_id FOR UPDATE;
  IF NOT FOUND OR v_op.state_generation<>p_expected_generation
     OR v_op.executor_id<>p_executor_id OR v_op.lease_id<>p_lease_id
     OR v_op.lease_expires_at<=statement_timestamp() THEN
    RAISE EXCEPTION 'managed Office operation lease or generation changed' USING ERRCODE='BZ324';
  END IF;
  v_allowed:=CASE v_op.state
    WHEN 'claimed' THEN p_next_state IN ('preflight','paused_recoverable','failed_terminal')
    WHEN 'preflight' THEN p_next_state IN ('pulling','disabling_launches','cancelled','failed_terminal')
    WHEN 'pulling' THEN p_next_state IN ('verifying','paused_recoverable','failed_terminal')
    WHEN 'verifying' THEN p_next_state IN ('staging','failed_terminal')
    WHEN 'staging' THEN p_next_state IN ('starting','rolling_back','failed_terminal')
    WHEN 'starting' THEN p_next_state IN ('qualifying','rolling_back','failed_terminal')
    WHEN 'qualifying' THEN p_next_state IN ('connected_inactive','rolling_back','failed_terminal')
    WHEN 'disabling_launches' THEN p_next_state IN ('draining','rolling_back','failed_terminal')
    WHEN 'draining' THEN p_next_state IN ('retention_pending','rolling_back','blocked_drain','failed_terminal')
    WHEN 'blocked_drain' THEN p_next_state IN ('draining','rolled_back')
    WHEN 'rolling_back' THEN p_next_state IN ('rolled_back','failed_terminal')
    WHEN 'paused_recoverable' THEN p_next_state IN ('preflight','failed_terminal')
    ELSE false END;
  IF NOT v_allowed THEN
    RAISE EXCEPTION 'illegal managed Office operation transition' USING ERRCODE='BZ324';
  END IF;
  UPDATE public.office_app_operations
     SET state=p_next_state,state_generation=state_generation+1,phase=p_phase,
         progress=p_progress,error=p_error,updated_at=statement_timestamp(),
         completed_at=CASE WHEN p_next_state IN (
           'connected_inactive','rolled_back','retention_pending','removed',
           'failed_terminal','cancelled')
           THEN statement_timestamp() ELSE NULL END
   WHERE id=p_operation_id RETURNING state_generation INTO v_generation;
  PERFORM public.app_notify('office_app_operation_changed',json_build_object(
    'operation_id',p_operation_id,'state',p_next_state,'generation',v_generation)::text);
  RETURN jsonb_build_object('operationId',p_operation_id::text,'state',p_next_state,
    'stateGeneration',v_generation,'phase',p_phase,'progress',p_progress,'error',p_error);
END;
$$;
SELECT apply_worker_ownership('office_app_operation_advance(uuid,bigint,text,uuid,text,text,jsonb,jsonb)'::regprocedure);
