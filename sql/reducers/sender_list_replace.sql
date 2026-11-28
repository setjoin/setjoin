-- Atomic full-list compatibility replacement under generation and replay CAS.

CREATE OR REPLACE FUNCTION sender_list_replace(
  p_user_id bigint,p_operation_id uuid,p_expected_generation bigint,p_request_digest text,
  p_safe text[],p_blocked text[]
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_state sender_control_state%ROWTYPE; v_existing sender_list_operations%ROWTYPE;
  v_safe text[]; v_blocked text[]; v_result jsonb;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.sender_control_center'),false) THEN
    RAISE EXCEPTION 'sender control center is disabled' USING ERRCODE='BZ300';
  END IF;
  IF p_operation_id IS NULL OR p_expected_generation<1 OR p_request_digest!~'^[0-9a-f]{64}$'
     OR cardinality(p_safe)>1000 OR cardinality(p_blocked)>1000 THEN
    RAISE EXCEPTION 'invalid sender-list replacement' USING ERRCODE='BZ301';
  END IF;
  SELECT COALESCE(array_agg(DISTINCT lower(btrim(x)) ORDER BY lower(btrim(x))),'{}') INTO v_safe FROM unnest(COALESCE(p_safe,'{}')) x;
  SELECT COALESCE(array_agg(DISTINCT lower(btrim(x)) ORDER BY lower(btrim(x))),'{}') INTO v_blocked FROM unnest(COALESCE(p_blocked,'{}')) x;
  IF EXISTS(SELECT 1 FROM unnest(v_safe||v_blocked) x WHERE x='' OR octet_length(x)>320 OR x~'[[:cntrl:]]')
     OR v_safe&&v_blocked THEN RAISE EXCEPTION 'invalid sender-list replacement' USING ERRCODE='BZ301'; END IF;
  SELECT * INTO v_existing FROM sender_list_operations WHERE operation_id=p_operation_id;
  IF FOUND THEN
    IF v_existing.user_id=p_user_id AND v_existing.request_digest=p_request_digest THEN RETURN v_existing.result||'{"replayed":true}'::jsonb; END IF;
    RAISE EXCEPTION 'sender-list idempotency conflict' USING ERRCODE='BZ303';
  END IF;
  SELECT * INTO v_state FROM sender_control_state WHERE user_id=p_user_id FOR UPDATE;
  IF NOT FOUND THEN INSERT INTO sender_control_state(user_id) VALUES(p_user_id) RETURNING * INTO v_state; END IF;
  IF v_state.generation<>p_expected_generation THEN RAISE EXCEPTION 'sender control generation is stale' USING ERRCODE='BZ304'; END IF;
  DELETE FROM user_sender_list WHERE user_id=p_user_id;
  INSERT INTO user_sender_list(user_id,sender,list_type) SELECT p_user_id,x,'safe' FROM unnest(v_safe) x;
  INSERT INTO user_sender_list(user_id,sender,list_type) SELECT p_user_id,x,'blocked' FROM unnest(v_blocked) x;
  UPDATE sender_control_state SET generation=generation+1,updated_at=statement_timestamp() WHERE user_id=p_user_id RETURNING * INTO v_state;
  v_result:=sender_list_read(p_user_id)||jsonb_build_object('operationId',p_operation_id,'replayed',false);
  INSERT INTO sender_list_operations(operation_id,user_id,generation,request_digest,result)
    VALUES(p_operation_id,p_user_id,v_state.generation,p_request_digest,v_result);
  PERFORM audit_write(p_user_id,'sender_list_replaced','user',p_user_id,NULL,
    jsonb_build_object('safeCount',cardinality(v_safe),'blockedCount',cardinality(v_blocked),'generation',v_state.generation),NULL,NULL,'core');
  PERFORM app_notify('sender_control',json_build_object('user_id',p_user_id,'generation',v_state.generation)::text);
  RETURN v_result;
END $$;

ALTER FUNCTION sender_list_replace(bigint,uuid,bigint,text,text[],text[]) OWNER TO setjoin_worker;
