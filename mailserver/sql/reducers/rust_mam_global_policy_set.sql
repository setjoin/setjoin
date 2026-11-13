-- Frozen Go MAMHandler.SetGlobalPolicy's data transaction. NULL device ids
-- deliberately retain PostgreSQL's NULL-distinct unique semantics: repeated
-- writes insert another global row. The checked notify is a later transaction.
CREATE OR REPLACE FUNCTION rust_mam_global_policy_set(p_policies jsonb)
RETURNS bigint LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_key text; v_value text; v_count bigint;
BEGIN
 FOR v_key, v_value IN SELECT key,value FROM jsonb_each_text(COALESCE(p_policies,'{}'::jsonb)) LOOP
  INSERT INTO device_policy(device_id,policy_key,policy_value,updated_at)
  VALUES(NULL,v_key,v_value,now())
  ON CONFLICT(device_id,policy_key) DO UPDATE SET policy_value=EXCLUDED.policy_value,updated_at=now();
 END LOOP;
 SELECT count(*) INTO v_count FROM device_policy WHERE device_id IS NULL;
 RETURN v_count;
END;
$$;
