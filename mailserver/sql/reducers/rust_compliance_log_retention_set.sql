-- Frozen-Go SetLogRetention: four ordered config upserts in one transaction.
-- Config triggers own config_changed notifications. No audit is added.
CREATE OR REPLACE FUNCTION rust_compliance_log_retention_set(p_actor bigint,p_values bigint[])
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_keys text[]:=ARRAY['message_trace','mailbox_audit','auth_event','webhook_delivery'];v_i integer;
BEGIN
 FOR v_i IN 1..4 LOOP
  INSERT INTO system_config(key,value,updated_at)
  SELECT 'log_retention_'||v_keys[v_i]||'_days',to_jsonb(GREATEST(COALESCE(p_values[v_i],0),0)),now()
  WHERE p_actor>0
  ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_at=now() WHERE p_actor>0;
 END LOOP;
END;
$$;
