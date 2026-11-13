-- Frozen Go SetPerDevicePolicy transaction 1. Evidence and notify each occur
-- in later transactions, preserving Go's partial-success failure behavior.
CREATE OR REPLACE FUNCTION rust_mam_device_policy_set(p_device_id bigint,p_domain_scope bigint,p_policies jsonb)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_key text; v_value text; v_count bigint;
BEGIN
 FOR v_key,v_value IN SELECT key,value FROM jsonb_each_text(COALESCE(p_policies,'{}'::jsonb)) LOOP
  IF p_domain_scope > 0 THEN
   INSERT INTO device_policy(device_id,policy_key,policy_value,updated_at)
   SELECT dev.id,v_key,v_value,now() FROM devices dev JOIN users u ON u.id=dev.user_id
   WHERE dev.id=p_device_id AND u.domain_id=p_domain_scope
   ON CONFLICT(device_id,policy_key) DO UPDATE SET policy_value=EXCLUDED.policy_value,updated_at=now();
   GET DIAGNOSTICS v_count=ROW_COUNT;
   IF v_count=0 THEN
    RAISE EXCEPTION 'Device not found' USING ERRCODE='BZ081',HINT='{"type":"not_found"}';
   END IF;
  ELSE
   INSERT INTO device_policy(device_id,policy_key,policy_value,updated_at)
   VALUES(p_device_id,v_key,v_value,now())
   ON CONFLICT(device_id,policy_key) DO UPDATE SET policy_value=EXCLUDED.policy_value,updated_at=now();
  END IF;
 END LOOP;
 RETURN true;
END;
$$;
