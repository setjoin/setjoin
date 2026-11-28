-- Frozen Go MAMHandler.SetGroupPolicy's data transaction; no audit or notify.
-- Group/global policy configuration is organization-wide under mam.write.
CREATE OR REPLACE FUNCTION rust_mam_group_policy_set(p_group_type text,p_group_id bigint,p_policies jsonb)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_key text; v_value text;
BEGIN
 FOR v_key, v_value IN SELECT key,value FROM jsonb_each_text(COALESCE(p_policies,'{}'::jsonb)) LOOP
  INSERT INTO device_policy_groups(policy_key,policy_value,group_type,group_id,updated_at)
  VALUES(v_key,v_value,p_group_type,p_group_id,now())
  ON CONFLICT(policy_key,group_type,group_id) DO UPDATE SET policy_value=EXCLUDED.policy_value,updated_at=now();
 END LOOP;
 RETURN true;
END;
$$;
