-- audit_write.sql — the ONLY path that inserts into admin_audit_log. Both Go (via
-- internal/audit wrapper) and reducers call it. Level gate: core always; routine
-- only at level='full'. The v2 trigger chains the row.
CREATE OR REPLACE FUNCTION audit_write(
  p_actor bigint, p_action text, p_target_type text, p_target_id bigint,
  p_before jsonb, p_after jsonb, p_ip inet, p_notes text, p_tier text
) RETURNS void AS $$
DECLARE v_level text;
BEGIN
  IF p_tier NOT IN ('core','routine') THEN
    RAISE EXCEPTION 'audit_write: bad tier %', p_tier USING ERRCODE='BZ067';
  END IF;
  IF p_tier = 'routine' THEN
    SELECT level INTO v_level FROM audit_policy WHERE id = 1;
    IF v_level <> 'full' THEN RETURN; END IF;   -- suppressed at lean
  END IF;
  INSERT INTO admin_audit_log (user_id, ip, action, target_type, target_id, before_state, after_state, notes)
    VALUES (p_actor, p_ip, p_action, p_target_type, p_target_id, p_before, p_after, p_notes);
END;
$$ LANGUAGE plpgsql VOLATILE;
