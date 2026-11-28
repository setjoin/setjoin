-- Frozen Go's MDMHandler.DeletePolicy: the enabled-global count and the target's
-- scope as best-effort probes, the last-global refusal, then the DELETE, as one
-- transaction (the caller's actor GUC admits the Posture C arms). Returns
-- {status}: 200 deleted, 409 last global policy, 404 no such policy. No audit
-- row and no notify, as in Go.
CREATE OR REPLACE FUNCTION rust_mdm_policy_delete(p_id bigint)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE
 v_n bigint;
 v_scope text;
BEGIN
 SELECT COUNT(*) INTO v_n FROM mdm_policies WHERE scope_type = 'global' AND enabled;
 SELECT scope_type INTO v_scope FROM mdm_policies WHERE id = p_id;
 IF v_scope = 'global' AND v_n <= 1 THEN
  RETURN jsonb_build_object('status', 409);
 END IF;
 DELETE FROM mdm_policies WHERE id = p_id;
 IF NOT FOUND THEN
  RETURN jsonb_build_object('status', 404);
 END IF;
 RETURN jsonb_build_object('status', 200);
END;
$$;
