-- Frozen Go's admin create/update of a conditional-access policy
-- (admin.ConditionalAccessHandler.Create and Update) as one reducer. Go opens a
-- transaction, calls ca_policy_upsert, then, when the request carried a session_control
-- value, set_session_control for the same policy (a BZ098 there rolls the upsert back), and
-- commits. The two existing reducers keep their own audit rows and the single
-- ca_notify_policy_change each; this wrapper only fixes their order and atomicity.
--
-- p_session_control is SQL NULL when the request omitted the field and a jsonb value
-- (jsonb null included, as Go's json.RawMessage keeps a literal null) when it was present.
-- p_actions is the request's actions document or the {"action":"allow"} default Go sends.
-- Create (p_id NULL) only validates session_control when the new id is positive, as Go.
-- Returns the persisted policy row jsonb that ca_policy_upsert returned.
CREATE OR REPLACE FUNCTION rust_ca_policy_save(
    p_actor           bigint,
    p_ip              inet,
    p_id              bigint,
    p_policy          jsonb,
    p_actions         jsonb,
    p_session_control jsonb
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE
    v_out jsonb;
    v_id  bigint;
BEGIN
    v_out := ca_policy_upsert(p_actor, p_ip, p_id, p_policy);
    IF p_session_control IS NOT NULL THEN
        v_id := COALESCE(p_id, (v_out->>'id')::bigint);
        IF v_id IS NOT NULL AND v_id > 0 THEN
            PERFORM set_session_control(v_id, p_actions, p_session_control, p_actor, p_ip);
        END IF;
    END IF;
    RETURN v_out;
END;
$$;
