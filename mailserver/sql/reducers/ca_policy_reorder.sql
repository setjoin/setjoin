-- ca_policy_reorder.sql — CA-0a admin reorder. Re-prioritises (stepped by 10 in
-- the supplied order) in one txn; writes ONE summary admin_audit_log row (D4) whose
-- after_state is the ordered id→priority map; PERFORMs ca_notify_policy_change (F2).
-- VOLATILE.

CREATE OR REPLACE FUNCTION ca_policy_reorder(
    p_actor BIGINT,
    p_ip    INET,
    p_ids   BIGINT[]
) RETURNS VOID AS $$
DECLARE
    v_id    BIGINT;
    v_i     INT := 0;
    v_after JSONB := '[]'::jsonb;
BEGIN
    FOREACH v_id IN ARRAY p_ids LOOP
        v_i := v_i + 1;
        UPDATE conditional_access_policies
           SET priority = v_i * 10, updated_at = now()
         WHERE id = v_id;
        v_after := v_after || jsonb_build_object('id', v_id, 'priority', v_i * 10);
    END LOOP;

    PERFORM audit_write(p_actor, 'ca_policy_reorder', 'conditional_access_policy', NULL, NULL, v_after, p_ip, NULL, 'core');

    -- F2: CA-F choke point — not a bespoke app_notify call.
    PERFORM ca_notify_policy_change('ca_policy_reorder');
END;
$$ LANGUAGE plpgsql VOLATILE;
