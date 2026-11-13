-- ca_policy_delete.sql — CA-0a admin HARD delete of a conditional-access policy.
-- (Soft-delete/restore is CA-1.) Captures before_state, deletes, writes the
-- admin_audit_log row in-txn, PERFORMs ca_notify_policy_change (F2 choke point). VOLATILE.

CREATE OR REPLACE FUNCTION ca_policy_delete(
    p_actor BIGINT,
    p_ip    INET,
    p_id    BIGINT
) RETURNS VOID AS $$
DECLARE
    v_before JSONB;
BEGIN
    SELECT to_jsonb(c) - 'enabled' INTO v_before
      FROM conditional_access_policies c WHERE id = p_id;
    IF v_before IS NULL THEN
        RAISE EXCEPTION 'policy not found' USING ERRCODE = 'BZ081', HINT = 'no conditional_access_policy row with the given id';
    END IF;

    DELETE FROM conditional_access_policies WHERE id = p_id;

    PERFORM audit_write(p_actor, 'ca_policy_delete', 'conditional_access_policy', p_id, v_before, NULL, p_ip, NULL, 'core');

    -- F2: CA-F choke point — not a bespoke app_notify.
    PERFORM ca_notify_policy_change('ca_policy_delete');
END;
$$ LANGUAGE plpgsql VOLATILE;
