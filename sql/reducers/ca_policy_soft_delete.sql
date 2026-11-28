-- ca_policy_soft_delete.sql — CA-1 C3: soft-delete a conditional-access policy.
-- Sets deleted_at = now() (removing it from the partial-unique priority index
-- WHERE state='on' AND deleted_at IS NULL) so the priority slot is freed for
-- other live policies. Captures before_state, writes admin_audit_log in-txn,
-- PERFORMs ca_notify_policy_change (F2 choke point). Hard-delete stays ca_policy_delete.
-- VOLATILE.

CREATE OR REPLACE FUNCTION ca_policy_soft_delete(
    p_id       BIGINT,
    p_admin_id BIGINT
) RETURNS VOID AS $$
DECLARE
    v_before JSONB;
BEGIN
    SELECT to_jsonb(c) - 'enabled' INTO v_before
      FROM conditional_access_policies c WHERE id = p_id;
    IF v_before IS NULL THEN
        RAISE EXCEPTION 'policy not found' USING ERRCODE = 'BZ081',
            HINT = 'no conditional_access_policy row with the given id';
    END IF;

    UPDATE conditional_access_policies
       SET deleted_at = now(), updated_at = now()
     WHERE id = p_id;

    PERFORM audit_write(p_admin_id, 'ca_policy_soft_delete', 'conditional_access_policy', p_id, v_before, NULL, NULL, NULL, 'core');

    -- F2: CA-F choke point — not a bespoke app_notify call.
    PERFORM ca_notify_policy_change('ca_policy_soft_delete');
END;
$$ LANGUAGE plpgsql VOLATILE;
