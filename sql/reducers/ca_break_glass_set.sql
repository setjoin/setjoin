-- ca_break_glass_set.sql — CA-0a: sets system_config.ca_break_glass_user_ids.
-- Validates the input array is non-empty (at least one break-glass admin must
-- remain reachable after the write). Captures the before/after states in
-- admin_audit_log (in-txn), then PERFORMs ca_notify_policy_change (F2 choke point)
-- so both servers' policy-engine break-glass snapshots refresh. VOLATILE.
--
-- BZ082: empty/NULL p_ids → 400 Bad Request (caErrorStatus maps BZ082 → 400).

CREATE OR REPLACE FUNCTION ca_break_glass_set(
    p_actor   BIGINT,
    p_ip      INET,
    p_ids     BIGINT[]
) RETURNS VOID AS $$
DECLARE
    v_before JSONB;
    v_after  JSONB;
BEGIN
    PERFORM admin_authority_fence();

    -- Require at least one break-glass admin (empty array defeats the purpose).
    IF p_ids IS NULL OR cardinality(p_ids) = 0 THEN
        RAISE EXCEPTION 'ca_break_glass_set requires at least one user id'
            USING ERRCODE = 'BZ082',
                  HINT = 'pass a non-empty array of admin user IDs; an empty break-glass set would lock out all administrators';
    END IF;

    -- Capture before state (NULL if not yet set).
    SELECT value INTO v_before FROM system_config WHERE key = 'ca_break_glass_user_ids';

    v_after := to_jsonb(p_ids);

    -- Upsert the break-glass set into system_config.
    INSERT INTO system_config (key, value, updated_by)
        VALUES ('ca_break_glass_user_ids', v_after, p_actor)
        ON CONFLICT (key) DO UPDATE
            SET value = EXCLUDED.value,
                updated_by = EXCLUDED.updated_by,
                updated_at = now();

    -- Append an audit row (in-txn; before_state NULL on first set).
    PERFORM audit_write(p_actor, 'ca_break_glass_set', 'system_config', NULL, v_before, v_after, p_ip, NULL, 'core');

    -- F2: CA-F choke point — so both servers refresh their break-glass snapshot.
    PERFORM ca_notify_policy_change('break_glass_set');
END;
$$ LANGUAGE plpgsql VOLATILE;
