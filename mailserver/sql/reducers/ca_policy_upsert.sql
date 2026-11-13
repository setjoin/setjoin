-- ca_policy_upsert.sql — CA-0a admin create/update of a conditional-access policy.
--
-- Calls ca_lockout_guard (RAISE BZ080), INSERT-or-UPDATE writing `state` ONLY
-- (never `enabled` — the ca_sync_enabled BEFORE trigger owns it; a direct enabled
-- write would be silently discarded, V026 L2), writes the admin_audit_log
-- before/after row IN THE SAME TXN, and PERFORMs ca_notify_policy_change(reason)
-- per CA-F §F2's channel contract (do NOT call app_notify directly — the choke
-- point is ca_notify_policy_change so both servers' LISTEN consumers receive exactly
-- one fixed-channel notification). Returns the persisted row as jsonb.
--
-- p_id IS NULL → create. The state/scope_type/array/doc-valid CHECKs (V026) reject
-- bad enums at the row layer (handler also calls ValidatePolicyDocument first → 400). VOLATILE.

CREATE OR REPLACE FUNCTION ca_policy_upsert(
    p_actor  BIGINT,
    p_ip     INET,
    p_id     BIGINT,
    p_policy JSONB
) RETURNS JSONB AS $$
DECLARE
    v_id       BIGINT := p_id;
    v_before   JSONB;
    v_after    JSONB;
    v_priority INT;
    v_action   TEXT;
BEGIN
    -- Lockout floor (logic-where-the-data-is).
    PERFORM ca_lockout_guard(
        p_policy->>'state',
        COALESCE(p_policy->>'scope_type', 'global'),
        COALESCE(p_policy->'actions', '{"action":"allow"}'::jsonb),
        COALESCE(p_policy->'exclude_users', '[]'::jsonb),
        COALESCE(p_policy->'exclude_groups', '[]'::jsonb)
    );

    IF v_id IS NULL THEN
        -- Auto-assign priority unless supplied.
        v_priority := COALESCE(
            (p_policy->>'priority')::int,
            (SELECT COALESCE(MAX(priority), 0) + 10 FROM conditional_access_policies));

        INSERT INTO conditional_access_policies
            (priority, name, description, state, scope_type, scope_target,
             conditions, actions, exclude_users, exclude_groups)
        VALUES (
            v_priority,
            p_policy->>'name',
            COALESCE(p_policy->>'description', ''),
            p_policy->>'state',
            COALESCE(p_policy->>'scope_type', 'global'),
            COALESCE(p_policy->>'scope_target', ''),
            COALESCE(p_policy->'conditions', '{}'::jsonb),
            COALESCE(p_policy->'actions', '{"action":"allow"}'::jsonb),
            COALESCE(p_policy->'exclude_users', '[]'::jsonb),
            COALESCE(p_policy->'exclude_groups', '[]'::jsonb)
        )
        RETURNING id INTO v_id;
        v_action := 'ca_policy_create';
    ELSE
        SELECT to_jsonb(c) - 'enabled' INTO v_before
          FROM conditional_access_policies c WHERE id = v_id;
        IF v_before IS NULL THEN
            RAISE EXCEPTION 'policy not found' USING ERRCODE = 'BZ081', HINT = 'no conditional_access_policy row with the given id';
        END IF;

        UPDATE conditional_access_policies SET
            priority      = COALESCE((p_policy->>'priority')::int, priority),
            name          = p_policy->>'name',
            description   = COALESCE(p_policy->>'description', description),
            state         = p_policy->>'state',                       -- state ONLY
            scope_type    = COALESCE(p_policy->>'scope_type', scope_type),
            scope_target  = COALESCE(p_policy->>'scope_target', scope_target),
            conditions    = COALESCE(p_policy->'conditions', conditions),
            actions       = COALESCE(p_policy->'actions', actions),
            exclude_users = COALESCE(p_policy->'exclude_users', exclude_users),
            exclude_groups= COALESCE(p_policy->'exclude_groups', exclude_groups),
            updated_at    = now()
        WHERE id = v_id;
        v_action := 'ca_policy_update';
    END IF;

    -- after_state: the row as written, WITHOUT enabled (trigger-derived, not authored).
    SELECT to_jsonb(c) - 'enabled' INTO v_after
      FROM conditional_access_policies c WHERE id = v_id;

    PERFORM audit_write(p_actor, v_action, 'conditional_access_policy', v_id, v_before, v_after, p_ip, NULL, 'core');

    -- F2: use the CA-F choke point, not a bespoke app_notify call, so both servers'
    -- LISTEN conditional_access consumers see exactly one fixed-channel notification.
    PERFORM ca_notify_policy_change(v_action);

    RETURN v_after;
END;
$$ LANGUAGE plpgsql VOLATILE;
