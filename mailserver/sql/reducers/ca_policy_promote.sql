-- ca_policy_promote.sql — CA-1 C5: promote a report_only policy to on.
--
-- Flip a report_only conditional-access policy to state=on.
-- Guards against admin lockout via ca_lockout_guard (BZ080) BEFORE the UPDATE.
-- Captures a 7d would-block snapshot from ca_policy_impact, embeds it in
-- the audit after_state. Writes admin_audit_log in-txn, PERFORMs
-- ca_notify_policy_change (F2 choke point). Returns JSONB:
--   {id, state:'on', promoted_from:'report_only', would_block_users}
-- Already-on policy → no-op, returns current shape.
-- VOLATILE.

CREATE OR REPLACE FUNCTION ca_policy_promote(
    p_policy_id BIGINT,
    p_admin_id  BIGINT
) RETURNS JSONB AS $$
DECLARE
    v_before            JSONB;
    v_state             TEXT;
    v_actions           JSONB;
    v_scope             TEXT;
    v_excl_u            JSONB;
    v_excl_g            JSONB;
    v_impact            JSONB;
    v_would_block       BIGINT;
    v_after             JSONB;
BEGIN
    -- Universal CA lock order: reachability advisory fence before the policy
    -- row. The locked tuple below is the exact snapshot passed to the guard.
    PERFORM ca_reachability_fence();

    SELECT to_jsonb(c) - 'enabled', c.state,
           c.actions, c.scope_type, c.exclude_users, c.exclude_groups
      INTO v_before, v_state, v_actions, v_scope, v_excl_u, v_excl_g
      FROM conditional_access_policies c
     WHERE id = p_policy_id AND deleted_at IS NULL
     FOR UPDATE;

    IF v_before IS NULL THEN
        RAISE EXCEPTION 'policy not found' USING ERRCODE = 'BZ081',
            HINT = 'no live conditional_access_policy row with the given id';
    END IF;

    -- Already on: no-op — return current shape without audit/notify.
    -- ponytail: idempotent; handler can safely retry after network blip.
    IF v_state = 'on' THEN
        RETURN jsonb_build_object(
            'id',              p_policy_id,
            'state',           'on',
            'promoted_from',   'report_only',
            'would_block_users', 0
        );
    END IF;

    -- Lockout guard — must run BEFORE the UPDATE so the DB row is still report_only
    -- (guard short-circuits for non-on/non-global/non-block cases — zero cost on safe flips).
    PERFORM ca_lockout_guard(
        'on',                              -- the state we are ABOUT to write
        COALESCE(v_scope, 'global'),
        COALESCE(v_actions, '{"action":"allow"}'::jsonb),
        COALESCE(v_excl_u, '[]'::jsonb),
        COALESCE(v_excl_g, '[]'::jsonb)
    );

    -- 7d impact snapshot (read-only; STABLE so safe inside a write txn).
    v_impact := ca_policy_impact(p_policy_id, '7d', NULL);
    v_would_block := COALESCE((v_impact->>'would_block')::bigint, 0);

    -- ponytail: R3 TOCTOU guard — concurrent soft-delete between SELECT and UPDATE
    -- would otherwise promote a deleted policy past the BZ081 guard above.
    UPDATE conditional_access_policies
       SET state = 'on', updated_at = now()
     WHERE id = p_policy_id
       AND deleted_at IS NULL
       AND state = 'report_only';

    SELECT to_jsonb(c) - 'enabled' INTO v_after
      FROM conditional_access_policies c WHERE id = p_policy_id;

    -- Embed the would-block count as an extra key on after_state for the audit row.
    v_after := v_after || jsonb_build_object('would_block_snapshot', v_would_block);

    PERFORM audit_write(p_admin_id, 'ca_policy_promote', 'conditional_access_policy',
         p_policy_id, v_before, v_after, NULL, NULL, 'core');

    -- F2: CA-F choke point — not a bespoke app_notify call.
    PERFORM ca_notify_policy_change('ca_policy_promote');

    RETURN jsonb_build_object(
        'id',                p_policy_id,
        'state',             'on',
        'promoted_from',     'report_only',
        'would_block_users', v_would_block
    );
END;
$$ LANGUAGE plpgsql VOLATILE;
