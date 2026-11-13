-- ca_policy_restore.sql — CA-1 C3: restore a soft-deleted conditional-access policy.
-- Clears deleted_at. If the policy has state='on' and another live on-policy already
-- holds the same priority, raises BZ087 (caller must reorder or soft-delete the
-- blocker first). Calls ca_lockout_guard before the UPDATE (BZ080 on admin lockout).
-- TOCTOU: a concurrent restore racing to the same priority slot is caught by trapping
-- unique_violation (23505) and re-raising as BZ087 rather than the opaque DB error.
-- Idempotent on already-live rows. Captures before_state, writes
-- admin_audit_log in-txn, PERFORMs ca_notify_policy_change (F2 choke point). VOLATILE.

CREATE OR REPLACE FUNCTION ca_policy_restore(
    p_id       BIGINT,
    p_admin_id BIGINT
) RETURNS VOID AS $$
DECLARE
    v_before   JSONB;
    v_priority INT;
    v_state    TEXT;
    v_actions  JSONB;
    v_excl_u   JSONB;
    v_excl_g   JSONB;
    v_scope    TEXT;
BEGIN
    -- Universal CA lock order: reachability advisory fence before the policy
    -- row. Guard and restore consume this one locked current tuple.
    PERFORM ca_reachability_fence();

    SELECT to_jsonb(c) - 'enabled', c.priority, c.state,
           c.actions, c.exclude_users, c.exclude_groups, c.scope_type
      INTO v_before, v_priority, v_state,
           v_actions, v_excl_u, v_excl_g, v_scope
      FROM conditional_access_policies c WHERE id = p_id
      FOR UPDATE;
    IF v_before IS NULL THEN
        RAISE EXCEPTION 'policy not found' USING ERRCODE = 'BZ081',
            HINT = 'no conditional_access_policy row with the given id';
    END IF;

    -- BZ087: priority clash — another live on policy holds the same slot.
    -- ponytail: check only when state='on'; off/report_only rows are not in the
    -- partial-unique index so they can never clash regardless of deleted_at.
    IF v_state = 'on' AND EXISTS (
        SELECT 1 FROM conditional_access_policies
         WHERE priority = v_priority
           AND state = 'on'
           AND deleted_at IS NULL
           AND id <> p_id
    ) THEN
        RAISE EXCEPTION 'cannot restore policy %: priority % is already held by an active policy', p_id, v_priority
            USING ERRCODE = 'BZ087',
                  HINT = 'change the restored policy''s priority, or soft-delete the conflicting policy first — see docs/reducer-error-codes.md#BZ087';
    END IF;

    -- Admin-lockout guard — must run before UPDATE makes the row live.
    -- ca_lockout_guard short-circuits immediately for non-on/non-global/non-block cases
    -- (see ca_lockout_guard.sql lines 40-43), so this is zero-cost on safe restores.
    PERFORM ca_lockout_guard(
        v_state,
        COALESCE(v_scope, 'global'),
        COALESCE(v_actions, '{"operator":"all","grants":[{"action":"allow"}]}'::jsonb),
        COALESCE(v_excl_u, '[]'::jsonb),
        COALESCE(v_excl_g, '[]'::jsonb)
    );

    BEGIN
        UPDATE conditional_access_policies
           SET deleted_at = NULL, updated_at = now()
         WHERE id = p_id;
    EXCEPTION WHEN unique_violation THEN
        -- TOCTOU: a concurrent restore of another soft-deleted on-policy at the same
        -- priority beat us to the UPDATE; both passed the EXISTS check above but the
        -- second commit triggers the partial-unique index (ca_policies_priority_unique_idx).
        -- Re-raise as BZ087 so callers get the structured error, not an opaque 23505.
        RAISE EXCEPTION 'cannot restore policy %: priority % is already held by an active policy (concurrent restore)', p_id, v_priority
            USING ERRCODE = 'BZ087',
                  HINT = 'change the restored policy''s priority, or soft-delete the conflicting policy first — see docs/reducer-error-codes.md#BZ087';
    END;

    PERFORM audit_write(p_admin_id, 'ca_policy_restore', 'conditional_access_policy', p_id, v_before, NULL, NULL, NULL, 'core');

    -- F2: CA-F choke point — not a bespoke app_notify call.
    PERFORM ca_notify_policy_change('ca_policy_restore');
END;
$$ LANGUAGE plpgsql VOLATILE;
