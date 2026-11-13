-- ca_policy_restore_from_audit.sql — CA-1 C3: rebuild a purged (hard-deleted)
-- conditional-access policy from an admin_audit_log before_state snapshot.
--
-- Reads before_state from the given audit row (must be a conditional_access_policy
-- target snapshot), re-INSERTs the policy with a fresh id (original id may be
-- reused by other rows or simply gone). Raises BZ087 on priority clash (same rule
-- as ca_policy_restore: state='on' + priority already held by a live policy).
-- Raises BZ086 if the audit row is missing or its before_state is not a valid
-- policy snapshot. Calls ca_lockout_guard before INSERT (BZ080 on admin lockout).
-- Writes admin_audit_log in-txn, PERFORMs ca_notify_policy_change (F2).
-- Returns the new policy id. VOLATILE.

CREATE OR REPLACE FUNCTION ca_policy_restore_from_audit(
    p_audit_id BIGINT,
    p_admin_id BIGINT
) RETURNS BIGINT AS $$
DECLARE
    v_snap     JSONB;
    v_priority INT;
    v_state    TEXT;
    v_new_id   BIGINT;
    v_after    JSONB;
BEGIN
    -- Enter the universal CA advisory-fence domain before reading the immutable
    -- audit snapshot or probing/inserting the live policy set.
    PERFORM ca_reachability_fence();

    -- (1) Load the before_state snapshot; validate it is a CA-policy audit row.
    SELECT before_state INTO v_snap
      FROM admin_audit_log
     WHERE id = p_audit_id
       AND target_type = 'conditional_access_policy';

    IF v_snap IS NULL THEN
        -- BZ086: audit row missing or not a CA-policy snapshot.
        -- (BZ082 is already allocated to ca_break_glass_empty — cannot reuse.)
        RAISE EXCEPTION 'audit row % not found or not a conditional_access_policy snapshot', p_audit_id
            USING ERRCODE = 'BZ086',
                  HINT = 'pass the id of a ca_policy_delete audit row with a non-null before_state for target_type=conditional_access_policy';
    END IF;

    v_priority := (v_snap->>'priority')::int;
    v_state    := COALESCE(v_snap->>'state', 'off');

    -- (2) BZ087: priority clash (same logic as ca_policy_restore).
    IF v_state = 'on' AND EXISTS (
        SELECT 1 FROM conditional_access_policies
         WHERE priority = v_priority
           AND state = 'on'
           AND deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION 'cannot restore policy from audit %: priority % is already held by an active policy', p_audit_id, v_priority
            USING ERRCODE = 'BZ087',
                  HINT = 'change the restored policy''s priority, or soft-delete the conflicting policy first — see docs/reducer-error-codes.md#BZ087';
    END IF;

    -- (2b) Admin-lockout guard — must run before INSERT makes the row live.
    -- ca_lockout_guard short-circuits immediately for non-on/non-global/non-block cases
    -- (see ca_lockout_guard.sql lines 40-43), so this is zero-cost on safe restores.
    -- Snapshot exclude lists may be stale (admin memberships change after snapshot);
    -- the guard re-checks live admin_role_assignments + user_group_members.
    PERFORM ca_lockout_guard(
        v_state,
        COALESCE(v_snap->>'scope_type', 'global'),
        COALESCE(v_snap->'actions', '{"operator":"all","grants":[{"action":"allow"}]}'::jsonb),
        COALESCE(v_snap->'exclude_users', '[]'::jsonb),
        COALESCE(v_snap->'exclude_groups', '[]'::jsonb)
    );

    -- (3) Re-INSERT with a fresh id (sequence-generated); original id not reused.
    -- ponytail: all columns from snapshot; name/description/state/scope defaults
    -- keep COALESCE so a partial snapshot does not crash (defensive).
    -- MUST pass enabled explicitly: the ca_sync_enabled BEFORE-INSERT trigger has a
    -- back-compat branch that flips state='off' → 'on' when enabled=TRUE (the column
    -- default). Set enabled=false to bypass it; the trigger then derives enabled from
    -- state correctly. This is the only safe INSERT path for non-'on' states.
    -- TOCTOU: a concurrent restore of another audit snapshot at the same priority
    -- slot can beat us to the INSERT; trap unique_violation (23505) and re-raise
    -- as BZ087 (mirrors ca_policy_restore.sql pattern).
    BEGIN
        INSERT INTO conditional_access_policies
            (priority, name, description, state, enabled, scope_type, scope_target,
             conditions, actions, exclude_users, exclude_groups, created_from_template)
        VALUES (
            v_priority,
            COALESCE(v_snap->>'name', 'restored-policy'),
            COALESCE(v_snap->>'description', ''),
            v_state,
            false,     -- ponytail: bypass the legacy enabled=TRUE default; trigger rewrites from state
            COALESCE(v_snap->>'scope_type', 'global'),
            COALESCE(v_snap->>'scope_target', ''),
            COALESCE(v_snap->'conditions', '{}'::jsonb),
            COALESCE(v_snap->'actions', '{"operator":"all","grants":[{"action":"allow"}]}'::jsonb),
            COALESCE(v_snap->'exclude_users', '[]'::jsonb),
            COALESCE(v_snap->'exclude_groups', '[]'::jsonb),
            COALESCE(v_snap->>'created_from_template', '')
        )
        RETURNING id INTO v_new_id;
    EXCEPTION WHEN unique_violation THEN
        RAISE EXCEPTION 'cannot restore policy from audit %: priority % is already held by an active policy (concurrent restore)', p_audit_id, v_priority
            USING ERRCODE = 'BZ087',
                  HINT = 'change the restored policy''s priority, or soft-delete the conflicting policy first — see docs/reducer-error-codes.md#BZ087';
    END;

    SELECT to_jsonb(c) - 'enabled' INTO v_after
      FROM conditional_access_policies c WHERE id = v_new_id;

    -- (4) Audit row — link back to the source audit via notes.
    PERFORM audit_write(p_admin_id, 'ca_policy_restore_from_audit',
            'conditional_access_policy', v_new_id,
            v_snap, v_after, NULL,
            'restored from audit_log id ' || p_audit_id, 'core');

    -- (5) F2: CA-F choke point — not a bespoke app_notify call.
    PERFORM ca_notify_policy_change('ca_policy_restore_from_audit');

    RETURN v_new_id;
END;
$$ LANGUAGE plpgsql VOLATILE;
