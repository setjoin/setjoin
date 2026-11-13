-- ════════════════════════════════════════════════════════════════════════
-- admin_protection_check.sql — authorization-beyond-route-perm guard
--
-- Called by Go handlers ON THEIR OWN TRANSACTION for the 5 sensitive
-- admin ops (delete, suspend, remove_role, password_reset, impersonate).
-- Domination/self-protection have no trigger backstop — this is the only
-- gate.
--
-- Raises:
--   BZ066 — actor tries to delete/suspend their own account (self-protection,
--           always-on); OR a non-Super-Admin self-assigns a role while 等保三级
--           SoD mode (dengbao.sod_mode) is ON. Super Admin may always
--           self-assign; outside 等保三级 anyone may self-assign.
--   BZ065 — target out-ranks actor (perms superset OR broader scope)
--   BZ064 — op would remove/disable the last USABLE (enabled) Super Admin
--
-- Super-Admin short-circuit: a role_group_id=1 actor dominates everyone.
--   The raw perm array for role 1 is deliberately NOT a superset of the
--   audit admin's array (audit.export silo), so the domination check MUST
--   use the group membership test rather than the array comparison.
--   Mirrors the impersonation gate's group-check logic.
--
-- Scope semantics (mirroring admin_effective_authority broadest-reach):
--   A domain-scoped actor (scope IS NOT NULL) may NOT manage a global
--   admin target (scope IS NULL) — that target has broader reach.
--   The scope gate fires only when the target holds admin perms at all
--   (cardinality > 0), so a domain-scoped actor CAN manage a non-admin
--   in-domain target.
--   Symmetric OU arm: an OU-confined actor (ou_reach non-empty) may NOT
--   manage an admin target whose OU reach is broader — target unconfined,
--   or holding a subtree not contained in the actor's union of subtrees.
--   Same cardinality gate.
--
-- Last-usable-SA pre-check:
--   Counts OTHER enabled Super Admins — EXCLUDING the target — so a
--   disabled target's removal never spuriously blocks. Raises BZ064 when
--   the remaining usable SA count is exactly 0. This MUST agree with the
--   Task 3 trigger (which excludes OLD.id on DELETE/UPDATE).
--
-- VOLATILE (default): the PERFORM … FOR UPDATE principal lock makes this
-- non-read-only. STABLE would make Postgres reject the lock at runtime:
-- "SELECT FOR UPDATE is not allowed in a non-volatile function."
-- The helper admin_effective_authority stays STABLE (genuinely read-only).
-- ════════════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION admin_protection_check(
    p_actor_id       BIGINT,
    p_target_id      BIGINT,
    p_op             TEXT,
    p_role_group_id  BIGINT
) RETURNS VOID AS $$
DECLARE
    v_actor        RECORD;
    v_target       RECORD;
    v_is_super     BOOLEAN;
    v_target_is_sa BOOLEAN;
    v_enabled_sa   INT;
BEGIN
    -- V172 universal order: authority advisory fence before the principal row.
    -- Assignment/group writers take this same fence in BEFORE triggers.
    PERFORM admin_authority_fence();

    -- serialize concurrent grants to this principal (the AssignMember idiom)
    PERFORM 1 FROM users WHERE id = p_target_id FOR UPDATE;

    -- Super-Admin actor dominates all (group membership, not the raw array).
    -- The audit.export silo means the raw perm array for role 1 is NOT a
    -- superset of the audit admin's array, so the domination check MUST
    -- use this group-membership test (mirrors the impersonation gate).
    -- Computed once here and reused by both the self-check and the domination
    -- block below.
    v_is_super := admin_is_super(p_actor_id);

    -- self-protection.
    --   delete / suspend self → ALWAYS blocked, for everyone (lockout
    --     prevention): an admin must never lock themselves out of their own
    --     account.
    --   assign_role self → blocked ONLY under 等保三级 SoD mode AND only when the
    --     actor is NOT a Super Admin. A Super Admin may always self-assign;
    --     outside 等保三级 anyone may self-assign (Rule A still bars escalation
    --     elsewhere). The bulk apply reducer relies on this (BZ066 → reason
    --     'self').
    --   remove_role self → never blocked here: a Super Admin may remove their
    --     own SA role (the last-usable-SA pre-check below — BZ064 — is the only
    --     constraint there).
    IF p_actor_id = p_target_id THEN
        IF p_op IN ('delete','suspend') THEN
            RAISE EXCEPTION 'cannot % your own account', p_op
                USING ERRCODE='BZ066', HINT='{"type":"admin_protection_self"}';
        ELSIF p_op = 'assign_role'
              AND NOT v_is_super
              AND COALESCE((SELECT enabled FROM feature_toggles
                              WHERE key = 'dengbao.sod_mode'), false) THEN
            RAISE EXCEPTION 'cannot % your own account', p_op
                USING ERRCODE='BZ066', HINT='{"type":"admin_protection_self"}';
        END IF;
    END IF;

    IF NOT v_is_super THEN
        -- actor: ACTIVE-ONLY (a dormant-eligible actor wields nothing).
        SELECT * INTO v_actor  FROM admin_effective_authority(p_actor_id);
        -- target: ELIGIBLE-OR-ACTIVE (a dormant-eligible higher admin stays
        -- protected — the dormant-window-abuse guard) via p_active_only => FALSE.
        SELECT * INTO v_target FROM admin_effective_authority(p_target_id, FALSE);

        -- perms: target must be a subset of actor's perms
        IF NOT (v_target.perms <@ v_actor.perms) THEN
            RAISE EXCEPTION 'target holds privileges beyond your own'
                USING ERRCODE='BZ065', HINT='{"type":"admin_protection_outranked"}';
        END IF;

        -- scope: a domain-scoped actor may NOT act on a GLOBAL admin target.
        -- Guard gated on cardinality > 0 so a domain-scoped actor CAN manage
        -- a non-admin target in-domain (their perms array is empty → no admin
        -- exposure → no scope conflict).
        IF cardinality(v_target.perms) > 0
           AND v_actor.scope IS NOT NULL AND v_target.scope IS NULL THEN
            RAISE EXCEPTION 'target has broader (global) scope than you'
                USING ERRCODE='BZ065', HINT='{"type":"admin_protection_outranked"}';
        END IF;

        -- Object-axis domination (OU + set), per-user union containment.
        --   actor.is_unconfined ⇒ object axis satisfied (skip; perms/self/last-SA
        --     arms still apply).
        --   target.is_unconfined AND NOT actor.is_unconfined ⇒ target reaches more
        --     ⇒ block.
        --   both object-confined ⇒ block iff the target reaches a user the actor
        --     cannot. Same cardinality gate: a non-admin target has no exposure.
        -- NEVER infer "unconfined" from a NULL/empty ou_reach (the v1/v2 P0): a
        -- 'set'-confined target has ou_reach NULL yet reaches only its set members.
        IF cardinality(v_target.perms) > 0 AND NOT v_actor.is_unconfined THEN
            IF v_target.is_unconfined THEN
                RAISE EXCEPTION 'target has broader org-unit reach than you'
                    USING ERRCODE='BZ065', HINT='{"type":"admin_protection_outranked"}';
            ELSIF EXISTS (SELECT 1 FROM admin_actor_reach_users(p_target_id) tu
                           WHERE NOT admin_can_reach(p_actor_id, tu)) THEN
                RAISE EXCEPTION 'target has broader org-unit reach than you'
                    USING ERRCODE='BZ065', HINT='{"type":"admin_protection_outranked"}';
            END IF;
        END IF;
    END IF;

    -- last-usable-Super-Admin pre-check (the triggers are authoritative;
    -- this is the application-layer early gate for the three relevant ops).
    IF p_op = 'delete'
       OR (p_op = 'remove_role' AND p_role_group_id = 1)
       OR p_op = 'suspend'
    THEN
        SELECT EXISTS(
            SELECT 1 FROM admin_role_assignments
             WHERE user_id = p_target_id AND role_group_id = 1
               AND (expires_at IS NULL OR expires_at > now())
        ) INTO v_target_is_sa;

        IF v_target_is_sa THEN
            -- Count the OTHER usable (enabled) Super Admins — EXCLUDING the
            -- target — so a disabled target's removal never spuriously blocks.
            -- This MUST agree with the Task 3 trigger, which excludes OLD.id;
            -- raise only when removing the target leaves zero usable SAs.
            SELECT count(DISTINCT ara.user_id) INTO v_enabled_sa
              FROM admin_role_assignments ara
              JOIN users u ON u.id = ara.user_id
             WHERE ara.role_group_id = 1
               AND ara.user_id <> p_target_id
               AND (ara.expires_at IS NULL OR ara.expires_at > now())
               AND u.enabled;

            IF v_enabled_sa = 0 THEN
                RAISE EXCEPTION 'the last Super Admin cannot be removed'
                    USING ERRCODE='BZ064',
                          HINT='{"type":"admin_protection_last_super_admin"}';
            END IF;
        END IF;
    END IF;
END;
$$ LANGUAGE plpgsql;   -- VOLATILE (default): the PERFORM … FOR UPDATE principal lock makes
                       -- this NON-read-only; STABLE would make Postgres reject the lock at
                       -- runtime ("SELECT FOR UPDATE is not allowed in a non-volatile function").
                       -- The helper admin_effective_authority stays STABLE (genuinely read-only).
