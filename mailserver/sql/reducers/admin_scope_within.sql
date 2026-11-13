-- ════════════════════════════════════════════════════════════════════════
-- admin_scope_within.sql — Rule A scope containment predicate
--
-- Produces: admin_scope_within(p_actor, p_grant_scope_type, p_grant_scope_id,
--           p_grant_domain) RETURNS boolean — TRUE iff a grant carrying that
--           (domain, OU) is AT/UNDER the actor's own reach (the actor cannot
--           write a grant broader than what they themselves hold).
--
-- Closes the self-broaden hole: Rule A was perms-only (target perms ⊆ actor
-- perms), so an OU-scoped admin with roles.assign could write a grant carrying
-- a root/NULL scope and reach the whole org. This predicate is the scope arm.
--
-- Object axis — an actor with ANY object-unrestricted grant (is_unconfined:
--   some active grant has scope_type IS NULL) may grant anything. This is NEVER
--   inferred from a NULL/empty ou_reach array (the v1/v2 P0: a 'set'-confined
--   actor has ou_reach NULL yet is confined). An object-confined actor (NOT
--   is_unconfined) granting a no-scope (domain-wide) grant is FALSE — the
--   broadening case. Otherwise the grant must be STRUCTURALLY within the actor's
--   reach (forever-safe), per spec §5:
--     • grant 'ou' D → admin_actor_contains_ou: D's subtree sits at/under one of
--       the actor's own OU grants OR an OU member of one of the actor's scope-sets.
--       SUBTREE CONTAINMENT, never point-in-time membership — a department's
--       population grows via routine `users.department_id` writes (NOT a privileged
--       set-edit), so resolving the OU to its CURRENT users would be vacuously TRUE
--       for an empty OU and let the grantee reach users moved in later (escalation).
--     • grant 'set' S → every member of S within reach: ou members by the same
--       structural containment; user/group members point-in-time via admin_can_reach
--       (the spec's accepted user-move / SoD-bounded-group-drift residual).
--     • any other scope_type → fail closed.
--
-- Domain axis — reuses the existing domain rule: a global actor (scope NULL)
--   may grant any domain; a domain-scoped actor may grant only their own
--   domain. A grant with NO domain (p_grant_domain NULL) is domain-wide and is
--   FALSE for a domain-scoped actor (broadening).
--
-- A fully-unconfined actor (scope NULL, is_unconfined) → any grant TRUE.
--
-- STABLE: read-only (admin_effective_authority + admin_actor_contains_ou +
--   admin_can_reach + departments lookup).
-- ════════════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION admin_scope_within(
    p_actor            BIGINT,
    p_grant_scope_type TEXT,
    p_grant_scope_id   BIGINT,
    p_grant_domain     BIGINT
) RETURNS BOOLEAN AS $$
DECLARE
    v_actor RECORD;
BEGIN
    SELECT scope, is_unconfined INTO v_actor FROM admin_effective_authority(p_actor);

    -- Domain axis: a domain-scoped actor may grant only within their domain.
    -- A domain-wide grant (p_grant_domain NULL) from a confined actor broadens.
    IF v_actor.scope IS NOT NULL
       AND (p_grant_domain IS NULL OR p_grant_domain <> v_actor.scope) THEN
        RETURN false;
    END IF;

    -- Object axis. is_unconfined (any scope_type-NULL grant) ⇒ may grant anything.
    -- NEVER infer "unconfined" from an empty ou_reach array (the v1/v2 P0).
    IF v_actor.is_unconfined THEN
        RETURN true;
    END IF;

    -- Object-confined actor: an unrestricted (no scope) grant broadens → reject.
    IF p_grant_scope_type IS NULL OR p_grant_scope_id IS NULL THEN
        RETURN false;
    END IF;

    -- Grant must be STRUCTURALLY within the actor's reach (forever-safe), per spec §5.
    -- OU coverage (grant OU, or an OU member of a granted set) → subtree containment
    -- (never point-in-time: a department grows via routine assignment). user/group set
    -- members → point-in-time admin_can_reach (the spec's accepted user-move / SoD-
    -- bounded-group-drift model).
    IF p_grant_scope_type = 'ou' THEN
        RETURN admin_actor_contains_ou(p_actor,
                 (SELECT path FROM departments WHERE id = p_grant_scope_id));
    END IF;

    IF p_grant_scope_type = 'set' THEN
        RETURN NOT EXISTS (
            SELECT 1 FROM admin_scope_set_members m
             WHERE m.set_id = p_grant_scope_id AND (
                (m.member_type='ou'   AND NOT admin_actor_contains_ou(p_actor,
                     (SELECT path FROM departments WHERE id = m.member_id)))
             OR (m.member_type='user' AND NOT admin_can_reach(p_actor, m.member_id))
             OR (m.member_type='group' AND EXISTS (
                     SELECT 1 FROM distribution_group_members dgm
                       JOIN mailboxes mb ON mb.id = dgm.mailbox_id AND mb.is_primary
                      WHERE dgm.group_id = m.member_id
                        AND NOT admin_can_reach(p_actor, mb.user_id)))
            )
        );
    END IF;

    RETURN false;  -- unknown scope_type → fail closed
END;
$$ LANGUAGE plpgsql STABLE;
