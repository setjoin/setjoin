-- admin_can_manage.sql — admin-target SCOPE-NARROWING gate (domain AND OU) used by
-- every sensitive admin handler. Semantics (UNCHANGED from the 9 inline copies it
-- replaces): an actor with NO active admin assignment reaches everyone; otherwise the
-- actor must reach the target via admin_can_reach (domain AND OU per the per-assignment
-- union). STABLE: read-only.
--
-- NOT A STANDALONE AUTHORIZATION GATE — it FAILS OPEN for a zero-assignment actor by
-- design. It only NARROWS scope AFTER the route permission middleware (RequirePerm /
-- RequirePermAudited) has already authorized the action. The authority axis is the
-- caller's permission claim, enforced at the route; in production every admin holds ≥1
-- active assignment (see access_review_start's same fallback), so the open arm is a
-- test-fixture convenience, not a production path. Callers MUST run the route perm
-- gate first; never use admin_can_manage as the sole authorization check.
-- (A revoked admin presenting a still-valid JWT is a JWT-staleness concern that spans
--  the whole claim-based perm model — RequirePerm reads claims, not live DB rows — and
--  is not closeable here without breaking that model and the documented fail-open.)
CREATE OR REPLACE FUNCTION admin_can_manage(p_actor bigint, p_target bigint)
RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT NOT EXISTS (
    SELECT 1 FROM admin_role_assignments
    WHERE user_id = p_actor AND (expires_at IS NULL OR expires_at > now())
  ) OR admin_can_reach(p_actor, p_target);
$$;

-- Security-sensitive mutations that must survive stale JWT permission claims
-- use this stricter primitive. Permission, domain, and OU/set reach must come
-- from the SAME persisted, unexpired, currently-active assignment. Unlike
-- admin_can_manage, zero live assignments never fail open.
CREATE OR REPLACE FUNCTION admin_can_manage_with_permission(
    p_actor bigint, p_target bigint, p_permission text
) RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT EXISTS (
    SELECT 1
      FROM admin_role_assignments ra
      JOIN admin_role_groups rg ON rg.id = ra.role_group_id
      LEFT JOIN departments sd
        ON ra.scope_type = 'ou' AND sd.id = ra.scope_id
     WHERE ra.user_id = p_actor
       AND p_permission = ANY(rg.permissions)
       AND (ra.expires_at IS NULL OR ra.expires_at > now())
       AND admin_assignment_active(ra.eligible, ra.activated_until)
       AND (
         COALESCE(ra.domain_override, rg.domain_scope) IS NULL
         OR EXISTS (
           SELECT 1
             FROM users tu
            WHERE tu.id = p_target
              AND COALESCE(guest_account_host_domain(tu.id), tu.domain_id)
                  = COALESCE(ra.domain_override, rg.domain_scope)
         )
       )
       AND (
         ra.scope_type IS NULL
         OR (
           ra.scope_type = 'ou'
           AND EXISTS (
             SELECT 1
               FROM users tu
               JOIN departments td ON td.id = tu.department_id
              WHERE tu.id = p_target
                AND (td.path = sd.path OR starts_with(td.path, sd.path || '/'))
           )
         )
         OR (
           ra.scope_type = 'set'
           AND admin_set_reaches(ra.scope_id, p_target)
         )
       )
  );
$$;
