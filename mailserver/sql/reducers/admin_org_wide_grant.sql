-- admin_org_wide_grant(p_actor, p_perms) — does the actor hold ANY of p_perms through
-- an organization-wide assignment (no domain on the assignment or its role group, and
-- no OU/set narrowing)? Owner-approved security fix 2026-11-05 (#510): objects that
-- belong to the whole organization (scope sets without a domain, department trees,
-- org-wide conditional-access policies, global roles' activation policy) may only be
-- read or changed under such a grant; a domain-scoped admin is confined to objects
-- whose owning domain is one of their own.
--
-- Live assignments only: unexpired and JIT-active (admin_assignment_active), so a
-- dormant eligible grant, a lapsed activation or a revocation takes effect at once.
-- STABLE, read-only; callers repeat it inside the statement that mutates (R3).
CREATE OR REPLACE FUNCTION admin_org_wide_grant(p_actor bigint, p_perms text[])
RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT EXISTS (
    SELECT 1
      FROM admin_role_assignments ra
      JOIN admin_role_groups rg ON rg.id = ra.role_group_id
     WHERE ra.user_id = p_actor
       AND (ra.expires_at IS NULL OR ra.expires_at > now())
       AND admin_assignment_active(ra.eligible, ra.activated_until)
       AND COALESCE(ra.domain_override, rg.domain_scope) IS NULL
       AND ra.scope_type IS NULL
       AND rg.permissions && p_perms
  );
$$;

-- admin_domain_restriction(p_actor, p_perms) — the domain a caller is confined to for the
-- permissions of a route, derived ONLY from live grants that carry one of p_perms (a grant
-- of another permission never widens or narrows it). 0 = organization-wide grant; a
-- positive id = the narrowest domain among its domain-scoped grants; -1 = no usable grant
-- (for example an OU- or set-confined grant on a domain-less role group): refuse. Callers
-- filter with `r = 0 OR domain_id = r`, which -1 can never satisfy.
CREATE OR REPLACE FUNCTION admin_domain_restriction(p_actor bigint, p_perms text[])
RETURNS bigint LANGUAGE sql STABLE AS $$
  SELECT CASE WHEN admin_org_wide_grant(p_actor, p_perms) THEN 0
    ELSE COALESCE((
      SELECT MIN(COALESCE(ra.domain_override, rg.domain_scope))
        FROM admin_role_assignments ra
        JOIN admin_role_groups rg ON rg.id = ra.role_group_id
       WHERE ra.user_id = p_actor
         AND (ra.expires_at IS NULL OR ra.expires_at > now())
         AND admin_assignment_active(ra.eligible, ra.activated_until)
         AND rg.permissions && p_perms
         AND COALESCE(ra.domain_override, rg.domain_scope) IS NOT NULL), -1) END;
$$;

-- admin_perm_unconfined(p_actor, p_perms): does any live grant carrying one of p_perms reach
-- every object of its domain (no OU/set narrowing)? Permission-aware twin of the
-- is_unconfined flag of admin_effective_authority.
CREATE OR REPLACE FUNCTION admin_perm_unconfined(p_actor bigint, p_perms text[])
RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT EXISTS (
    SELECT 1 FROM admin_role_assignments ra
      JOIN admin_role_groups rg ON rg.id = ra.role_group_id
     WHERE ra.user_id = p_actor
       AND (ra.expires_at IS NULL OR ra.expires_at > now())
       AND admin_assignment_active(ra.eligible, ra.activated_until)
       AND ra.scope_type IS NULL
       AND rg.permissions && p_perms);
$$;

-- admin_can_reach_perm(p_actor, p_target, p_perms): admin_can_reach through grants that
-- carry one of p_perms only (admin_can_reach accepts any grant, so a domain-wide grant of an
-- unrelated permission would extend the reach of another). Same domain/OU/set semantics.
CREATE OR REPLACE FUNCTION admin_can_reach_perm(p_actor bigint, p_target bigint, p_perms text[])
RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT EXISTS (
    SELECT 1
    FROM admin_role_assignments ra
    JOIN admin_role_groups rg ON rg.id = ra.role_group_id
    LEFT JOIN departments sd ON ra.scope_type = 'ou' AND sd.id = ra.scope_id
    WHERE ra.user_id = p_actor
      AND rg.permissions && p_perms
      AND (ra.expires_at IS NULL OR ra.expires_at > now())
      AND admin_assignment_active(ra.eligible, ra.activated_until)
      AND ( COALESCE(ra.domain_override, rg.domain_scope) IS NULL
            OR EXISTS (SELECT 1 FROM users tu WHERE tu.id = p_target
                        AND COALESCE(guest_account_host_domain(tu.id), tu.domain_id)
                            = COALESCE(ra.domain_override, rg.domain_scope)) )
      AND ( ra.scope_type IS NULL
            OR ( ra.scope_type = 'ou'
                 AND EXISTS (SELECT 1 FROM users tu JOIN departments td ON td.id = tu.department_id
                              WHERE tu.id = p_target
                                AND (td.path = sd.path OR starts_with(td.path, sd.path || '/'))) )
            OR ( ra.scope_type = 'set' AND admin_set_reaches(ra.scope_id, p_target) ) )
  );
$$;
