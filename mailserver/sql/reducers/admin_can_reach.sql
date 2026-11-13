-- admin_can_reach(p_actor, p_target) — the single OU-scope enforcement primitive.
--
-- True iff the actor has at least one active admin role assignment whose domain
-- AND OU both cover the target. Union ACROSS assignments (the outer EXISTS),
-- intersection WITHIN one assignment (domain clause AND OU clause).
--
-- Domain coverage: COALESCE(domain_override, role group's domain_scope) IS NULL
--   (all domains) OR the target's ownership domain matches. For members that
--   is users.domain_id; for guests it is guest_accounts.host_domain_id, read
--   through the RLS-safe guest_account_host_domain helper because the guest's
--   users.domain_id is only the guest.invalid routing-isolation landing spot.
-- OU coverage: scope_type IS NULL (no OU narrowing) OR the target's department
--   path equals the scoped department's path OR is a descendant of it. The
--   starts_with(path, scoped || '/') test is the load-bearing path boundary —
--   '/eng' covers '/eng/backend' but NOT '/engineering'. starts_with (not LIKE)
--   is deliberate: department names may contain '_' or '%' (ValidateResourceName
--   allows them), which a LIKE pattern would interpret as wildcards and leak
--   across OU boundaries — starts_with does a literal prefix match.
CREATE OR REPLACE FUNCTION admin_can_reach(p_actor bigint, p_target bigint)
RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT EXISTS (
    SELECT 1
    FROM admin_role_assignments ra
    JOIN admin_role_groups rg ON rg.id = ra.role_group_id
    LEFT JOIN departments sd ON ra.scope_type = 'ou' AND sd.id = ra.scope_id
    WHERE ra.user_id = p_actor
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
