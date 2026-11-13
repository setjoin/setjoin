-- Domain-scoped RBAC authority for the Exchange assessment control plane.
-- Owner-approved security fix 2026-11-05 (#434): the domain comes from the assignment
-- override OR, when that is NULL, the role group's domain_scope; frozen Go ignored the
-- group scope, so a group-scoped admin could act for every domain. Only a grant with
-- neither (organization-wide) reaches all domains. Every caller derives p_domain_id
-- from the stored project row (or the request's domain for project creation, which
-- this check then confines).
CREATE OR REPLACE FUNCTION exchange_assessment_domain_authorized(
  p_actor_id bigint, p_domain_id bigint, p_permission text
) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
  SELECT EXISTS (
    SELECT 1
    FROM admin_role_assignments a
    JOIN admin_role_groups g ON g.id=a.role_group_id
    WHERE a.user_id=p_actor_id
      AND p_permission=ANY(g.permissions)
      AND (a.expires_at IS NULL OR a.expires_at>statement_timestamp())
      AND admin_assignment_active(a.eligible,a.activated_until)
      AND a.scope_type IS NULL
      AND (COALESCE(a.domain_override,g.domain_scope) IS NULL
           OR COALESCE(a.domain_override,g.domain_scope)=p_domain_id)
  )
$$;
SELECT apply_worker_ownership('exchange_assessment_domain_authorized(bigint,bigint,text)'::regprocedure);
