-- V048: Seed approvals.view + approvals.manage perms; upgrade V045 RLS from interim super-gate.
-- Spec: docs/superpowers/specs/2026-06-27-approval-engine-design.md §11.

-- Seed the two approval permissions.
INSERT INTO public.admin_permissions (permission_key, category, description, is_sensitive)
VALUES
  ('approvals.view',   'Approvals', 'View and audit approval requests',     false),
  ('approvals.manage', 'Approvals', 'Create/edit/delete approval policies', true)
ON CONFLICT (permission_key) DO NOTHING;

-- Append both to the Super Admin role (role_group_id = 1).
UPDATE public.admin_role_groups
   SET permissions = (SELECT array_agg(DISTINCT p ORDER BY p)
                        FROM unnest(permissions || ARRAY['approvals.view','approvals.manage']) AS p)
 WHERE id = 1;

-- ── Upgrade V045 RLS policies to use the real perms ──────────────────────────

DROP POLICY approval_policies_admin_only ON public.approval_policies;
CREATE POLICY approval_policies_admin_only ON public.approval_policies
  FOR ALL TO public
  USING (
    EXISTS (
      SELECT 1 FROM public.admin_role_assignments ara
      JOIN public.admin_role_groups arg ON arg.id = ara.role_group_id
      WHERE ara.user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
        AND (ara.expires_at IS NULL OR ara.expires_at > now())
        AND (
          NOT COALESCE((SELECT enabled FROM public.feature_toggles WHERE key='rbac.jit'), false)
          OR ara.eligible = false
          OR (ara.activated_until IS NOT NULL AND ara.activated_until > now())
        )
        AND 'approvals.manage' = ANY(arg.permissions)
    )
  );

DROP POLICY approval_requests_row_visibility ON public.approval_requests;
CREATE POLICY approval_requests_row_visibility ON public.approval_requests
  FOR ALL TO public
  USING (
    (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint) IS NOT NULL
    AND (
      requester_user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
      OR (approver_kind = 'user'
          AND approver_ref = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint))
      OR (approver_kind = 'role_group'
          AND EXISTS (
            SELECT 1 FROM public.admin_role_assignments ara
             WHERE ara.role_group_id = approver_ref
               AND ara.user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
               AND (ara.expires_at IS NULL OR ara.expires_at > now())
               AND (
                 NOT COALESCE((SELECT enabled FROM public.feature_toggles WHERE key='rbac.jit'), false)
                 OR ara.eligible = false
                 OR (ara.activated_until IS NOT NULL AND ara.activated_until > now())
               )))
      -- admin: approvals.view OR approvals.manage
      OR EXISTS (
           SELECT 1 FROM public.admin_role_assignments ara
           JOIN public.admin_role_groups arg ON arg.id = ara.role_group_id
            WHERE ara.user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
              AND (ara.expires_at IS NULL OR ara.expires_at > now())
              AND (
                NOT COALESCE((SELECT enabled FROM public.feature_toggles WHERE key='rbac.jit'), false)
                OR ara.eligible = false
                OR (ara.activated_until IS NOT NULL AND ara.activated_until > now())
              )
              AND (
                'approvals.view' = ANY(arg.permissions)
                OR 'approvals.manage' = ANY(arg.permissions)
              ))
    )
  );

INSERT INTO public.schema_migrations (version, applied_at) VALUES (73, now())
  ON CONFLICT (version) DO NOTHING;
