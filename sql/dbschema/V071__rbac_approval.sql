-- V046: RBAC approval columns on admin_role_activation_policy.
-- require_approval: when true AND approval.rbac toggle is on, admin_role_activate parks
--   the request instead of opening the window. approver_spec mirrors approval_policies.approver_spec.
ALTER TABLE public.admin_role_activation_policy
  ADD COLUMN require_approval boolean NOT NULL DEFAULT false,
  ADD COLUMN approver_spec    jsonb;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (71, now())
  ON CONFLICT (version) DO NOTHING;
