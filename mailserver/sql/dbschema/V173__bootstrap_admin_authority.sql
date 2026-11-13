-- V173 — repair the unambiguous first-boot administrator authority gap.
--
-- ensure_default_admin historically created a users.is_local_admin marker but
-- no governed admin_role_assignments row. Since the legacy IsAdmin bridge was
-- removed, a fresh installation could authenticate but correctly failed every
-- permission-gated admin route.
--
-- This repair is intentionally narrow: there must be exactly one enabled local
-- administrator marker in the whole deployment and no live governed admin
-- assignment for anyone. Ordinary member accounts may already exist: creating
-- one must not make a locked-out bootstrap installation unrecoverable.
-- Multiple local-admin candidates or any live governed admin make the state
-- ambiguous, so the migration elevates nobody.

INSERT INTO public.admin_role_assignments (user_id, role_group_id, granted_by)
SELECT u.id, g.id, u.id
  FROM public.users u
  JOIN public.admin_role_groups g
    ON g.name = 'Super Admin'
   AND g.is_builtin = TRUE
 WHERE u.enabled = TRUE
   AND u.is_local_admin = TRUE
   AND (
         SELECT count(*)
           FROM public.users candidate
          WHERE candidate.enabled = TRUE
            AND candidate.is_local_admin = TRUE
       ) = 1
   AND NOT EXISTS (
         SELECT 1
           FROM public.admin_role_assignments live_assignment
          WHERE live_assignment.expires_at IS NULL
             OR live_assignment.expires_at > now()
       )
   AND NOT EXISTS (
         SELECT 1
           FROM public.admin_role_assignments existing
          WHERE existing.user_id = u.id
       )
ON CONFLICT (user_id, role_group_id) DO NOTHING;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (173, now())
  ON CONFLICT (version) DO NOTHING;
