-- ════════════════════════════════════════════════════════════════════════
-- V010__rbac_p1_presets.sql — forward migration (RBAC preset role groups).
--
-- Seeds 2 new built-in role groups that peer suites ship near-universally but
-- setjoin's baseline 6 lacked: Compliance Admin and Global Reader (read-only
-- org-wide). Both are composable from the existing 21 permissions — no new
-- permission keys. Idempotent via WHERE NOT EXISTS on the UNIQUE name.
-- ════════════════════════════════════════════════════════════════════════

INSERT INTO public.admin_role_groups (name, description, permissions, domain_scope, is_builtin)
SELECT 'Compliance Admin',
       'eDiscovery, retention, DLP policy management plus audit-log read.',
       '{compliance.read,compliance.write,audit.read}'::text[],
       NULL, true
WHERE NOT EXISTS (SELECT 1 FROM public.admin_role_groups WHERE name = 'Compliance Admin');

INSERT INTO public.admin_role_groups (name, description, permissions, domain_scope, is_builtin)
SELECT 'Global Reader',
       'Read-only access across every admin area. No write permissions.',
       '{users.read,domains.read,audit.read,mam.read,queue.read,reports.read,compliance.read,backup.read}'::text[],
       NULL, true
WHERE NOT EXISTS (SELECT 1 FROM public.admin_role_groups WHERE name = 'Global Reader');

-- Keep the identity sequence ahead of the max id we just inserted.
SELECT pg_catalog.setval('public.admin_role_groups_id_seq',
       (SELECT MAX(id) FROM public.admin_role_groups), true);

INSERT INTO public.schema_migrations (version, applied_at) VALUES (10, now())
    ON CONFLICT (version) DO NOTHING;
