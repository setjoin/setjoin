-- ════════════════════════════════════════════════════════════════════════
-- V022__drop_umbrella_perms.sql — remove the deprecated umbrella permission
-- keys users.write and mail.write from the catalog and all role groups.
--
-- Background: V020 backfilled the four 等保三级 split keys (users.create,
-- users.suspend, mail.pipeline, mail.security) onto every role group that
-- held an umbrella key. The umbrella keys are now redundant; V022 removes
-- them permanently.
--
-- Idempotent: both DELETE and array_remove are no-ops if the rows / elements
-- are already absent. Safe to run twice with no observable change.
-- ════════════════════════════════════════════════════════════════════════

-- Remove umbrella keys from the permission catalog.
DELETE FROM public.admin_permissions
WHERE  permission_key IN ('users.write', 'mail.write');

-- Strip umbrella keys from every role group's permissions array.
UPDATE public.admin_role_groups
SET    permissions = array_remove(array_remove(permissions, 'users.write'), 'mail.write'),
       updated_at  = now()
WHERE  permissions && ARRAY['users.write', 'mail.write'];


-- ── Schema migration record ────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (22, now())
  ON CONFLICT (version) DO NOTHING;
