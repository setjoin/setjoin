-- ════════════════════════════════════════════════════════════════════════
-- V058__offline_policy_perm.sql — register mail.offline_policy permission.
--
-- Adds the mail.offline_policy write permission (offline-cache governance:
-- policy CRUD + org enable toggle) to the admin_permissions catalog.
-- Assigns it to Super Admin (all-perm role) only; 系统管理员 is intentionally
-- excluded (V019 §5.2 allow-list is spec-locked; amend there if needed).
--
-- Idempotent: INSERT … ON CONFLICT DO NOTHING; array append skips if present.
-- ════════════════════════════════════════════════════════════════════════

-- Register the permission in the catalog.
INSERT INTO public.admin_permissions (permission_key, category, description, is_sensitive) VALUES
  ('mail.offline_policy', 'Mail', 'Offline-cache governance: policy CRUD and org enable/disable toggle', true)
ON CONFLICT (permission_key) DO NOTHING;

-- Super Admin receives all non-SoD permissions; append if absent (idempotent).
-- ponytail: 系统管理员 not assigned here — V019 §5.2 allow-list is spec-locked;
-- add mail.offline_policy there only after a spec amendment + V019 update.
UPDATE public.admin_role_groups
SET    permissions = permissions || ARRAY(
         SELECT k FROM unnest(ARRAY['mail.offline_policy']) AS k
         WHERE NOT (permissions @> ARRAY[k])
       ),
       updated_at  = now()
WHERE  name = 'Super Admin';

-- ── Schema migration record ────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (58, now())
  ON CONFLICT (version) DO NOTHING;
