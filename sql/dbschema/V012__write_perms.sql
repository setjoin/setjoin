-- ════════════════════════════════════════════════════════════════════════
-- V012__write_perms.sql — forward migration (two granular WRITE permissions).
--
-- Adds `mail.write` (mail-flow config: rules, DLP, TLS, anti-phishing, spam,
-- branding, SMTP pipeline) and `identity.write` (auth methods, AD/LDAP,
-- conditional access, group mappings, address policies) to the RBAC catalog so
-- admin WRITE endpoints can be gated on a granular write perm instead of the
-- coarse read-console perm. Both are sensitive. Super Admin holds every
-- permission, so it gains both. Idempotent.
-- ════════════════════════════════════════════════════════════════════════

INSERT INTO public.admin_permissions (permission_key, category, description, is_sensitive) VALUES
  ('mail.write', 'Mail', 'Edit mail-flow configuration: rules, DLP, TLS, anti-phishing, spam, branding, SMTP pipeline', true),
  ('identity.write', 'Identity', 'Edit identity/directory configuration: auth methods, AD/LDAP, conditional access, group mappings, address policies', true)
ON CONFLICT (permission_key) DO NOTHING;

-- Super Admin = all permissions; append the two new keys if absent (idempotent).
UPDATE public.admin_role_groups
SET permissions = permissions || ARRAY(
      SELECT k FROM unnest(ARRAY['mail.write','identity.write']) AS k
      WHERE NOT (permissions @> ARRAY[k])
    ),
    updated_at = now()
WHERE name = 'Super Admin';

INSERT INTO public.schema_migrations (version, applied_at) VALUES (12, now())
    ON CONFLICT (version) DO NOTHING;
