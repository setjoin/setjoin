-- ════════════════════════════════════════════════════════════════════════
-- V233__mail_export_permission.sql — dedicated mail.export permission
--
-- Round-2 admin-scope correction (Astra implementation review HOLD): the
-- admin mailbox-export route previously guarded on the broad Mail-console
-- umbrella (requireMailPerm → any mail.* console read). Exporting full
-- mailbox contents is a privileged bulk content read (same exposure class
-- as audit.export / chat.ediscovery), so it gets its own grant.
--
-- Seed ONLY — deliberately NO role backfill. Unlike V020 (mail.write →
-- mail.pipeline + mail.security split, backfilled onto every holding role
-- group), existing roles do NOT automatically gain mail.export: export
-- must be granted explicitly per role after this migration. Existing
-- exports therefore require a NEW grant (admin console → role groups →
-- permissions, or UPDATE admin_role_groups SET permissions =
-- permissions || ARRAY['mail.export'] WHERE …) before the route answers
-- 200 again. Mailbox IMPORT keeps its existing users.create guard and is
-- unaffected.
--
-- Idempotent via ON CONFLICT DO NOTHING.
-- ════════════════════════════════════════════════════════════════════════

INSERT INTO public.admin_permissions (permission_key, category, description, is_sensitive) VALUES
  ('mail.export', 'Mail', 'Export mailbox contents (MBOX/EML) — privileged bulk content read, granted per role explicitly', true)
ON CONFLICT (permission_key) DO NOTHING;

INSERT INTO public.schema_migrations(version, applied_at) VALUES (233, now()) ON CONFLICT DO NOTHING;
