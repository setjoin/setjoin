-- ════════════════════════════════════════════════════════════════════════
-- V019__dengbao_sod.sql — 等保三级 三权分立 SoD core DDL + seed
--
-- Delivers:
--   1. sod_class column on admin_role_groups — classifies each role group
--      as 'system' / 'security' / 'audit' (or NULL while mode is OFF).
--   2. Five new permission catalog rows: users.create, users.suspend,
--      mail.pipeline, mail.security, audit.export (the perm-split halves
--      plus the audit-export key).  Sensitive: users.suspend, mail.security,
--      audit.export.
--   3. Three built-in 等保 preset role groups — 系统管理员 / 安全管理员 /
--      审计管理员 — each seeded with its §5.2 allow-list and sod_class.
--   4. feature_toggles row 'dengbao.sod_mode' (enabled=FALSE — DEFAULT OFF).
--   5. sod_exclusion_guard() trigger function + trg_sod_exclusion BEFORE
--      trigger on admin_role_assignments — the hard mutual-exclusion gate.
--
-- Safe to apply twice (all inserts are idempotent via ON CONFLICT DO NOTHING
-- / WHERE NOT EXISTS).  sod_class column add is wrapped in IF NOT EXISTS.
--
-- Standard basis: GB/T 22239-2019 §8.1.5 + §8.1.10; BMB17-2006 (stricter
-- 涉密 placement adopted).  Per-class allow-lists in §5.2 of
-- docs/superpowers/specs/2026-06-22-dengbao-sod-three-powers-design.md.
-- ════════════════════════════════════════════════════════════════════════

-- ── 1. sod_class column ────────────────────────────────────────────────────

ALTER TABLE public.admin_role_groups
  ADD COLUMN IF NOT EXISTS sod_class text
  CONSTRAINT admin_role_groups_sod_class_check
  CHECK (sod_class IS NULL OR sod_class IN ('system','security','audit'));


-- ── 2. Five new permission catalog rows ────────────────────────────────────
--
-- users.create  — create/update accounts (system class; perm-split from users.write)
-- users.suspend — enable/disable (停启) accounts (security class; sensitive)
-- mail.pipeline — SMTP pipeline, rules, branding (system class)
-- mail.security — DLP, TLS, anti-phishing, spam threshold (security class; sensitive)
-- audit.export  — export audit trail (audit class; sensitive)

INSERT INTO public.admin_permissions (permission_key, category, description, is_sensitive) VALUES
  ('users.create',   'Users',    'Create and update user accounts',                                              false),
  ('users.suspend',  'Users',    'Enable/disable (停启) user accounts and modify security-sensitive attributes',  true),
  ('mail.pipeline',  'Mail',     'SMTP pipeline config, mail rules, branding',                                   false),
  ('mail.security',  'Mail',     'DLP, TLS, anti-phishing, spam threshold (安全策略 surface)',                   true),
  ('audit.export',   'Audit',    'Export audit trail records (the only permitted audit-trail export path)',       true)
ON CONFLICT (permission_key) DO NOTHING;


-- ── 3. Three 等保 preset role groups ──────────────────────────────────────
--
-- 系统管理员 (配置权) — sod_class='system'
--   Allow-list (§5.2): users.read, users.create, users.delete,
--     domains.read, domains.write, queue.read, queue.write,
--     backup.read, backup.write, system.config, system.upgrade,
--     mail.pipeline, reports.read

INSERT INTO public.admin_role_groups (name, description, permissions, sod_class, domain_scope, is_builtin)
SELECT
  '系统管理员',
  '等保三级·配置权 — 系统管理员。负责系统配置、帐号创建和运维管理。不持有授权权或审计权。',
  ARRAY[
    'users.read', 'users.create', 'users.delete',
    'domains.read', 'domains.write',
    'queue.read', 'queue.write',
    'backup.read', 'backup.write',
    'system.config', 'system.upgrade',
    'mail.pipeline', 'reports.read'
  ]::text[],
  'system',
  NULL,
  true
WHERE NOT EXISTS (SELECT 1 FROM public.admin_role_groups WHERE name = '系统管理员');

-- 安全管理员 (授权权) — sod_class='security'
--   Allow-list (§5.2): users.read, users.suspend, users.password_reset,
--     roles.manage, security.write, mail.security, identity.write,
--     mam.write, compliance.write, compliance.read

INSERT INTO public.admin_role_groups (name, description, permissions, sod_class, domain_scope, is_builtin)
SELECT
  '安全管理员',
  '等保三级·授权权 — 安全管理员。负责授权、角色分配、密码重置、身份策略和安全配置。不持有配置权或审计权。',
  ARRAY[
    'users.read', 'users.suspend', 'users.password_reset',
    'roles.manage', 'security.write',
    'mail.security', 'identity.write',
    'mam.write', 'compliance.write', 'compliance.read'
  ]::text[],
  'security',
  NULL,
  true
WHERE NOT EXISTS (SELECT 1 FROM public.admin_role_groups WHERE name = '安全管理员');

-- 审计管理员 (审计权) — sod_class='audit'
--   Allow-list (§5.2): audit.read, audit.export,
--     mam.read, compliance.read, users.read

INSERT INTO public.admin_role_groups (name, description, permissions, sod_class, domain_scope, is_builtin)
SELECT
  '审计管理员',
  '等保三级·审计权 — 审计管理员。独立审计日志读取和导出。不持有配置权或授权权，不可写入任何系统状态。',
  ARRAY[
    'audit.read', 'audit.export',
    'mam.read', 'compliance.read', 'users.read'
  ]::text[],
  'audit',
  NULL,
  true
WHERE NOT EXISTS (SELECT 1 FROM public.admin_role_groups WHERE name = '审计管理员');

-- Advance the sequence past the newly inserted ids.
SELECT pg_catalog.setval('public.admin_role_groups_id_seq',
       (SELECT MAX(id) FROM public.admin_role_groups), true);


-- ── 4. dengbao.sod_mode feature toggle (DEFAULT OFF) ──────────────────────
--
-- enabled is explicitly set to FALSE.  The feature_toggles table defaults
-- enabled to TRUE, so this explicit false is required — the safety net is
-- shared/toggle.IsEnabledDefault("dengbao.sod_mode", false) which returns
-- false when the row is absent, but we seed the row so it is visible and
-- flippable in the admin console while remaining inert.

INSERT INTO public.feature_toggles (key, enabled, description) VALUES
  ('dengbao.sod_mode', false,
   '等保三级 三权分立 mode. When ON: super-admin is unassignable, every role must carry a non-NULL sod_class, and the trg_sod_exclusion trigger enforces hard mutual exclusion across system/security/audit classes. Flip via the dedicated gated endpoint (security.write required); the OFF→ON flip runs admin_sod_precheck() in the same transaction. DEFAULT OFF — fully inert until deliberately enabled by a qualified security administrator.')
ON CONFLICT (key) DO NOTHING;


-- ── 5. sod_exclusion_guard() trigger function + trg_sod_exclusion ─────────
--
-- Hard gate (§9 of the spec): when dengbao.sod_mode is ON, a principal's
-- effective class must be a single class across all unexpired assignments.
-- This fires BEFORE INSERT OR UPDATE so every write path (Go handler, SSO
-- sync, SCIM, direct SQL) is covered.
--
-- Missing / NULL toggle row is treated as OFF (COALESCE → false) — the trigger
-- is inert on a fresh database or after a toggle row deletion.
--
-- ERRCODE 'BZ001': SoD class conflict — principal would span ≥ 2 classes.

CREATE OR REPLACE FUNCTION public.sod_exclusion_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  v_class_count int;
BEGIN
  -- Fast path: treat missing or NULL toggle row as OFF.
  IF NOT COALESCE(
       (SELECT enabled FROM feature_toggles WHERE key = 'dengbao.sod_mode'),
       false
     ) THEN
    RETURN NEW;
  END IF;

  -- Compute the count of distinct non-null sod_class values this principal
  -- will hold after this INSERT/UPDATE, including the NEW row itself.
  -- Unexpired = expires_at IS NULL OR expires_at > now().
  SELECT COUNT(DISTINCT rg.sod_class) INTO v_class_count
  FROM (
    -- Existing unexpired assignments for this user (excluding the row being
    -- updated, if this is an UPDATE, to avoid double-counting).
    SELECT ara.role_group_id
    FROM admin_role_assignments ara
    WHERE ara.user_id = NEW.user_id
      AND (ara.expires_at IS NULL OR ara.expires_at > now())
      AND (TG_OP = 'INSERT' OR ara.id <> NEW.id)
    UNION ALL
    -- The NEW row itself.
    SELECT NEW.role_group_id
  ) combined
  JOIN admin_role_groups rg ON rg.id = combined.role_group_id
  WHERE rg.sod_class IS NOT NULL;

  IF v_class_count > 1 THEN
    RAISE EXCEPTION
      'SoD class conflict: assigning this role would give principal (user_id=%) '
      'assignments spanning % distinct 等保 classes. Under dengbao.sod_mode a '
      'principal may hold roles of at most one class (system / security / audit).',
      NEW.user_id, v_class_count
      USING ERRCODE = 'BZ001';
  END IF;

  RETURN NEW;
END;
$$;

-- Drop any pre-existing trigger (idempotent re-apply).
DROP TRIGGER IF EXISTS trg_sod_exclusion ON public.admin_role_assignments;

CREATE TRIGGER trg_sod_exclusion
  BEFORE INSERT OR UPDATE ON public.admin_role_assignments
  FOR EACH ROW EXECUTE FUNCTION public.sod_exclusion_guard();


-- ── Schema migration record ────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (19, now())
  ON CONFLICT (version) DO NOTHING;
