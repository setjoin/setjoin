-- ════════════════════════════════════════════════════════════════════════
-- V089__sharing_defaults.sql — sharing & delegation permissions (Spec 2).
-- Spec: docs/superpowers/specs/2026-06-27-sharing-delegation-design.md §4.
--
-- The default-scope policy layer: org/OU/group/user default CALENDAR
-- visibility (D2: calendar-only — no mailbox default layer), layered UNDER
-- explicit calendar_acls grants (D5). Resolution = most-specific-wins across
-- tiers, most-permissive within a tier (D4); fail-closed to 'none' (D10).
-- Behaviorally inert until the 'sharing.defaults' toggle (seeded OFF below)
-- is flipped (D11) — calendar_effective_acl short-circuits to explicit grants.
--
-- owner_scope × owner_ref — WHOSE calendar the default applies to:
--   org   → domain_id (D7: org scope is domain-scoped)
--   ou    → department_id
--   group → distribution_group id
--   user  → user_id (the owner's self-set default / opt-out, D5)
-- audience × audience_ref — WHO may see:
--   everyone → domain_id (D7: "everyone" means everyone in the OWNER's domain)
--   ou       → department_id
--   group    → distribution_group id
-- level — 无 none / 闲忙 freebusy / 详细 read (reuses the calendar_acls enum
-- subset; write/admin are explicit-grant-only, never a default).
-- ════════════════════════════════════════════════════════════════════════

CREATE TABLE public.sharing_defaults (
  id            bigserial PRIMARY KEY,
  resource      text   NOT NULL CHECK (resource = 'calendar'),          -- v1: calendar only (D2)
  owner_scope   text   NOT NULL CHECK (owner_scope IN ('org','ou','group','user')),
  owner_ref     bigint NOT NULL,
  audience      text   NOT NULL CHECK (audience IN ('everyone','ou','group')),
  audience_ref  bigint NOT NULL,
  level         text   NOT NULL CHECK (level IN ('none','freebusy','read')),
  created_by    bigint NOT NULL REFERENCES public.users(id),
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (resource, owner_scope, owner_ref, audience, audience_ref)     -- one rule per (scope-target, audience)
);
CREATE INDEX sharing_defaults_owner_idx ON public.sharing_defaults (owner_scope, owner_ref);

-- ── Native-RLS backstop (R4) — ENABLE+FORCE, V080/V073 latent posture ───────
-- INERT for the current superuser/owner pool identity; engages when the prod
-- DSN switches to setjoin_app (docs/standards/DATABASE_SECURITY.md deploy gate).
-- The real auth ladder is ALSO enforced inside the reducers (BZ116), §8.
ALTER TABLE public.sharing_defaults ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sharing_defaults FORCE  ROW LEVEL SECURITY;

-- Read: any authenticated context (user GUC or mailbox GUC). Rows are
-- org-visible POLICY data, not private content — the (viewer, owner) resolver
-- must read org/ou/group rows and other owners' user-scope rows to answer a
-- visibility question, and the §6-A status line shows users their inherited
-- baseline. Fail-closed: no GUC → no rows.
CREATE POLICY sharing_defaults_read ON public.sharing_defaults
  FOR SELECT TO public
  USING (
    (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint) IS NOT NULL
    OR (SELECT NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint) IS NOT NULL
  );

-- Write: the owner mutates their own user-scope rows (self-default, D5).
CREATE POLICY sharing_defaults_self_write ON public.sharing_defaults
  FOR ALL TO public
  USING (
    owner_scope = 'user'
    AND owner_ref = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
  )
  WITH CHECK (
    owner_scope = 'user'
    AND owner_ref = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
  );

-- Write: sharing.manage admins mutate any row (org/ou/group defaults + user
-- overrides, §7). V073 shape: active assignment (jit-gated) carrying the perm.
CREATE POLICY sharing_defaults_admin_write ON public.sharing_defaults
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
        AND 'sharing.manage' = ANY(arg.permissions)
    )
  )
  WITH CHECK (
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
        AND 'sharing.manage' = ANY(arg.permissions)
    )
  );

-- ── Permissions catalog (D9) + Super Admin append (V073 pattern) ─────────────

INSERT INTO public.admin_permissions (permission_key, category, description, is_sensitive)
VALUES
  ('sharing.read',   'Sharing', 'View sharing defaults and who-can-see-what audit',              false),
  ('sharing.manage', 'Sharing', 'Set org/OU/group sharing defaults; override any user''s sharing', true)
ON CONFLICT (permission_key) DO NOTHING;

UPDATE public.admin_role_groups
   SET permissions = (SELECT array_agg(DISTINCT p ORDER BY p)
                        FROM unnest(permissions || ARRAY['sharing.read','sharing.manage']) AS p)
 WHERE id = 1;

-- ── Feature toggle, DEFAULT OFF (D11) — V083 pattern ─────────────────────────

INSERT INTO public.feature_toggles (key, enabled, description) VALUES
  ('sharing.defaults', false, 'Org/OU/group/user default calendar-visibility layer under explicit grants. Seeded OFF; flip deliberately.')
ON CONFLICT (key) DO NOTHING;

INSERT INTO schema_migrations (version, applied_at) VALUES (89, now()) ON CONFLICT DO NOTHING;
