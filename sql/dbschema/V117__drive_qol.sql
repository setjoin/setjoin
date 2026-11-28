-- V117__drive_qol.sql — Drive P6: two-level trash columns + drive_audit_alarms.
-- Spec: docs/superpowers/specs/2026-07-09-drive-v1-spec.md §2.4, §3.5, §9.3.
-- Plan: docs/superpowers/plans/archive/2026-07-09-drive-P6-qol-audit.md Task 1
-- (AUTOPLAN batch-2 blockers #1/#2 + non-blocking #8 folded — see inline notes).

-- Two-level trash (二级回收站): tier 1 = deleted_at (user bin, restorable by
-- editors, P1-shipped); tier 2 = purged_at (admin bin: manager destroyed or
-- 30-day aged-out — drive.manage-recoverable for a 30-day grace, then
-- hard-destroyed by the maintenance sweep, P6 Task 4).
-- ponytail: columns on drive_nodes, not a copy table — the tree stays intact
-- for restore-to-original-path; a separate drive_trash table would duplicate
-- the subtree.
-- AUTOPLAN batch-2 #8: purged_by stays nullable — NULL = system/aged-out
-- (Task 4's sweep), not a manager action.
ALTER TABLE public.drive_nodes
    ADD COLUMN purged_at timestamptz,
    ADD COLUMN purged_by bigint REFERENCES public.users(id);

-- The admin console + sweep scan tier 2 per space; live queries are untouched.
CREATE INDEX drive_nodes_purged_idx
    ON public.drive_nodes (space_id, purged_at) WHERE purged_at IS NOT NULL;

-- AUTOPLAN batch-2 BLOCKER #1: the V114 policy names are drive_nodes_read /
-- drive_nodes_write (V114 §C, lines 305/307) — NOT drive_nodes_member_select
-- / _member_write; a DROP against those names would fail at apply time. The
-- recreated bodies keep P1's Locked-resolution-R1 shape
-- (public.drive_member_role(space_id, <GUC>)), not an inline
-- drive_space_members subquery (that re-enters drive_space_members' own
-- RLS-expressed-in-terms-of-the-same-predicate policies — infinite
-- recursion under FORCE).
-- The purged gate lives in USING ONLY: a WITH CHECK purged_at IS NULL would
-- reject the very "UPDATE ... SET purged_at = now()" the flipped destroy
-- reducer performs (Task 2) once the native-RLS DSN flip binds — the
-- transition row is non-NULL on the NEW side by definition. USING alone
-- still keeps tier-2 rows invisible to every member SELECT/UPDATE/DELETE
-- target (a member can never re-target a purged row, un-purge included).
DROP POLICY drive_nodes_read  ON public.drive_nodes;
DROP POLICY drive_nodes_write ON public.drive_nodes;
CREATE POLICY drive_nodes_read ON public.drive_nodes FOR SELECT TO public
  USING (purged_at IS NULL AND public.drive_member_role(space_id,
         (SELECT NULLIF(current_setting('app.current_user_id', true),'')::bigint)) IS NOT NULL);
CREATE POLICY drive_nodes_write ON public.drive_nodes FOR ALL TO public
  USING (purged_at IS NULL AND public.drive_member_role(space_id,
         (SELECT NULLIF(current_setting('app.current_user_id', true),'')::bigint)) IN ('manager','editor'))
  WITH CHECK (public.drive_member_role(space_id,
         (SELECT NULLIF(current_setting('app.current_user_id', true),'')::bigint)) IN ('manager','editor'));
-- Tier-2 reads/writes happen ONLY via the SECURITY DEFINER pair (Task 3) and
-- the BYPASSRLS worker pool — no member policy ever exposes a purged row.

CREATE TABLE public.drive_audit_alarms (           -- §9.3 alarm layer
    id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    space_id       bigint REFERENCES public.drive_spaces(id),   -- NULL = all spaces
    action_pattern text   NOT NULL CHECK (length(action_pattern) BETWEEN 1 AND 60),
                                  -- exact action or prefix + '*' ('export.deny', 'lock.*')
    threshold      int    NOT NULL DEFAULT 5 CHECK (threshold >= 1),
    window_minutes int    NOT NULL DEFAULT 10 CHECK (window_minutes BETWEEN 1 AND 1440),
    enabled        boolean NOT NULL DEFAULT true,
    created_by     bigint REFERENCES public.users(id),   -- NULL = system-seeded (batch-2 #8)
    created_at     timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.drive_audit_alarms ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.drive_audit_alarms FORCE  ROW LEVEL SECURITY;

-- AUTOPLAN batch-2 BLOCKER #2: drive_has_admin_perm is defined in the V114
-- migration §B (not a reducer), so it already exists at V117 apply time in
-- load-test-schema.sh — the inline-JIT-clause fallback (Global Constraints,
-- "reducer helpers load AFTER migrations") does not apply to this helper.
-- Using the worker-owned DEFINER helper also avoids FORCE-starving
-- setjoin_app on a direct admin_role_assignments/admin_role_groups read
-- inside the policy — the exact reason P1 made the helper worker-owned
-- DEFINER in the first place.
CREATE POLICY drive_audit_alarms_admin ON public.drive_audit_alarms
  FOR ALL TO public
  USING (public.drive_has_admin_perm(
    (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint), 'drive.manage'))
  WITH CHECK (public.drive_has_admin_perm(
    (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint), 'drive.manage'));

-- Seed: the denied-export storm detector (§9.3), org-wide.
-- AUTOPLAN batch-2 #8: "FROM users ORDER BY id LIMIT 1" inserts ZERO rows on
-- a fresh install (no users exist yet at migration time) — the storm
-- detector would silently never exist on new deployments. created_by NULL
-- = system-seeded; recorded as a §2.4 spec delta in Task 18.
INSERT INTO public.drive_audit_alarms (space_id, action_pattern, threshold, window_minutes, created_by)
VALUES (NULL, 'export.deny', 5, 10, NULL);

INSERT INTO schema_migrations (version, applied_at) VALUES (117, now())
ON CONFLICT (version) DO NOTHING;
