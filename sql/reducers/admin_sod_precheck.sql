-- ════════════════════════════════════════════════════════════════════════
-- admin_sod_precheck.sql — 等保三级 SoD OFF→ON enablement gate
--
-- One-shot pre-flight scan called inside the same transaction as the
-- dengbao.sod_mode OFF→ON flip.  Reports every obstruction that would
-- violate 三权分立 invariants BEFORE the flip commits.
--
-- NOT for request-path use.  Call it once; fix the violations it reports;
-- retry the flip.
--
-- Returns: TABLE(violation_type text, subject text, detail text)
--   violation_type ∈ { cross_class, unclassified_role, super_admin_role,
--                      unclassifiable_perm }
--
-- Priority (mutually exclusive per subject — highest wins):
--   1. cross_class        — principal already spans ≥2 classes
--   2. super_admin_role   — role group spans ≥2 exclusive classes
--   3. unclassifiable_perm — role group holds a no-class perm (mutually exclusive
--                            with super_admin_role; role_violations_fine assigns
--                            exactly one type per role by priority)
--   4. unclassified_role  — role group has NULL sod_class
--
-- The legacy_admin_role axis was RETIRED by the RBAC cut-over: users.admin_role
-- was dropped, so there is no enum to be "legacy" against. Every admin's
-- authority now flows through governed admin_role_assignments — the only axis
-- this gate scans. (is_admin is retained as authn context but no longer feeds an
-- SoD violation: a bare is_admin with no governed row resolves to an empty perm
-- set and is denied everywhere, so it can grant nothing to violate against.)
--
-- A "no-class permission" is any permission absent from the PermClasses map
-- (shared/permissions/classes.go): users.impersonate.
-- These may never appear in a classed role — their presence makes a role
-- unclassifiable.
--
-- Expired assignments (expires_at ≤ now()) are ignored everywhere.
-- ════════════════════════════════════════════════════════════════════════

CREATE OR REPLACE FUNCTION admin_sod_precheck()
RETURNS TABLE(violation_type text, subject text, detail text)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
  -- ── The class-map lives in Go (shared/permissions/classes.go); replicate
  -- the no-class set here.  A perm is no-class when it is absent from the map.
  -- Known classed perms (from PermClasses): all others are no-class.
  -- The only catalogued no-class perm is: users.impersonate.
  --
  -- Implementation: build the classed-perm set inline and flag any role perm
  -- NOT IN that set as a no-class perm.

  RETURN QUERY
  WITH
  -- ── 1. Per-role violation classification ─────────────────────────────────
  --
  -- classed_perms: the canonical set of perms that appear in PermClasses.
  -- Built as a subquery constant so it is evaluated once.
  classed_perms(perm) AS (
    VALUES
      ('users.read'),
      ('users.create'),
      ('users.delete'),
      ('users.suspend'),
      ('users.password_reset'),
      ('domains.read'),
      ('domains.write'),
      ('queue.read'),
      ('queue.write'),
      ('backup.read'),
      ('backup.write'),
      ('system.config'),
      ('system.upgrade'),
      ('mail.pipeline'),
      ('mail.security'),
      ('reports.read'),
      ('roles.manage'),
      ('security.write'),
      ('identity.write'),
      ('mam.read'),
      ('mam.write'),
      ('compliance.read'),
      ('compliance.write'),
      ('audit.read'),
      ('audit.export'),
      ('mail.offline_policy'),
      ('scope_sets.manage'),
      ('approvals.view'),
      ('approvals.manage'),
      ('sharing.read'),
      ('sharing.manage'),
      ('access.policy_read'),
      ('access.policy_write'),
      ('exchange.assessment.read'),
      ('exchange.assessment.run'),
      ('exchange.assessment.decide'),
      ('exchange.assessment.attest'),
      ('exchange.assessment.audit'),
      ('exchange.assessment.publish'),
      ('exchange.assessment.delete')
  ),

  -- perm → class mapping (mirrors PermClasses; read-overlaps included).
  -- Only classed perms appear here; no-class perms are absent.
  perm_class_map(perm, sod_class) AS (
    VALUES
      ('users.read',          'system'),
      ('users.read',          'security'),
      ('users.read',          'audit'),
      ('users.create',        'system'),
      ('users.delete',        'system'),
      ('domains.read',        'system'),
      ('domains.write',       'system'),
      ('queue.read',          'system'),
      ('queue.write',         'system'),
      ('backup.read',         'system'),
      ('backup.write',        'system'),
      ('system.config',       'system'),
      ('system.upgrade',      'system'),
      ('mail.pipeline',       'system'),
      ('reports.read',        'system'),
      ('users.suspend',       'security'),
      ('users.password_reset','security'),
      ('roles.manage',        'security'),
      ('security.write',      'security'),
      ('mail.security',       'security'),
      ('identity.write',      'security'),
      ('mam.write',           'security'),
      ('compliance.write',    'security'),
      ('compliance.read',     'security'),
      ('compliance.read',     'audit'),
      ('audit.read',          'audit'),
      ('audit.export',        'audit'),
      ('mam.read',            'audit'),
      ('mail.offline_policy', 'system'),
      ('scope_sets.manage',   'security'),
      ('approvals.view',      'security'),
      ('approvals.manage',    'security'),
      ('exchange.assessment.read',    'system'),
      ('exchange.assessment.read',    'security'),
      ('exchange.assessment.read',    'audit'),
      ('exchange.assessment.run',     'system'),
      ('exchange.assessment.decide',  'security'),
      ('exchange.assessment.attest',  'audit'),
      ('exchange.assessment.audit',   'audit'),
      ('exchange.assessment.publish', 'security'),
      ('exchange.assessment.delete',  'system'),
      ('sharing.read',        'security'),
      ('sharing.manage',      'security'),
      ('access.policy_read',  'security'),
      ('access.policy_write', 'security')
  ),

  -- ── 2. Per-role: no-class perm presence flag + distinct-class count ────
  --
  -- A role "spans" classes based only on its EXCLUSIVE perms — the three
  -- read-overlapping perms (users.read, compliance.read) count toward all
  -- their classes.  A role holding ONLY users.read spans all three classes
  -- in the map, but users.read IS in every class's allow-list so it does not
  -- constitute a cross-class violation at the role level.  We compute
  -- "exclusive classes" — classes reachable via perms that belong to exactly
  -- ONE class — to detect roles like Super Admin that hold perms from
  -- genuinely separate exclusive classes.
  --
  -- However, the spec says: "spans ≥2 classes OR holds a no-class perm."
  -- We implement: count distinct classes from perm_class_map for the role's
  -- perms, using DISTINCT ON each perm→class mapping.  Read-overlaps
  -- contribute their multiple classes, but the 3 等保 preset roles are
  -- intentionally single-class after the §5.2 allow-lists are applied, so
  -- they will NOT be flagged (verified by the false-positive guard tests).

  role_perm_facts AS (
    SELECT
      rg.id                                          AS role_id,
      rg.name                                        AS role_name,
      rg.sod_class                                   AS role_sod_class,
      -- Does this role hold any no-class perm?
      EXISTS (
        SELECT 1
          FROM unnest(rg.permissions) AS p(perm)
         WHERE p.perm NOT IN (SELECT cp.perm FROM classed_perms cp)
      )                                              AS has_noclass_perm,
      -- How many distinct SoD classes do this role's perms map to?
      (
        SELECT COUNT(DISTINCT pcm.sod_class)
          FROM unnest(rg.permissions) AS p(perm)
          JOIN perm_class_map pcm ON pcm.perm = p.perm
      )                                              AS perm_class_count,
      -- Are there perms from ≥2 EXCLUSIVE classes (each class reachable only
      -- via a perm that belongs to exactly one class)?
      (
        SELECT COUNT(DISTINCT pcm.sod_class)
          FROM unnest(rg.permissions) AS p(perm)
          JOIN perm_class_map pcm ON pcm.perm = p.perm
         WHERE (
           SELECT COUNT(*) FROM perm_class_map pcm2 WHERE pcm2.perm = p.perm
         ) = 1
      )                                              AS exclusive_class_count
    FROM admin_role_groups rg
  ),

  -- Per-role violation type (highest priority for that role), assigned by
  -- role_violations_fine.  Three mutually exclusive buckets:
  --   super_admin_role    : exclusive_class_count ≥ 2
  --   unclassifiable_perm : has_noclass_perm (only) AND exclusive_class_count < 2
  --   unclassified_role   : role_sod_class IS NULL
  role_violations_fine AS (
    SELECT
      rpf.role_id,
      rpf.role_name,
      CASE
        WHEN rpf.exclusive_class_count >= 2
          THEN 'super_admin_role'
        WHEN rpf.has_noclass_perm
          THEN 'unclassifiable_perm'
        WHEN rpf.role_sod_class IS NULL
          THEN 'unclassified_role'
        ELSE NULL
      END AS role_violation_type
    FROM role_perm_facts rpf
  ),

  -- ── 3. Unexpired assignments JOIN role violation facts ────────────────────
  active_assignments AS (
    SELECT
      ara.user_id,
      u.username                  AS username,
      ara.role_group_id,
      rvf.role_violation_type,
      rvf.role_name,
      rg.sod_class                AS assigned_class
    FROM admin_role_assignments ara
    JOIN users u               ON u.id = ara.user_id
    JOIN admin_role_groups rg  ON rg.id = ara.role_group_id
    JOIN role_violations_fine rvf ON rvf.role_id = ara.role_group_id
    WHERE (ara.expires_at IS NULL OR ara.expires_at > now())
  ),

  -- ── 4. Per-principal: does this user hold unexpired assignments spanning
  --       ≥2 distinct NON-NULL sod_class values? (cross_class)
  principal_class_counts AS (
    SELECT
      ara.user_id,
      u.username,
      COUNT(DISTINCT rg.sod_class) AS class_count
    FROM admin_role_assignments ara
    JOIN users u              ON u.id = ara.user_id
    JOIN admin_role_groups rg ON rg.id = ara.role_group_id
    WHERE (ara.expires_at IS NULL OR ara.expires_at > now())
      AND rg.sod_class IS NOT NULL
    GROUP BY ara.user_id, u.username
  ),

  -- ── 5. Build per-(principal, role) candidate violations, then pick the
  --       highest-priority one per principal.
  --
  -- Priority order (numeric): 1=cross_class, 2=super_admin_role,
  --   3=unclassifiable_perm, 4=unclassified_role.
  candidate_violations AS (
    -- (A) cross_class — principal spans ≥2 classes
    SELECT
      1                                             AS priority,
      'cross_class'::text                          AS v_type,
      pcc.username                                  AS v_subject,
      format(
        'Principal holds unexpired role assignments spanning %s distinct 等保 classes.',
        pcc.class_count
      )                                             AS v_detail
    FROM principal_class_counts pcc
    WHERE pcc.class_count >= 2

    UNION ALL

    -- (B) Role-level violations (super_admin_role, unclassifiable_perm,
    --     unclassified_role) — only emit for principals who are NOT already
    --     flagged as cross_class (priority suppression is applied later, but
    --     we include them so DISTINCT ON can choose).
    SELECT
      CASE aa.role_violation_type
        WHEN 'super_admin_role'    THEN 2
        WHEN 'unclassifiable_perm' THEN 3
        WHEN 'unclassified_role'   THEN 4
      END                                           AS priority,
      aa.role_violation_type                        AS v_type,
      aa.username                                   AS v_subject,
      CASE aa.role_violation_type
        WHEN 'super_admin_role' THEN
          format(
            'Role "%s" spans multiple 等保 classes or holds a no-class permission (users.impersonate).',
            aa.role_name
          )
        WHEN 'unclassifiable_perm' THEN
          format(
            'Role "%s" holds a no-class permission (users.impersonate) and cannot be assigned under 等保三级 mode.',
            aa.role_name
          )
        WHEN 'unclassified_role' THEN
          format(
            'Role "%s" has no sod_class set; every role must carry system / security / audit under 等保三级 mode.',
            aa.role_name
          )
      END                                           AS v_detail
    FROM active_assignments aa
    WHERE aa.role_violation_type IS NOT NULL
  ),

  -- ── 6. Per principal: keep only the highest-priority violation (lowest
  --       priority integer = highest severity).
  ranked_violations AS (
    SELECT DISTINCT ON (v_subject)
      v_type,
      v_subject,
      v_detail
    FROM candidate_violations
    ORDER BY v_subject, priority ASC
  ),

  -- ── 7. (retired) The legacy admin_role axis was removed by the RBAC
  --       cut-over: users.admin_role no longer exists, so there is no enum
  --       to scan for an ungoverned bypass. Authority flows exclusively
  --       through admin_role_assignments (scanned by CTEs 3–6); a bare
  --       is_admin with no governed row resolves to an empty perm set and is
  --       denied everywhere, granting nothing that could violate SoD.

  -- ── 8. Role-level violations emitted as role-centric rows (for roles with
  --       no principal currently assigned to them — still a violation if the
  --       role exists and is mis-classified).
  --       We emit these keyed on the role NAME as subject.
  --       Principals assigned to violating roles are already covered above.
  --       A bare role row with no assignments still violates the invariant.
  role_only_violations AS (
    SELECT
      CASE rvf.role_violation_type
        WHEN 'super_admin_role'    THEN 'super_admin_role'::text
        WHEN 'unclassifiable_perm' THEN 'unclassifiable_perm'::text
        WHEN 'unclassified_role'   THEN 'unclassified_role'::text
      END AS v_type,
      rvf.role_name AS v_subject,
      CASE rvf.role_violation_type
        WHEN 'super_admin_role' THEN
          format(
            'Role group "%s" spans multiple 等保 classes or holds a no-class permission; it cannot exist under 等保三级 mode.',
            rvf.role_name
          )
        WHEN 'unclassifiable_perm' THEN
          format(
            'Role group "%s" holds a no-class permission (users.impersonate); it must be cleaned up before enabling 等保三级 mode.',
            rvf.role_name
          )
        WHEN 'unclassified_role' THEN
          format(
            'Role group "%s" has no sod_class; every role must carry system / security / audit under 等保三级 mode.',
            rvf.role_name
          )
      END AS v_detail
    FROM role_violations_fine rvf
    WHERE rvf.role_violation_type IS NOT NULL
      -- Exclude roles that are already surfaced via a principal (assignment axis).
      AND NOT EXISTS (
        SELECT 1
          FROM active_assignments aa
         WHERE aa.role_group_id = rvf.role_id
      )
  )

  -- ── 9. Union all violation streams ───────────────────────────────────────
  SELECT rv.v_type, rv.v_subject, rv.v_detail FROM ranked_violations rv
  UNION ALL
  SELECT rov.v_type, rov.v_subject, rov.v_detail FROM role_only_violations rov;
END;
$$;
