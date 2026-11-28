-- ════════════════════════════════════════════════════════════════════════
-- V024__sod_exclusion_perm_span.sql — fix SoD trigger: reject roles whose
-- permissions span ≥2 exclusive 等保 classes (plugs Super Admin escape).
--
-- BUG (pre-V024): sod_exclusion_guard() only checked the sod_class of the
-- assigned role group, filtering with WHERE rg.sod_class IS NOT NULL.
-- This let Super Admin (id=1, sod_class=NULL) be assigned under SoD ON
-- without raising BZ001, defeating the 三权分立 invariant.
--
-- FIX: also reject when the role being assigned has permissions spanning
-- ≥2 EXCLUSIVE SoD classes (independent of its sod_class column value).
-- "Exclusive" means: a permission that belongs to exactly one class in
-- the PermClasses map; read-overlap perms (users.read, compliance.read)
-- appear in multiple class allow-lists and are excluded from the span
-- count so they do not false-positive single-class roles.
--
-- The existing assigned-class-union check is RETAINED and fires
-- independently. Both checks can raise BZ001. The OFF no-op path is
-- unchanged: COALESCE → false when the toggle row is absent.
--
-- Mirrors the exclusive_class_count logic from admin_sod_precheck.sql.
-- ════════════════════════════════════════════════════════════════════════

CREATE OR REPLACE FUNCTION public.sod_exclusion_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  v_class_count         int;
  v_new_role_class_span int;
BEGIN
  -- Fast path: treat missing or NULL toggle row as OFF.
  IF NOT COALESCE(
       (SELECT enabled FROM feature_toggles WHERE key = 'dengbao.sod_mode'),
       false
     ) THEN
    RETURN NEW;
  END IF;

  -- ── Check 1 (existing): assigned-class union ─────────────────────────────
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

  -- ── Check 2 (new): perm-span on the role being assigned ─────────────────
  -- Reject when the role's own permissions span ≥2 exclusive SoD classes.
  -- This catches NULL-sod_class roles like Super Admin that hold permissions
  -- drawn from genuinely separate exclusive classes.
  --
  -- "Exclusive class" = a class reachable only via perms that belong to
  -- exactly ONE class in the map (excludes read-overlap perms users.read
  -- and compliance.read which appear in multiple class allow-lists).
  --
  -- perm_class_map mirrors PermClasses in shared/permissions/classes.go.
  -- Read-overlap perms (users.read, compliance.read) are listed in multiple
  -- rows and therefore have count(*) > 1 in the subquery; the WHERE clause
  -- excludes them from the exclusive-class count.
  SELECT COUNT(DISTINCT pcm.sod_class) INTO v_new_role_class_span
  FROM unnest((
    SELECT permissions FROM admin_role_groups WHERE id = NEW.role_group_id
  )) AS p(perm)
  JOIN (
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
      ('mam.read',            'audit')
  ) AS pcm(perm, sod_class) ON pcm.perm = p.perm
  -- Only count classes reachable via exclusively-classed perms (count=1 in
  -- the map means the perm belongs to exactly one class).
  WHERE (
    SELECT COUNT(*) FROM (
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
        ('mam.read',            'audit')
    ) AS pcm2(perm2, cls2)
    WHERE pcm2.perm2 = pcm.perm
  ) = 1;

  IF v_new_role_class_span >= 2 THEN
    RAISE EXCEPTION
      'SoD class conflict: role (role_group_id=%) has permissions spanning % exclusive '
      '等保 classes. Under dengbao.sod_mode only single-class roles (system / security / '
      'audit) may be assigned.',
      NEW.role_group_id, v_new_role_class_span
      USING ERRCODE = 'BZ001';
  END IF;

  RETURN NEW;
END;
$$;

-- The trigger definition is unchanged (BEFORE INSERT OR UPDATE, FOR EACH ROW).
-- Re-create it idempotently so V024 is safe to re-apply.
DROP TRIGGER IF EXISTS trg_sod_exclusion ON public.admin_role_assignments;

CREATE TRIGGER trg_sod_exclusion
  BEFORE INSERT OR UPDATE ON public.admin_role_assignments
  FOR EACH ROW EXECUTE FUNCTION public.sod_exclusion_guard();


-- ── Schema migration record ────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (24, now())
  ON CONFLICT (version) DO NOTHING;
