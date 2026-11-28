-- V219__exchange_assessment_sod_perm_map.sql — add the Exchange assessment
-- permission family to sod_exclusion_guard() for existing installations.
-- V100 is immutable and already applied, so the complete function body is
-- replaced here to keep fresh installs and upgrades equivalent.

CREATE OR REPLACE FUNCTION public.sod_exclusion_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  v_class_count         int;
  v_new_role_class_span int;
BEGIN
  IF NOT COALESCE(
       (SELECT enabled FROM feature_toggles WHERE key = 'dengbao.sod_mode'),
       false
     ) THEN
    RETURN NEW;
  END IF;

  SELECT COUNT(DISTINCT rg.sod_class) INTO v_class_count
  FROM (
    SELECT ara.role_group_id
    FROM admin_role_assignments ara
    WHERE ara.user_id = NEW.user_id
      AND (ara.expires_at IS NULL OR ara.expires_at > now())
      AND (TG_OP = 'INSERT' OR ara.id <> NEW.id)
    UNION ALL
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
      ('mam.read',            'audit'),
      ('mail.offline_policy', 'system'),
      ('scope_sets.manage',   'security'),
      ('approvals.view',      'security'),
      ('approvals.manage',    'security'),
      ('sharing.read',        'security'),
      ('sharing.manage',      'security'),
      ('access.policy_read',  'security'),
      ('access.policy_write', 'security'),
      ('exchange.assessment.read',    'system'),
      ('exchange.assessment.read',    'security'),
      ('exchange.assessment.read',    'audit'),
      ('exchange.assessment.run',     'system'),
      ('exchange.assessment.decide',  'security'),
      ('exchange.assessment.attest',  'audit'),
      ('exchange.assessment.audit',   'audit'),
      ('exchange.assessment.publish', 'security'),
      ('exchange.assessment.delete',  'system')
  ) AS pcm(perm, sod_class) ON pcm.perm = p.perm
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
        ('mam.read',            'audit'),
        ('mail.offline_policy', 'system'),
        ('scope_sets.manage',   'security'),
        ('approvals.view',      'security'),
        ('approvals.manage',    'security'),
        ('sharing.read',        'security'),
        ('sharing.manage',      'security'),
        ('access.policy_read',  'security'),
        ('access.policy_write', 'security'),
        ('exchange.assessment.read',    'system'),
        ('exchange.assessment.read',    'security'),
        ('exchange.assessment.read',    'audit'),
        ('exchange.assessment.run',     'system'),
        ('exchange.assessment.decide',  'security'),
        ('exchange.assessment.attest',  'audit'),
        ('exchange.assessment.audit',   'audit'),
        ('exchange.assessment.publish', 'security'),
        ('exchange.assessment.delete',  'system')
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

DROP TRIGGER IF EXISTS trg_sod_exclusion ON public.admin_role_assignments;

CREATE TRIGGER trg_sod_exclusion
  BEFORE INSERT OR UPDATE ON public.admin_role_assignments
  FOR EACH ROW EXECUTE FUNCTION public.sod_exclusion_guard();

INSERT INTO public.schema_migrations (version, applied_at) VALUES (219, now())
  ON CONFLICT (version) DO NOTHING;
