-- Serialize Conditional Access policy validation with every mutation of the
-- admin-reachability graph. V172's fixed advisory-lock key is reused so mixed
-- role/CA transactions have one lock domain and one order.

CREATE OR REPLACE FUNCTION public.ca_reachability_fence()
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  PERFORM public.admin_authority_fence();
END;
$$;

-- Canonical grant type plus retained schema-v1 action compatibility. This
-- definition is included in the forward migration because V001 predates the
-- discriminator-parity repair; reducers remain the canonical replay source.
CREATE OR REPLACE FUNCTION public.ca_grant_discriminators_valid(p_actions jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
  v_grant jsonb;
  v_type text;
  v_action text;
BEGIN
  IF p_actions IS NULL OR NOT (p_actions ? 'grants') THEN
    RETURN true;
  END IF;
  IF jsonb_typeof(p_actions->'grants') <> 'array'
     OR jsonb_array_length(p_actions->'grants') = 0 THEN
    RETURN false;
  END IF;

  FOR v_grant IN SELECT * FROM jsonb_array_elements(p_actions->'grants') LOOP
    IF jsonb_typeof(v_grant) <> 'object' THEN
      RETURN false;
    END IF;
    IF (v_grant ? 'type') AND jsonb_typeof(v_grant->'type') <> 'string' THEN
      RETURN false;
    END IF;
    IF (v_grant ? 'action') AND jsonb_typeof(v_grant->'action') <> 'string' THEN
      RETURN false;
    END IF;

    v_type := NULLIF(v_grant->>'type', '');
    v_action := NULLIF(v_grant->>'action', '');
    IF ((v_grant ? 'type') AND v_type IS NULL)
       OR ((v_grant ? 'action') AND v_action IS NULL) THEN
      RETURN false;
    END IF;
    IF v_type IS NOT NULL AND v_action IS NOT NULL AND v_type <> v_action THEN
      RETURN false;
    END IF;
    IF COALESCE(v_type, v_action) IS NULL
       OR COALESCE(v_type, v_action) IN ('require_terms', 'require_risk_remediation')
       OR COALESCE(v_type, v_action) <> ALL (
         ARRAY['allow','block','step_up','notify','require_acr','require_strength',
               'limited_web','require_terms','require_risk_remediation']
       ) THEN
      RETURN false;
    END IF;
  END LOOP;
  RETURN true;
END;
$$;

CREATE OR REPLACE FUNCTION public.ca_lockout_guard(
  p_state text,
  p_scope_type text,
  p_actions jsonb,
  p_exclude_users jsonb,
  p_exclude_groups jsonb
) RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_break_glass jsonb;
  v_reachable_count integer;
  v_has_dangerous boolean := false;
  v_grant jsonb;
BEGIN
  PERFORM public.ca_reachability_fence();

  IF NOT public.ca_grant_discriminators_valid(p_actions) THEN
    RAISE EXCEPTION 'invalid or conflicting conditional-access grant discriminator'
      USING ERRCODE = '22023',
            HINT = 'use one non-empty grants[].type value, or a matching schema-v1 grants[].action value';
  END IF;

  IF p_state <> 'on' OR p_scope_type <> 'global' THEN
    RETURN;
  END IF;

  v_has_dangerous := COALESCE((p_actions->>'action') IN ('block', 'step_up'), false);
  IF NOT v_has_dangerous AND (p_actions ? 'grants') THEN
    FOR v_grant IN SELECT * FROM jsonb_array_elements(p_actions->'grants') LOOP
      IF COALESCE(NULLIF(v_grant->>'type', ''), v_grant->>'action')
         IN ('block', 'step_up') THEN
        v_has_dangerous := true;
        EXIT;
      END IF;
    END LOOP;
  END IF;
  IF NOT v_has_dangerous THEN
    RETURN;
  END IF;

  SELECT COALESCE(value, '[]'::jsonb)
    INTO v_break_glass
    FROM public.system_config
   WHERE key = 'ca_break_glass_user_ids';
  v_break_glass := COALESCE(v_break_glass, '[]'::jsonb);

  -- A finite expiry or eligible activation window can lapse without a write.
  -- Only permanent, non-JIT assignments are durable lockout escape paths.
  SELECT count(*)
    INTO v_reachable_count
    FROM (
      SELECT DISTINCT ara.user_id
        FROM public.admin_role_assignments ara
        JOIN public.users u ON u.id = ara.user_id AND u.enabled
       WHERE ara.expires_at IS NULL
         AND ara.eligible = false
         AND public.admin_assignment_active(ara.eligible, ara.activated_until)
    ) admins
   WHERE admins.user_id IN (
           SELECT e::bigint FROM jsonb_array_elements_text(p_exclude_users) e
         )
      OR admins.user_id IN (
           SELECT e::bigint FROM jsonb_array_elements_text(v_break_glass) e
         )
      OR EXISTS (
           SELECT 1
             FROM public.user_group_members ugm
            WHERE ugm.user_id = admins.user_id
              AND ugm.group_id IN (
                SELECT e::bigint FROM jsonb_array_elements_text(p_exclude_groups) e
              )
         );

  IF v_reachable_count = 0 THEN
    RAISE EXCEPTION 'global blocking policy would lock out all admins'
      USING ERRCODE = 'BZ080',
            HINT = 'exclude a break-glass admin account (system_config.ca_break_glass_user_ids) or an admin group';
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION public.ca_revalidate_active_lockout_policies()
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_policy public.conditional_access_policies%ROWTYPE;
BEGIN
  PERFORM public.ca_reachability_fence();
  FOR v_policy IN
    SELECT *
      FROM public.conditional_access_policies
     WHERE state = 'on'
       AND scope_type = 'global'
       AND deleted_at IS NULL
     ORDER BY id
  LOOP
    PERFORM public.ca_lockout_guard(
      v_policy.state,
      v_policy.scope_type,
      v_policy.actions,
      v_policy.exclude_users,
      v_policy.exclude_groups
    );
  END LOOP;
END;
$$;

CREATE OR REPLACE FUNCTION public.trg_ca_reachability_fence()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  PERFORM public.ca_reachability_fence();
  RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION public.trg_ca_reachability_revalidate()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  PERFORM public.ca_revalidate_active_lockout_policies();
  RETURN NULL;
END;
$$;

-- BEFORE STATEMENT acquires the fence before row locks. The assignment trigger
-- deliberately reacquires V172's same lock through the named CA helper.
DROP TRIGGER IF EXISTS trg_ca_reachability_assignments_fence ON public.admin_role_assignments;
CREATE TRIGGER trg_ca_reachability_assignments_fence
  BEFORE INSERT OR UPDATE OR DELETE ON public.admin_role_assignments
  FOR EACH STATEMENT EXECUTE FUNCTION public.trg_ca_reachability_fence();

DROP TRIGGER IF EXISTS trg_ca_reachability_break_glass_fence ON public.system_config;
CREATE TRIGGER trg_ca_reachability_break_glass_fence
  BEFORE INSERT OR UPDATE OR DELETE ON public.system_config
  FOR EACH STATEMENT EXECUTE FUNCTION public.trg_ca_reachability_fence();

DROP TRIGGER IF EXISTS trg_ca_reachability_user_groups_fence ON public.user_group_members;
CREATE TRIGGER trg_ca_reachability_user_groups_fence
  BEFORE INSERT OR UPDATE OR DELETE ON public.user_group_members
  FOR EACH STATEMENT EXECUTE FUNCTION public.trg_ca_reachability_fence();

DROP TRIGGER IF EXISTS trg_ca_reachability_users_fence ON public.users;
CREATE TRIGGER trg_ca_reachability_users_fence
  BEFORE UPDATE OF enabled OR DELETE ON public.users
  FOR EACH STATEMENT EXECUTE FUNCTION public.trg_ca_reachability_fence();

-- Deferred constraint triggers validate the final transaction state, allowing
-- safe remove-then-add replacements while rejecting an unsafe commit.
DROP TRIGGER IF EXISTS trg_ca_reachability_assignments_validate ON public.admin_role_assignments;
CREATE CONSTRAINT TRIGGER trg_ca_reachability_assignments_validate
  AFTER INSERT OR UPDATE OR DELETE ON public.admin_role_assignments
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION public.trg_ca_reachability_revalidate();

DROP TRIGGER IF EXISTS trg_ca_reachability_break_glass_validate ON public.system_config;
CREATE CONSTRAINT TRIGGER trg_ca_reachability_break_glass_validate
  AFTER INSERT OR UPDATE OR DELETE ON public.system_config
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION public.trg_ca_reachability_revalidate();

DROP TRIGGER IF EXISTS trg_ca_reachability_user_groups_validate ON public.user_group_members;
CREATE CONSTRAINT TRIGGER trg_ca_reachability_user_groups_validate
  AFTER INSERT OR UPDATE OR DELETE ON public.user_group_members
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION public.trg_ca_reachability_revalidate();

DROP TRIGGER IF EXISTS trg_ca_reachability_users_validate ON public.users;
CREATE CONSTRAINT TRIGGER trg_ca_reachability_users_validate
  AFTER UPDATE OF enabled OR DELETE ON public.users
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION public.trg_ca_reachability_revalidate();

-- Upgrade gate: policies admitted by the old snapshot-only/looser reachability
-- rule must not survive until an unrelated future mutation happens to recheck
-- them. Fail the migration atomically with BZ080; the operator must turn the
-- unsafe policy off or establish an enabled permanent non-JIT escape admin,
-- then retry the idempotent migration.
SELECT public.ca_revalidate_active_lockout_policies();

INSERT INTO public.schema_migrations(version, applied_at)
VALUES (222, statement_timestamp())
ON CONFLICT (version) DO NOTHING;
