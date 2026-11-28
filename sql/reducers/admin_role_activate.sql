-- admin_role_activate: self-service JIT activation. The actor activates their OWN
-- eligible assignment for a bounded window: duration clamped to the role's policy max
-- (or the global system_config default), justification enforced if the policy requires,
-- activated_until capped at the assignment's expires_at. Audited tier=core. Lazy expiry
-- (no worker) — admin_assignment_active compares activated_until > now().
-- Errors: BZ104 (JIT off or no eligible assignment for actor), BZ105 (justification required).
-- Returns NULL when approval.rbac is on and the role's policy has require_approval=true —
-- a pending approval request was created; the Go caller treats NULL as pending-approval.
CREATE OR REPLACE FUNCTION admin_role_activate(
  p_actor          bigint,
  p_role_group_id  bigint,
  p_duration_minutes integer,
  p_justification  text
) RETURNS timestamptz AS $$
DECLARE
  v_max      int;
  v_req      boolean;
  v_approval boolean := false;
  v_aspec    jsonb;
  v_until    timestamptz;
  v_kind     text;
  v_ref      bigint;
  v_skip     boolean;
  v_ttl      int;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key = 'rbac.jit'), false) THEN
    RAISE EXCEPTION 'JIT activation is not enabled' USING ERRCODE = 'BZ104';
  END IF;

  -- must be the actor's OWN eligible assignment
  IF NOT EXISTS (
    SELECT 1 FROM admin_role_assignments
     WHERE user_id = p_actor AND role_group_id = p_role_group_id AND eligible = true
  ) THEN
    RAISE EXCEPTION 'no eligible assignment for this role' USING ERRCODE = 'BZ104';
  END IF;

  -- policy: per-role override else global defaults from system_config
  SELECT max_duration_minutes, require_justification, require_approval, approver_spec
    INTO v_max, v_req, v_approval, v_aspec
    FROM admin_role_activation_policy WHERE role_group_id = p_role_group_id;
  IF NOT FOUND THEN
    v_max      := COALESCE((SELECT (value ->> 0)::int  FROM system_config WHERE key = 'jit.default_max_minutes'),          480);
    v_req      := COALESCE((SELECT (value ->> 0)::bool FROM system_config WHERE key = 'jit.default_require_justification'), false);
    v_approval := false;
    v_aspec    := NULL;
  END IF;

  IF v_req AND (p_justification IS NULL OR btrim(p_justification) = '') THEN
    RAISE EXCEPTION 'a justification is required to activate this role' USING ERRCODE = 'BZ105';
  END IF;

  -- approval gate: when approval.rbac is on AND the policy requires approval,
  -- park a request instead of opening the window.  RETURN NULL signals "pending".
  IF COALESCE((SELECT enabled FROM feature_toggles WHERE key = 'approval.rbac'), false)
     AND v_approval THEN
    SELECT kind, ref, skip
      INTO v_kind, v_ref, v_skip
      FROM approval_resolve_approver(p_actor, v_aspec);
    IF NOT COALESCE(v_skip, false) THEN
      v_ttl := COALESCE(
        (SELECT (value #>> '{}')::int FROM system_config WHERE key = 'approval.request_ttl_minutes'),
        2880
      );
      PERFORM approval_request_create(
        'rbac.jit_activation',
        p_actor,
        'Activate ' || (SELECT name FROM admin_role_groups WHERE id = p_role_group_id),
        jsonb_build_object(
          'role_group_id',     p_role_group_id,
          'duration_minutes',  p_duration_minutes,
          'justification',     p_justification
        ),
        NULL,
        v_kind,
        v_ref,
        v_ttl
      );
      RETURN NULL;
    END IF;
    -- skip=true: fall through to immediate self-service activation
  END IF;

  -- window-open (non-approval path, or skip-terminal approval spec)
  v_until := admin_role_window_open(p_actor, p_role_group_id, p_duration_minutes);

  PERFORM audit_write(
    p_actor,
    'role_activated',
    'role_assignment',
    p_role_group_id,
    NULL,
    jsonb_build_object(
      'activatedUntil',   v_until,
      'durationMinutes',  LEAST(GREATEST(p_duration_minutes, 1), v_max),
      'justification',    p_justification
    ),
    NULL,
    COALESCE(p_justification, ''),
    'core'
  );

  RETURN v_until;
END;
$$ LANGUAGE plpgsql VOLATILE;
