-- admin_role_window_open: open the JIT time-boxed window for a user+role.
-- Shared by admin_role_activate (non-approval path) and rbac_approval_decide (apply path).
-- Duration clamped to policy max (or global default) and capped at the grant's expires_at.
-- Returns the activated_until timestamp written to admin_role_assignments.
CREATE OR REPLACE FUNCTION admin_role_window_open(
  p_user_id          bigint,
  p_role_group_id    bigint,
  p_duration_minutes int
) RETURNS timestamptz AS $$
DECLARE
  v_max     int;
  v_expires timestamptz;
  v_until   timestamptz;
  v_result  timestamptz;
BEGIN
  PERFORM admin_authority_fence();

  SELECT max_duration_minutes INTO v_max
    FROM admin_role_activation_policy WHERE role_group_id = p_role_group_id;
  IF NOT FOUND THEN
    v_max := COALESCE((SELECT (value ->> 0)::int FROM system_config WHERE key = 'jit.default_max_minutes'), 480);
  END IF;

  SELECT expires_at INTO v_expires
    FROM admin_role_assignments WHERE user_id = p_user_id AND role_group_id = p_role_group_id AND eligible = true;

  v_until := now() + make_interval(mins => LEAST(GREATEST(p_duration_minutes, 1), v_max));
  IF v_expires IS NOT NULL AND v_expires < v_until THEN
    v_until := v_expires;
  END IF;

  -- RETURNING yields NULL into v_result when 0 rows match (revoked/expired assignment).
  -- Callers that need to detect the miss check for NULL return.
  UPDATE admin_role_assignments
     SET activated_until = v_until
   WHERE user_id = p_user_id AND role_group_id = p_role_group_id AND eligible = true
  RETURNING activated_until INTO v_result;

  RETURN v_result;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY INVOKER;
