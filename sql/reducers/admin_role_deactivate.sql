-- admin_role_deactivate: the actor ends their own active JIT window early.
-- NULLs activated_until on the actor's own eligible assignment. Audited tier=core.
CREATE OR REPLACE FUNCTION admin_role_deactivate(
  p_actor         bigint,
  p_role_group_id bigint
) RETURNS void AS $$
DECLARE
  v_n INT;
BEGIN
  PERFORM admin_authority_fence();

  UPDATE admin_role_assignments
     SET activated_until = NULL
   WHERE user_id = p_actor AND role_group_id = p_role_group_id AND eligible = true;

  -- Only audit a deactivation that actually happened. A 0-row UPDATE (no eligible
  -- assignment / wrong role id) must NOT record a tier=core 'role_deactivated' that
  -- did not occur.
  GET DIAGNOSTICS v_n = ROW_COUNT;
  IF v_n > 0 THEN
    PERFORM audit_write(
      p_actor,
      'role_deactivated',
      'role_assignment',
      p_role_group_id,
      NULL,
      NULL,
      NULL,
      NULL,
      'core'
    );
  END IF;
END;
$$ LANGUAGE plpgsql VOLATILE;
