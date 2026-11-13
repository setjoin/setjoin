-- approval_resolve_approver: turn an approver_spec (from approval_policies.approver_spec)
-- into a concrete (kind, ref) pair for the caller to snapshot into approval_requests.
-- FAIL-CLOSED: never raises; exhausted chain / NULL manager → approval.default_approver_user_id.
-- BZ109 is spec-reserved but unreachable given the fail-closed guarantee (§11).
-- Kinds: manager → walk manager_id FK + optional fallback chain; named → user_id;
--        role_group → role_group_id. skip terminal → (NULL, NULL, skip=true).
-- OOO entrust (QoL #23): a resolution to a concrete 'user' is rerouted to that user's
-- active approval delegate at resolution time (before snapshot) — see the tail below.
CREATE OR REPLACE FUNCTION approval_resolve_approver(
  p_requester     bigint,
  p_approver_spec jsonb
) RETURNS TABLE(kind text, ref bigint, skip boolean) AS $$
DECLARE
  v_kind     text;
  v_manager  bigint;
  v_elem     jsonb;
  v_out_kind text;
  v_out_ref  bigint;
  v_out_skip boolean := false;
BEGIN
  v_kind := p_approver_spec->>'kind';

  IF v_kind = 'named' THEN
    v_out_kind := 'user';
    v_out_ref  := (p_approver_spec->>'user_id')::bigint;

  ELSIF v_kind = 'role_group' THEN
    v_out_kind := 'role_group';
    v_out_ref  := (p_approver_spec->>'role_group_id')::bigint;

  ELSE
    -- kind = 'manager' (or any unknown kind — same fail-closed path): look up the
    -- requester's direct manager.
    SELECT manager_id INTO v_manager FROM users WHERE id = p_requester;
    IF v_manager IS NOT NULL THEN
      v_out_kind := 'user';
      v_out_ref  := v_manager;
    ELSE
      -- manager is NULL: walk fallback[] in order, first match wins.
      FOR v_elem IN SELECT value FROM jsonb_array_elements(p_approver_spec->'fallback') AS value
      LOOP
        IF v_elem->>'kind' = 'skip' THEN
          v_out_skip := true;
          EXIT;
        ELSIF v_elem->>'kind' = 'named' THEN
          v_out_kind := 'user';
          v_out_ref  := (v_elem->>'user_id')::bigint;
          EXIT;
        ELSIF v_elem->>'kind' = 'default_admin' THEN
          v_out_kind := 'user';
          v_out_ref  := (SELECT (value#>>'{}')::bigint FROM system_config WHERE key = 'approval.default_approver_user_id');
          EXIT;
        END IF;
      END LOOP;

      -- chain exhausted (or no fallback key / no matching elem) — fail-closed to default_admin.
      IF v_out_kind IS NULL AND NOT v_out_skip THEN
        v_out_kind := 'user';
        v_out_ref  := (SELECT (value#>>'{}')::bigint FROM system_config WHERE key = 'approval.default_approver_user_id');
      END IF;
    END IF;
  END IF;

  -- OOO entrust (QoL #23): a request resolving to a specific person is rerouted to that
  -- person's active delegate. Only the 'user' kind is substituted — role_group approvers
  -- already share visibility and decide rights, so per-person OOO doesn't apply, and a
  -- skip terminal stays a skip.
  IF v_out_kind = 'user' THEN
    v_out_ref := approval_active_delegate(v_out_ref);
  END IF;

  RETURN QUERY SELECT v_out_kind, v_out_ref, v_out_skip;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY INVOKER;
