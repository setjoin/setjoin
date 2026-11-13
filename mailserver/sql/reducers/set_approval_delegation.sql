-- set_approval_delegation(p_user_id, p_delegate_user_id, p_starts_at, p_ends_at):
-- self-service out-of-office approval entrust writer (QoL #23). Delete-then-insert keeps
-- at most one delegation row per delegator. A NULL p_delegate_user_id clears the entrust.
--
-- Not a synced JMAP object (device-agnostic user config, fetched on demand) → no
-- jmap_*_state bump / notify. Every statement is scoped by p_user_id, so R2/R3 hold by
-- parameter propagation (approval_delegations has no RLS on purpose — the resolution
-- read runs on behalf of the APPROVER, a different user; see the V105 header).
--
-- Errors: BZ119 — invalid range (ends <= starts / missing) OR delegate invalid
-- (self / missing / not in the delegator's domain).
CREATE OR REPLACE FUNCTION set_approval_delegation(
  p_user_id          bigint,
  p_delegate_user_id bigint,
  p_starts_at        timestamptz DEFAULT NULL,
  p_ends_at          timestamptz DEFAULT NULL
) RETURNS VOID AS $$
DECLARE
  v_domain_id       bigint;
  v_delegate_domain bigint;
BEGIN
  -- Clear any existing entrust first: keeps a single active row and lets a NULL
  -- delegate act as "turn it off".
  DELETE FROM approval_delegations WHERE delegator_user_id = p_user_id;

  IF p_delegate_user_id IS NULL THEN
    RETURN;  -- cleared
  END IF;

  IF p_starts_at IS NULL OR p_ends_at IS NULL OR p_ends_at <= p_starts_at THEN
    RAISE EXCEPTION 'approval delegation end must be after start'
      USING ERRCODE = 'BZ119',
            HINT = jsonb_build_object('type', 'delegation_date_range',
                                      'starts_at', p_starts_at, 'ends_at', p_ends_at)::TEXT;
  END IF;

  IF p_delegate_user_id = p_user_id THEN
    RAISE EXCEPTION 'cannot delegate approvals to yourself'
      USING ERRCODE = 'BZ119',
            HINT = jsonb_build_object('type', 'delegate_invalid')::TEXT;
  END IF;

  -- Tenant safety: the delegate must exist AND live in the delegator's domain, so an
  -- entrust can never reroute an approval across tenants.
  SELECT domain_id INTO v_domain_id       FROM users WHERE id = p_user_id;
  SELECT domain_id INTO v_delegate_domain FROM users WHERE id = p_delegate_user_id;
  IF v_delegate_domain IS NULL OR v_delegate_domain IS DISTINCT FROM v_domain_id THEN
    RAISE EXCEPTION 'delegate not found in your organization'
      USING ERRCODE = 'BZ119',
            HINT = jsonb_build_object('type', 'delegate_invalid')::TEXT;
  END IF;

  INSERT INTO approval_delegations (delegator_user_id, delegate_user_id, starts_at, ends_at)
  VALUES (p_user_id, p_delegate_user_id, p_starts_at, p_ends_at);
END;
$$ LANGUAGE plpgsql;
