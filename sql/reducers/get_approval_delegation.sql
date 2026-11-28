-- get_approval_delegation(p_user_id): read the caller's out-of-office approval entrust
-- (QoL #23). p_user_id-scoped (R1 by parameter propagation; approval_delegations has no
-- RLS — see the V105 header). At most one row per delegator (set_approval_delegation
-- delete-then-inserts); returns it, or no row when there is no entrust.
CREATE OR REPLACE FUNCTION get_approval_delegation(p_user_id bigint)
RETURNS approval_delegations AS $$
  SELECT * FROM approval_delegations
   WHERE delegator_user_id = p_user_id
   ORDER BY created_at DESC
   LIMIT 1;
$$ LANGUAGE sql STABLE;
