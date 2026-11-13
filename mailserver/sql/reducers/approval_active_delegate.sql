-- approval_active_delegate(p_user_id): resolve the user an approval should route to,
-- honouring an active out-of-office entrust (QoL #23). Returns the delegate when
-- p_user_id has a currently-active approval_delegations row, else p_user_id itself.
--
-- SECURITY INVOKER + no RLS on approval_delegations (see V105 header): the caller is
-- the approval engine resolving on behalf of an approver, not the delegator, so the
-- read is scoped by the p_user_id param, not by a per-user RLS policy.
--
-- ponytail: SINGLE HOP only — if the delegate is themselves OOO the request is NOT
-- chained onward. Bounded-loop chain resolution is deferred; add it here (cap the
-- hops, guard against a delegation cycle) if real deployments need transitive entrust.
CREATE OR REPLACE FUNCTION approval_active_delegate(p_user_id bigint)
RETURNS bigint AS $$
  SELECT COALESCE(
    (SELECT delegate_user_id
       FROM approval_delegations
      WHERE delegator_user_id = p_user_id
        AND now() >= starts_at
        AND now() <  ends_at
      ORDER BY created_at DESC, id DESC   -- latest-created wins; id breaks a same-txn created_at tie
      LIMIT 1),
    p_user_id);
$$ LANGUAGE sql STABLE SECURITY INVOKER;
