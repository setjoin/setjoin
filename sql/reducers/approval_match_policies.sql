-- approval_match_policies: IAM-hybrid policy evaluator.
-- Given a consumer_type + request context, returns one row:
--   required         = true if ANY matched policy has requires_approval=true (fail-closed)
--   winner_policy_id = lowest-priority matched policy WITH requires_approval=true (NULL when !required)
--   approver_spec    = that policy's approver_spec (NULL when !required)
--
-- Match predicate: every key in policy.conditions must be present-and-equal in p_context.
-- Winner filter: requires_approval=true ONLY — an exempt (false) policy cannot supply the approver
-- for an approval a lower-priority policy demanded (the who-hole regression, OV-5).
--
-- SECURITY DEFINER (ARCH-018 recipe, worker-owned): approval_policies is
-- FORCE-RLS admin-only (approval_policies_admin_only), but this evaluator is
-- called by every NON-admin consumer path (hr_request_create by an employee,
-- drive_export_request/drive_member_grant/send outbound-external/group_moderation
-- by ordinary users, all SECURITY INVOKER). Under native-RLS the constrained
-- setjoin_app role sees ZERO policy rows through the admin-only USING clause →
-- NOT EXISTS matched → required=false → SILENT approval bypass (the #A4 allow-side
-- guard's flip-blocker). Matching is a fail-closed SYSTEM decision over org config,
-- not a user-data read: a non-admin must have policies APPLIED without being able
-- to SELECT them. This function returns only a decision (required/winner/spec),
-- never policy rows, so the admin-only read invariant is preserved at the choke point.
CREATE OR REPLACE FUNCTION approval_match_policies(
  p_consumer_type text,
  p_context       jsonb
) RETURNS TABLE(required boolean, winner_policy_id bigint, approver_spec jsonb)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  WITH v_matched AS (
    SELECT ap.id, ap.priority, ap.requires_approval, ap.approver_spec
      FROM approval_policies ap
     WHERE ap.enabled = true
       AND ap.consumer_type = p_consumer_type
       AND NOT EXISTS (
             SELECT 1 FROM jsonb_each(ap.conditions) c
              WHERE p_context->(c.key) IS DISTINCT FROM c.value
           )
  ),
  v_winner AS (
    SELECT id, approver_spec
      FROM v_matched
     WHERE requires_approval = true
     ORDER BY priority ASC
     LIMIT 1          -- priority UNIQUE per consumer_type; deterministic
  )
  SELECT
    EXISTS(SELECT 1 FROM v_matched WHERE requires_approval = true)  AS required,
    (SELECT id           FROM v_winner)                             AS winner_policy_id,
    (SELECT v_winner.approver_spec FROM v_winner)                   AS approver_spec;
$$;
SELECT apply_worker_ownership('approval_match_policies(text,jsonb)'::regprocedure);
