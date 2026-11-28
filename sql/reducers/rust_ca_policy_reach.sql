-- Reach of a conditional-access policy for a domain-scoped admin. Owner-approved
-- security fix 2026-11-05 (#510, #467): frozen Go had no tenant or domain filter on
-- the policy routes, so any holder of access.policy_* could read and change org-wide
-- policies. A policy is reachable when the actor holds an organization-wide grant of
-- one of p_perms, or when it is scoped to one user the actor reaches through a grant of p_perms (scope_type
-- 'user', target = that user's id). 'global', 'group', 'role', 'guests' and any
-- unparsable target need the org-wide grant: group membership is row-level-secured
-- per user (ugm_self), so a domain-scoped admin cannot prove every member is in reach.
--
-- rust_ca_policy_scope_reach judges a (type,target) pair, e.g. the document about
-- to be written; rust_ca_policy_row_reach judges the stored row of an existing id
-- (NULL when no such row, so the caller keeps the reducer's own not-found answer).
CREATE OR REPLACE FUNCTION rust_ca_policy_scope_reach(
  p_actor bigint, p_scope_type text, p_scope_target text, p_perms text[]
) RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT admin_org_wide_grant(p_actor, p_perms)
      OR CASE
           WHEN p_scope_target IS NULL OR p_scope_target !~ '^[0-9]{1,18}$' THEN false
           WHEN p_scope_type = 'user' THEN admin_can_reach_perm(p_actor, p_scope_target::bigint, p_perms)
           ELSE false
         END;
$$;

CREATE OR REPLACE FUNCTION rust_ca_policy_row_reach(
  p_actor bigint, p_id bigint, p_perms text[]
) RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT rust_ca_policy_scope_reach(p_actor, c.scope_type, c.scope_target, p_perms)
    FROM conditional_access_policies c WHERE c.id = p_id;
$$;

-- Reach of the policy snapshot a restore-from-audit would rebuild (NULL when the audit
-- row is not a conditional_access_policy snapshot, so the reducer keeps its BZ086).
CREATE OR REPLACE FUNCTION rust_ca_policy_audit_reach(
  p_actor bigint, p_audit_id bigint, p_perms text[]
) RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT rust_ca_policy_scope_reach(p_actor, COALESCE(a.before_state->>'scope_type','global'),
                                    COALESCE(a.before_state->>'scope_target',''), p_perms)
    FROM admin_audit_log a
   WHERE a.id = p_audit_id AND a.target_type = 'conditional_access_policy'
     AND a.before_state IS NOT NULL;
$$;

-- Priority floor of a policy writer. Owner-approved security fix 2026-11-06 (#467, #510): a
-- domain-limited admin may not place its policies ahead of (take effect before) any policy
-- outside its reach, i.e. an org-wide one. NULL = organization-wide grant (no floor); otherwise
-- the highest priority among live policies the actor does not reach (0 when there are none), and
-- the actor's priorities must be strictly greater.
CREATE OR REPLACE FUNCTION rust_ca_priority_floor(p_actor bigint, p_perms text[])
RETURNS integer LANGUAGE sql STABLE AS $$
  SELECT CASE WHEN admin_org_wide_grant(p_actor, p_perms) THEN NULL
         ELSE COALESCE((SELECT MAX(c.priority) FROM conditional_access_policies c
                         WHERE c.deleted_at IS NULL
                           AND NOT rust_ca_policy_scope_reach(p_actor, c.scope_type, c.scope_target, p_perms)), 0) END;
$$;

-- May the actor give a policy this priority? (NULL priority = the reducer's automatic max+10.)
CREATE OR REPLACE FUNCTION rust_ca_priority_ok(p_actor bigint, p_priority bigint, p_perms text[])
RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT p_priority IS NULL OR f IS NULL OR p_priority > f
    FROM (SELECT rust_ca_priority_floor(p_actor, p_perms) AS f) x;
$$;

-- The same question for the snapshot a restore-from-audit would rebuild (NULL: no such snapshot).
CREATE OR REPLACE FUNCTION rust_ca_audit_priority_ok(p_actor bigint, p_audit_id bigint, p_perms text[])
RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT rust_ca_priority_ok(p_actor, (a.before_state->>'priority')::bigint, p_perms)
    FROM admin_audit_log a
   WHERE a.id = p_audit_id AND a.target_type = 'conditional_access_policy' AND a.before_state IS NOT NULL;
$$;

-- Reorder for the console. An org-wide writer gets ca_policy_reorder unchanged (priorities
-- restepped by ten from 10). A domain-limited writer's policies are restepped by ten from the
-- floor, so they stay behind every org-wide policy; same audit row and notification.
CREATE OR REPLACE FUNCTION rust_ca_policy_reorder(p_actor bigint, p_ip inet, p_ids bigint[])
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE
  v_floor integer := rust_ca_priority_floor(p_actor, ARRAY['access.policy_write']);
  v_id bigint; v_i int := 0; v_after jsonb := '[]'::jsonb;
BEGIN
  IF v_floor IS NULL THEN
    PERFORM ca_policy_reorder(p_actor, p_ip, p_ids);
    RETURN;
  END IF;
  FOREACH v_id IN ARRAY p_ids LOOP
    v_i := v_i + 1;
    UPDATE conditional_access_policies SET priority = v_floor + v_i * 10, updated_at = now()
     WHERE id = v_id;
    v_after := v_after || jsonb_build_object('id', v_id, 'priority', v_floor + v_i * 10);
  END LOOP;
  PERFORM audit_write(p_actor, 'ca_policy_reorder', 'conditional_access_policy', NULL, NULL, v_after, p_ip, NULL, 'core');
  PERFORM ca_notify_policy_change('ca_policy_reorder');
END;
$$;
