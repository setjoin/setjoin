-- admin_is_super.sql — shared Super-Admin predicate. True iff the user holds an
-- unexpired role_group_id=1 (Super Admin) assignment that is CURRENTLY ACTIVE
-- (JIT-gated): a dormant-eligible SA is NOT "currently super" while rbac.jit is
-- ON — it must be activated first. Toggle OFF ⇒ admin_assignment_active TRUE ⇒
-- unchanged (every standing assignment is eligible=false → active). Extracted
-- from the inline EXISTS in admin_protection_check so the guard and
-- bulk_role_job_apply share ONE definition (DRY).
CREATE OR REPLACE FUNCTION admin_is_super(p_user_id bigint) RETURNS boolean AS $$
  SELECT EXISTS (
    SELECT 1 FROM admin_role_assignments
     WHERE user_id = p_user_id AND role_group_id = 1
       AND (expires_at IS NULL OR expires_at > now())
       AND admin_assignment_active(eligible, activated_until));
$$ LANGUAGE sql STABLE;
