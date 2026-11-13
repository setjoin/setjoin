-- admin_mailbox_in_group: non-materializing single-target membership test.
-- STATIC ONLY — dynamic groups are banned from RBAC scope (spec §3.3), so no
-- dynamic_filter evaluation. Indexed point lookup; FALSE for a missing group
-- (fail-closed). Used by admin_set_reaches in the hot reach path.
CREATE OR REPLACE FUNCTION admin_mailbox_in_group(p_group_id bigint, p_mailbox_id bigint)
RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT EXISTS (
    SELECT 1 FROM distribution_group_members
     WHERE group_id = p_group_id AND mailbox_id = p_mailbox_id
  );
$$;
