-- admin_set_reaches: does any member of the scope-set cover the target user?
--   ou    → target's department is in the member's subtree
--   group → target's PRIMARY mailbox is in the (static) group (admin_mailbox_in_group)
--   user  → target IS the member
-- Empty set / all members resolve to ∅ → FALSE (reaches nobody). Fail-closed.
CREATE OR REPLACE FUNCTION admin_set_reaches(p_set_id bigint, p_target bigint)
RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT EXISTS (
    SELECT 1 FROM admin_scope_set_members m
     WHERE m.set_id = p_set_id
       AND (
         (m.member_type = 'ou' AND EXISTS (
            SELECT 1 FROM users tu
              JOIN departments td ON td.id = tu.department_id
              JOIN departments sd ON sd.id = m.member_id
             WHERE tu.id = p_target
               AND (td.path = sd.path OR starts_with(td.path, sd.path || '/'))))
         OR (m.member_type = 'group' AND EXISTS (
            SELECT 1 FROM mailboxes mb
             WHERE mb.user_id = p_target AND mb.is_primary
               AND admin_mailbox_in_group(m.member_id, mb.id)))
         OR (m.member_type = 'user' AND m.member_id = p_target)
       )
  );
$$;
