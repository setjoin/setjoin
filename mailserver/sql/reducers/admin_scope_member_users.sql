-- admin_scope_member_users: the user ids a single grant scope covers.
--   ou  → users whose department is in the subtree (path = sd.path OR starts_with(path, sd.path||'/'))
--   set → union over the set's members:
--           ou    member → subtree users (as above)
--           group member → users whose PRIMARY mailbox is a static member of the group
--           user  member → the user directly
-- MUST agree with admin_set_reaches: u ∈ admin_scope_member_users('set',S) ⇔ admin_set_reaches(S,u).
-- Cold path only (grant-time Rule A + the 5 sensitive ops); materialising is fine.
CREATE OR REPLACE FUNCTION admin_scope_member_users(p_scope_type text, p_scope_id bigint)
RETURNS SETOF bigint LANGUAGE sql STABLE AS $$
  -- OU grant
  SELECT tu.id FROM users tu JOIN departments td ON td.id = tu.department_id
   WHERE p_scope_type = 'ou'
     AND EXISTS (SELECT 1 FROM departments sd WHERE sd.id = p_scope_id
                  AND (td.path = sd.path OR starts_with(td.path, sd.path || '/')))
  UNION
  -- SET grant — ou members
  SELECT tu.id FROM admin_scope_set_members m
     JOIN departments sd ON sd.id = m.member_id
     JOIN departments td ON (td.path = sd.path OR starts_with(td.path, sd.path || '/'))
     JOIN users tu ON tu.department_id = td.id
   WHERE p_scope_type = 'set' AND m.set_id = p_scope_id AND m.member_type = 'ou'
  UNION
  -- SET grant — group members (primary mailbox in the static group)
  SELECT mb.user_id FROM admin_scope_set_members m
     JOIN distribution_group_members dgm ON dgm.group_id = m.member_id
     JOIN mailboxes mb ON mb.id = dgm.mailbox_id AND mb.is_primary
   WHERE p_scope_type = 'set' AND m.set_id = p_scope_id AND m.member_type = 'group'
     AND mb.user_id IS NOT NULL
  UNION
  -- SET grant — direct user members
  SELECT m.member_id FROM admin_scope_set_members m
   WHERE p_scope_type = 'set' AND m.set_id = p_scope_id AND m.member_type = 'user';
$$;
