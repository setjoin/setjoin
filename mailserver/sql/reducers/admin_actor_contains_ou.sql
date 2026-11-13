-- admin_actor_contains_ou: does the actor's STRUCTURAL OU reach contain the OU at p_path?
-- Structural reach = the actor's own 'ou' grants ∪ the 'ou' MEMBERS of the actor's
-- scope-sets. An OU is forever-safe within reach iff its subtree sits at/under one of
-- these paths (covers FUTURE department members — never point-in-time). Group/user set
-- members do NOT provide OU containment (they cover specific users, not a growing subtree).
-- ponytail: path-only containment; domain confinement (Rule-B) is enforced at the grant sites.
CREATE OR REPLACE FUNCTION admin_actor_contains_ou(p_actor bigint, p_path text)
RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT p_path IS NOT NULL AND EXISTS (
    SELECT 1 FROM admin_role_assignments ra JOIN departments d ON d.id = ra.scope_id
     WHERE ra.user_id = p_actor AND ra.scope_type='ou'
       AND (ra.expires_at IS NULL OR ra.expires_at > now())
       AND (p_path = d.path OR starts_with(p_path, d.path || '/'))
    UNION ALL
    SELECT 1 FROM admin_role_assignments ra
       JOIN admin_scope_set_members m ON m.set_id = ra.scope_id AND m.member_type='ou'
       JOIN departments d ON d.id = m.member_id
     WHERE ra.user_id = p_actor AND ra.scope_type='set'
       AND (ra.expires_at IS NULL OR ra.expires_at > now())
       AND (p_path = d.path OR starts_with(p_path, d.path || '/'))
  );
$$;
