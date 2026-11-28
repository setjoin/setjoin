-- admin_actor_reach_users: every user covered by the actor's active OU/set grants.
-- The scope_type-NULL (unconfined) case is handled by is_unconfined upstream, so
-- this enumerates ONLY 'ou'/'set' grants. Used by admin_protection_check's
-- per-user union containment (the domination object-axis arm).
CREATE OR REPLACE FUNCTION admin_actor_reach_users(p_user bigint)
RETURNS SETOF bigint LANGUAGE sql STABLE AS $$
  SELECT u FROM admin_role_assignments ra
    CROSS JOIN LATERAL admin_scope_member_users(ra.scope_type, ra.scope_id) AS u
   WHERE ra.user_id = p_user
     AND ra.scope_type IN ('ou','set')
     AND (ra.expires_at IS NULL OR ra.expires_at > now());
$$;
