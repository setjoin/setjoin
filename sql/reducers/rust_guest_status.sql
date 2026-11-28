-- Frozen Go's explicit authority fence, scoped target lock, and lifecycle call.
-- False is Go's UX 404; callers roll back that result before issuing a receipt.
CREATE OR REPLACE FUNCTION rust_guest_status(
 p_actor bigint,p_guest bigint,p_action text,p_expires_at timestamptz
) RETURNS boolean LANGUAGE plpgsql VOLATILE AS $$
BEGIN
 PERFORM admin_authority_fence();
 PERFORM 1 FROM guest_accounts g WHERE g.user_id=p_guest
  AND guest_admin_can_reach_with_permission(p_actor,g.user_id,'guests.manage')
  FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM guest_set_status(p_actor,p_guest,p_action,p_expires_at);
 RETURN true;
END;
$$;
