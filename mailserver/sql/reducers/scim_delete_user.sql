-- scim_delete_user: Deprovision a user by SCIM external ID.
-- Soft delete (p_hard_delete=FALSE): calls scim_disable_user.
-- Hard delete (p_hard_delete=TRUE): DELETE FROM users (cascades to mailboxes, aliases, etc.)
-- Session revocation is the Go gateway's job (revokeSessions → authserver), not an
-- in-DB notify. (The former pg_notify('user_deleted') channel had no subscriber.)

CREATE OR REPLACE FUNCTION scim_delete_user(p_external_id TEXT, p_hard_delete BOOL DEFAULT FALSE) RETURNS VOID AS $$
DECLARE
  v_user_id BIGINT;
BEGIN
  -- Fence before resolving/deleting the user row; nested soft-disable is reentrant.
  PERFORM admin_authority_fence();

  SELECT id INTO v_user_id FROM users WHERE scim_external_id = p_external_id;
  IF v_user_id IS NULL THEN
    RAISE EXCEPTION 'User not found for external_id: %', p_external_id
      USING ERRCODE = 'BZ002', HINT = jsonb_build_object('type', 'not_found', 'external_id', p_external_id)::TEXT;
  END IF;

  IF p_hard_delete IS TRUE THEN
    DELETE FROM users WHERE id = v_user_id;

    -- WP3/astra P2-5: a hard delete is the terminal lifecycle transition —
    -- audited BEFORE the row disappears (after_state would have no row to
    -- describe). The soft arm audits inside scim_disable_user.
    PERFORM audit_write(
      NULL, 'scim_delete_user', 'user', v_user_id,
      jsonb_build_object('hard_delete', TRUE),
      jsonb_build_object('deleted', TRUE),
      NULL, 'scim', 'core');
  ELSE
    PERFORM scim_disable_user(p_external_id);
  END IF;
END;
$$ LANGUAGE plpgsql;
