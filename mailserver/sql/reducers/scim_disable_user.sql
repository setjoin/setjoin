-- scim_disable_user: Soft-disable a user by SCIM external ID. Sets enabled=FALSE.
-- Session revocation is the Go gateway's job (revokeSessions → authserver
-- POST /auth/scim/disable), fired by both the DELETE-soft and PATCH active=false
-- paths — NOT an in-DB LISTEN. (The former pg_notify('user_disabled') channel had
-- no subscriber anywhere and was removed; revocation never rode the notify.)

CREATE OR REPLACE FUNCTION scim_disable_user(p_external_id TEXT) RETURNS VOID AS $$
DECLARE
  v_user_id BIGINT;
BEGIN
  -- Fence before resolving the user row; the users.enabled trigger re-enters it.
  PERFORM admin_authority_fence();

  SELECT id INTO v_user_id FROM users WHERE scim_external_id = p_external_id;
  IF v_user_id IS NULL THEN
    RAISE EXCEPTION 'User not found for external_id: %', p_external_id
      USING ERRCODE = 'BZ002', HINT = jsonb_build_object('type', 'not_found', 'external_id', p_external_id)::TEXT;
  END IF;

  UPDATE users SET enabled = FALSE, updated_at = now() WHERE id = v_user_id;

  -- WP3/astra P2-5: disabling an account is a material security-disable
  -- transition — the frozen lifecycle policy audits it even when the driver
  -- is an IdP sync (actor NULL, system origin in the notes).
  PERFORM audit_write(
    NULL, 'scim_disable_user', 'user', v_user_id,
    NULL,
    jsonb_build_object('enabled', FALSE, 'driver', 'scim'),
    NULL, 'scim', 'core');
END;
$$ LANGUAGE plpgsql;
