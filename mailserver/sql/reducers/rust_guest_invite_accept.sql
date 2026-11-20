-- #342: frozen Go GuestInviteAcceptPost (guest_invite.go:265). The read reducer takes
-- Go's canonical guest -> user -> invite locks and returns every verdict; Rust
-- hashes under those locks; finish is the one consuming write, audited in-commit.
-- Retire the pre-release four-argument overload so defaulted calls stay unambiguous.
DROP FUNCTION IF EXISTS rust_guest_invite_accept_read(bigint, text, text, boolean);
CREATE OR REPLACE FUNCTION rust_guest_invite_accept_read(
  p_guest_user_id bigint, p_token_hash text, p_new_password text DEFAULT NULL,
  p_password_too_long boolean DEFAULT false, p_password_invalid_text boolean DEFAULT false
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE
  v_invite_id bigint; v_email text; v_status text; v_guest_expires timestamptz;
  v_federated boolean; v_invite_expires timestamptz; v_used_at timestamptz;
  v_now timestamptz; v_policy jsonb;
BEGIN
  SELECT gi.id INTO v_invite_id FROM guest_invites gi
   WHERE gi.token_hash = p_token_hash AND gi.guest_user_id = p_guest_user_id;
  IF NOT FOUND THEN RETURN jsonb_build_object('status', 'reject'); END IF;
  SELECT u.email, ga.status, ga.expires_at,
         (u.sync_source = 'sso' OR u.oidc_subject IS NOT NULL OR u.oidc_issuer IS NOT NULL
          OR u.saml_name_id IS NOT NULL OR u.saml_idp_entity_id IS NOT NULL)
    INTO v_email, v_status, v_guest_expires, v_federated
    FROM guest_accounts ga JOIN users u ON u.id = ga.user_id
   WHERE ga.user_id = p_guest_user_id
   FOR UPDATE OF ga, u;
  IF NOT FOUND THEN RETURN jsonb_build_object('status', 'reject'); END IF;
  SELECT expires_at, used_at INTO v_invite_expires, v_used_at
    FROM guest_invites
   WHERE id = v_invite_id AND token_hash = p_token_hash AND guest_user_id = p_guest_user_id
   FOR UPDATE;
  IF NOT FOUND THEN RETURN jsonb_build_object('status', 'reject'); END IF;
  v_now := clock_timestamp();
  IF v_used_at IS NULL AND (v_invite_expires <= v_now
       OR (v_guest_expires IS NOT NULL AND v_guest_expires <= v_now)) THEN
    UPDATE guest_invites SET used_at = expires_at, terminal_reason = 'expired'
     WHERE id = v_invite_id AND guest_user_id = p_guest_user_id
       AND token_hash = p_token_hash AND used_at IS NULL;
    RETURN jsonb_build_object('status', 'expired');
  END IF;
  IF v_used_at IS NOT NULL OR v_status <> 'invited' OR v_federated THEN
    RETURN jsonb_build_object('status', 'reject');
  END IF;
  -- Rust never binds more than 72 bytes; the flag carries Go's ceiling verdict.
  IF COALESCE(p_password_too_long, false) OR octet_length(COALESCE(p_new_password, '')) > 72 THEN
    RETURN jsonb_build_object('status', 'invalid', 'error', 'password exceeds the 72-byte limit');
  END IF;
  -- Go binds a NUL-bearing password to validate_password and PostgreSQL refuses it
  -- (22021) only after every terminal verdict: same position, same rollback, 500.
  IF COALESCE(p_password_invalid_text, false) THEN
    RAISE EXCEPTION 'guest invite acceptance: password is not valid text' USING ERRCODE = '22021';
  END IF;
  v_policy := validate_password(p_new_password, false)::jsonb;
  IF NOT COALESCE((v_policy ->> 'valid')::boolean, false) THEN
    RETURN jsonb_build_object('status', 'invalid', 'error',
      COALESCE(NULLIF(v_policy ->> 'error', ''), 'password does not meet policy requirements'));
  END IF;
  RETURN jsonb_build_object('status', 'ready', 'invite_id', v_invite_id,
                            'guest_user_id', p_guest_user_id, 'invited_email', v_email);
END;
$$;

CREATE OR REPLACE FUNCTION rust_guest_invite_accept_finish(
  p_guest_user_id bigint, p_invite_id bigint, p_token_hash text, p_password_hash text,
  p_ip inet DEFAULT NULL
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_email text;
BEGIN
  UPDATE guest_invites
     SET used_at = now(), disclosure_accepted_at = now(),
         disclosure_version = COALESCE(disclosure_version, 'v1'), terminal_reason = 'accepted'
   WHERE id = p_invite_id AND guest_user_id = p_guest_user_id
     AND token_hash = p_token_hash AND used_at IS NULL;
  IF NOT FOUND THEN RAISE EXCEPTION 'guest invite acceptance: invite not consumable'; END IF;
  UPDATE guest_accounts SET status = 'active', updated_at = now()
   WHERE user_id = p_guest_user_id AND status = 'invited';
  IF NOT FOUND THEN RAISE EXCEPTION 'guest invite acceptance: satellite not invited'; END IF;
  UPDATE users SET enabled = TRUE, password_hash = p_password_hash,
                   must_change_password = FALSE, updated_at = now()
   WHERE id = p_guest_user_id AND sync_source <> 'sso' AND oidc_subject IS NULL
     AND oidc_issuer IS NULL AND saml_name_id IS NULL AND saml_idp_entity_id IS NULL
  RETURNING email INTO v_email;
  IF NOT FOUND THEN RAISE EXCEPTION 'guest invite acceptance: identity not local'; END IF;
  PERFORM audit_write(p_guest_user_id, 'guest.invite_accept', 'guest_invite', p_invite_id, NULL,
    jsonb_build_object('status', 'active', 'guestUserId', p_guest_user_id::text),
    p_ip, 'guest invite accepted', 'core');
  RETURN jsonb_build_object('status', 'accepted', 'invited_email', v_email);
END;
$$;
