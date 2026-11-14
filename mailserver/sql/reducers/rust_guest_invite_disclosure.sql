-- #342: frozen Go GuestInviteAcceptGet (authserver/internal/handlers/guest_invite.go:122).
-- 'reject' is Go's uniform terminal verdict; the caller rolls it back (no stamp)
-- before its constant delay. Token possession is the authority.
CREATE OR REPLACE FUNCTION rust_guest_invite_disclosure(p_guest_user_id bigint, p_token_hash text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE
  v_invite_id bigint; v_host_domain_id bigint; v_email text; v_status text;
  v_invite_expires timestamptz; v_guest_expires timestamptz; v_used_at timestamptz;
  v_version text; v_federated boolean; v_now timestamptz := clock_timestamp();
  v_org text; v_locality text; v_addendum text; v_channels jsonb;
BEGIN
  SELECT gi.id, gi.host_domain_id, u.email, ga.status, gi.expires_at, ga.expires_at,
         gi.used_at, gi.disclosure_version,
         (u.sync_source = 'sso' OR u.oidc_subject IS NOT NULL OR u.oidc_issuer IS NOT NULL
          OR u.saml_name_id IS NOT NULL OR u.saml_idp_entity_id IS NOT NULL)
    INTO v_invite_id, v_host_domain_id, v_email, v_status, v_invite_expires, v_guest_expires,
         v_used_at, v_version, v_federated
    FROM guest_invites gi
    JOIN guest_accounts ga ON ga.user_id = gi.guest_user_id
    JOIN users u ON u.id = gi.guest_user_id
   WHERE gi.token_hash = p_token_hash AND gi.guest_user_id = p_guest_user_id;
  IF NOT FOUND OR v_used_at IS NOT NULL OR v_invite_expires <= v_now
     OR (v_guest_expires IS NOT NULL AND v_guest_expires <= v_now)
     OR v_status <> 'invited' OR v_federated THEN
    RETURN jsonb_build_object('status', 'reject');
  END IF;
  UPDATE guest_invites gi
     SET disclosure_version = COALESCE(gi.disclosure_version, 'v1')
    FROM guest_accounts ga
   WHERE gi.id = v_invite_id AND gi.guest_user_id = p_guest_user_id
     AND gi.token_hash = p_token_hash AND ga.user_id = gi.guest_user_id
     AND gi.used_at IS NULL AND gi.expires_at > now()
     AND (ga.expires_at IS NULL OR ga.expires_at > now()) AND ga.status = 'invited';
  IF NOT FOUND THEN RETURN jsonb_build_object('status', 'reject'); END IF;
  SELECT name INTO STRICT v_org FROM domains WHERE id = v_host_domain_id;
  v_locality := COALESCE((SELECT NULLIF(value #>> '{}', '') FROM system_config
                           WHERE key = 'installation.locality'), '');
  v_addendum := COALESCE((SELECT NULLIF(value #>> '{}', '') FROM system_config
                           WHERE key = 'guest.disclosure_addendum'), '');
  SELECT COALESCE(jsonb_agg(c.name ORDER BY c.name), '[]'::jsonb) INTO v_channels
    FROM chat_channels c JOIN chat_channel_members m ON m.channel_id = c.id
   WHERE m.user_id = p_guest_user_id AND c.name IS NOT NULL;
  RETURN jsonb_build_object(
    'status', 'ok', 'org_name', v_org, 'invited_email', v_email, 'channels', v_channels,
    'locality', v_locality, 'addendum', v_addendum,
    'disclosure_version', COALESCE(v_version, 'v1'),
    'expires_at', to_char(v_invite_expires AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'));
END;
$$;
