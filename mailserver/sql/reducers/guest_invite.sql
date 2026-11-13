-- guest_invite.sql — Guest Accounts G1 invite lifecycle and allowlist.
-- The backing tables are FORCE-RLS deny-all, so the production functions are
-- SECURITY DEFINER and worker-owned. Raw invite tokens never enter this file.
-- guest_invite_create is an internal mint primitive shared by the direct-admin
-- and approved-consumer paths: callers own workflow authorization, while this
-- reducer refuses forged guest type, host ownership, or creator attribution.

DROP FUNCTION IF EXISTS guest_invite_create(bigint,bigint,text,bigint,text,timestamptz);
CREATE FUNCTION guest_invite_create(
    p_creator_user_id  bigint,
    p_guest_user_id    bigint,
    p_token_hash       text,
    p_host_domain_id   bigint,
    p_created_by_email text,
    p_expires_at       timestamptz
) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    v_invited_email text;
    v_domain        text;
    v_guest_host_id bigint;
    v_creator_email text;
    v_guest_status  text;
    v_guest_expires_at timestamptz;
    v_effective_expires_at timestamptz;
    v_user_enabled  boolean;
    v_federated_identity boolean;
    v_superseded_invite_id bigint;
    v_invite_id bigint;
BEGIN
    SELECT u.email, g.host_domain_id, g.status, g.expires_at, u.enabled,
           (u.sync_source = 'sso'
            OR u.oidc_subject IS NOT NULL OR u.oidc_issuer IS NOT NULL
            OR u.saml_name_id IS NOT NULL OR u.saml_idp_entity_id IS NOT NULL)
      INTO v_invited_email, v_guest_host_id, v_guest_status, v_guest_expires_at, v_user_enabled,
           v_federated_identity
      FROM guest_accounts g
      JOIN users u ON u.id = g.user_id
     WHERE g.user_id = p_guest_user_id
     FOR UPDATE OF g, u;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'invite target % is not a guest account', p_guest_user_id
            USING ERRCODE='BZ221', HINT='{"type":"conflict","detail":"invite target is not a guest account"}';
    END IF;
    IF v_guest_host_id IS DISTINCT FROM p_host_domain_id THEN
        RAISE EXCEPTION 'invite host domain does not match the guest account'
            USING ERRCODE='BZ002', HINT='{"type":"forbidden","detail":"guest host domain mismatch"}';
    END IF;
    -- Token minting is not lifecycle authority. New guests arrive invited +
    -- disabled from provision_account; existing guests must first pass the
    -- explicit guest_set_status(...,'reinvite') transition. This prevents a
    -- raw invite mint from silently re-enabling an active/disabled/expired
    -- principal without session revocation and scope authorization.
    IF v_guest_status IS DISTINCT FROM 'invited' OR v_user_enabled THEN
        RAISE EXCEPTION 'guest must be explicitly re-armed before invite creation'
            USING ERRCODE='BZ162',
                  HINT='{"type":"invalidArguments","detail":"guest is not in the invited recovery state"}';
    END IF;
    IF v_federated_identity THEN
        RAISE EXCEPTION 'federated guest invite cannot mint a local password fallback'
            USING ERRCODE='BZ162',
                  HINT='{"type":"invalidArguments","detail":"federated guest recovery cannot mint a local password fallback"}';
    END IF;

    v_effective_expires_at := CASE
        WHEN v_guest_expires_at IS NULL THEN p_expires_at
        ELSE LEAST(p_expires_at, v_guest_expires_at)
    END;
    IF v_effective_expires_at IS NULL OR v_effective_expires_at <= clock_timestamp() THEN
        RAISE EXCEPTION 'guest invite expiry must be in the future'
            USING ERRCODE='BZ162',
                  HINT='{"type":"invalidArguments","detail":"guest invite expiry must be in the future and cannot exceed the guest account expiry"}';
    END IF;

    SELECT u.email INTO v_creator_email FROM users u WHERE u.id = p_creator_user_id;
    IF NOT FOUND OR lower(p_created_by_email) IS DISTINCT FROM lower(v_creator_email) THEN
        RAISE EXCEPTION 'invite creator attribution does not match the actor'
            USING ERRCODE='BZ002', HINT='{"type":"forbidden","detail":"invite creator mismatch"}';
    END IF;

    IF EXISTS (SELECT 1 FROM guest_invite_domains) THEN
        v_domain := lower(split_part(v_invited_email, '@', 2));
        IF NOT EXISTS (SELECT 1 FROM guest_invite_domains WHERE domain = v_domain) THEN
            RAISE EXCEPTION 'domain % is not in the guest invite allowlist', v_domain
                USING ERRCODE='BZ218',
                      HINT='{"type":"forbidden","detail":"domain not in guest_invite_domains"}';
        END IF;
    END IF;

    -- Natural expiry is truthful at expires_at, not at the later request that
    -- happens to observe it. Stamp it before replacement so history can never
    -- reclassify an already-expired link as superseded.
    UPDATE guest_invites
       SET used_at = expires_at,
           terminal_reason = 'expired'
     WHERE guest_user_id = p_guest_user_id
       AND used_at IS NULL
       AND expires_at <= now();

    UPDATE guest_invites
       SET used_at = now(),
           terminal_reason = 'superseded'
     WHERE guest_user_id = p_guest_user_id
       AND used_at IS NULL
       AND expires_at > now()
     RETURNING id INTO v_superseded_invite_id;

    INSERT INTO guest_invites (
        guest_user_id, token_hash, host_domain_id,
        created_by, created_by_email, expires_at
    ) VALUES (
        p_guest_user_id, p_token_hash, p_host_domain_id,
        p_creator_user_id, v_creator_email, v_effective_expires_at
    ) RETURNING id INTO v_invite_id;

    IF v_superseded_invite_id IS NOT NULL THEN
        PERFORM audit_write(
            p_creator_user_id, 'guest.invite_supersede', 'guest_invite',
            v_superseded_invite_id, NULL,
            jsonb_build_object(
                'terminalReason', 'superseded',
                'guestUserId', p_guest_user_id::text,
                'replacementInviteId', v_invite_id::text
            ), NULL, 'guest invite superseded by replacement', 'core'
        );
    END IF;
    PERFORM audit_write(
        p_creator_user_id, 'guest.invite_create', 'guest_invite',
        v_invite_id, NULL,
        jsonb_build_object(
            'state', 'pending',
            'guestUserId', p_guest_user_id::text,
            'expiresAt', v_effective_expires_at
        ), NULL, 'guest invite created', 'core'
    );
    RETURN v_invite_id;
END;
$$;
SELECT apply_worker_ownership('guest_invite_create(bigint,bigint,text,bigint,text,timestamptz)'::regprocedure);

DROP FUNCTION IF EXISTS guest_invite_revoke(bigint,bigint);
CREATE OR REPLACE FUNCTION guest_invite_revoke(
    p_actor_user_id bigint,
    p_guest_user_id bigint,
    p_expected_invite_id bigint
) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    v_invite_id bigint;
    v_expires_at timestamptz;
BEGIN
    IF NOT drive_has_admin_perm(p_actor_user_id, 'guests.manage') THEN
        RAISE EXCEPTION 'guests.manage required' USING ERRCODE='BZ002',
            HINT='{"type":"forbidden","detail":"guests.manage required"}';
    END IF;
    -- Canonical invite mutation order: guest row, user row, then invite row.
    -- Acceptance uses the same order so create/revoke/accept cannot deadlock.
    PERFORM 1
      FROM guest_accounts g
      JOIN users u ON u.id = g.user_id
     WHERE g.user_id = p_guest_user_id
       AND admin_can_reach(p_actor_user_id, g.user_id)
     FOR UPDATE OF g, u;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'access denied' USING ERRCODE='BZ002',
            HINT='{"type":"forbidden"}';
    END IF;

    SELECT id, expires_at
      INTO v_invite_id, v_expires_at
      FROM guest_invites
     WHERE guest_user_id = p_guest_user_id
       AND used_at IS NULL
     FOR UPDATE;
    IF NOT FOUND THEN
        RETURN 'not_found';
    END IF;

    IF v_expires_at <= now() THEN
        UPDATE guest_invites
           SET used_at = expires_at,
               terminal_reason = 'expired'
         WHERE id = v_invite_id
           AND guest_user_id = p_guest_user_id
           AND used_at IS NULL
           AND admin_can_reach(p_actor_user_id, p_guest_user_id);
        RETURN 'not_found';
    END IF;

    IF v_invite_id IS DISTINCT FROM p_expected_invite_id THEN
        RETURN 'stale';
    END IF;

    UPDATE guest_invites
       SET used_at = now(),
           terminal_reason = 'revoked'
     WHERE id = p_expected_invite_id
       AND guest_user_id = p_guest_user_id
       AND used_at IS NULL
       AND admin_can_reach(p_actor_user_id, p_guest_user_id);
    IF NOT FOUND THEN
        RETURN 'stale';
    END IF;
    PERFORM audit_write(
        p_actor_user_id, 'guest.invite_revoke', 'guest_invite',
        p_expected_invite_id, NULL,
        jsonb_build_object(
            'terminalReason', 'revoked',
            'guestUserId', p_guest_user_id::text
        ), NULL, 'pending guest invite revoked by admin', 'core'
    );
    RETURN 'revoked';
END;
$$;
SELECT apply_worker_ownership('guest_invite_revoke(bigint,bigint,bigint)'::regprocedure);

-- The old host-domain-wide list surface predates delegated administration and
-- exposed creator attribution without reachability redaction. No production
-- caller remains; scoped admin list/detail endpoints are the only history API.
DROP FUNCTION IF EXISTS guest_invite_list(bigint,bigint);

CREATE OR REPLACE FUNCTION guest_invite_domain_set(
    p_actor_user_id  bigint,
    p_domain         text,
    p_host_domain_id bigint,
    p_actor_email    text,
    p_remove         boolean DEFAULT false
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    v_domain      text := lower(p_domain);
    v_actor_email text;
BEGIN
    IF NOT drive_has_admin_perm(p_actor_user_id, 'guests.manage') THEN
        RAISE EXCEPTION 'guests.manage required' USING ERRCODE='BZ002',
            HINT='{"type":"forbidden","detail":"guests.manage required"}';
    END IF;
    IF p_remove THEN
        DELETE FROM guest_invite_domains WHERE domain = v_domain;
        RETURN;
    END IF;
    SELECT email INTO v_actor_email FROM users WHERE id = p_actor_user_id;
    IF NOT FOUND OR lower(p_actor_email) IS DISTINCT FROM lower(v_actor_email) THEN
        RAISE EXCEPTION 'domain actor attribution does not match the actor'
            USING ERRCODE='BZ002', HINT='{"type":"forbidden","detail":"guest domain actor mismatch"}';
    END IF;
    INSERT INTO guest_invite_domains (domain, host_domain_id, added_by, added_by_email)
    VALUES (v_domain, p_host_domain_id, p_actor_user_id, v_actor_email)
    ON CONFLICT (domain) DO UPDATE
        SET host_domain_id = EXCLUDED.host_domain_id,
            added_by = EXCLUDED.added_by,
            added_by_email = EXCLUDED.added_by_email;
END;
$$;
SELECT apply_worker_ownership('guest_invite_domain_set(bigint,text,bigint,text,boolean)'::regprocedure);
