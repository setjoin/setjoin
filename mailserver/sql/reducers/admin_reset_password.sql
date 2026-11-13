-- admin_reset_password.sql — authoritative administrator credential reset.
--
-- The gateway may perform early privacy-preserving lookups and password-policy
-- validation, but this reducer owns the security decision that commits:
--
--   authority fence -> person fence -> target row/protection lock ->
--   CURRENT domain+OU reach ->
--   password mutation -> complete all-session revocation
--
-- Keeping current reach after the target row lock closes the supported
-- department/domain move TOCTOU.  The final UPDATE repeats domain containment
-- in its own WHERE (R3) even though the row is already locked.
--
-- BZ060: target disappeared.
-- BZ061: target is outside the actor's current domain/OU reach.
CREATE OR REPLACE FUNCTION admin_reset_password(
    p_actor_id       BIGINT,
    p_target_id      BIGINT,
    p_domain_scope   BIGINT,
    p_password_hash  TEXT,
    p_must_change    BOOLEAN
) RETURNS BIGINT
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_domain_scope BIGINT := NULLIF(p_domain_scope, 0);
    v_revocation_id BIGINT;
BEGIN
    IF p_actor_id IS NULL OR p_target_id IS NULL OR p_password_hash IS NULL THEN
        RAISE EXCEPTION 'administrator password reset target not found'
            USING ERRCODE='BZ060',
                  HINT='{"type":"admin_reset_target_not_found"}';
    END IF;

    -- Global administrative lock order: authority topology precedes the person
    -- fence, which precedes user/OAuth/session rows.
    PERFORM admin_authority_fence();
    PERFORM identity_auth_person_fence(p_target_id);

    -- Locks the target users row and enforces self/domination/last-SA policy.
    PERFORM admin_protection_check(
        p_actor_id, p_target_id, 'password_reset', NULL
    );

    IF NOT EXISTS (SELECT 1 FROM users WHERE id=p_target_id) THEN
        RAISE EXCEPTION 'administrator password reset target not found'
            USING ERRCODE='BZ060',
                  HINT='{"type":"admin_reset_target_not_found"}';
    END IF;

    -- Authorize against the state protected by admin_protection_check's row
    -- lock, not the stale pre-bcrypt state observed by the gateway.
    -- The gateway's JWT permission claim may be stale after an assignment is
    -- revoked. Require one live persisted assignment that simultaneously owns
    -- the password-reset permission and current reach; zero assignments are a
    -- denial here, never admin_can_manage's compatibility fail-open.
    IF NOT admin_can_manage_with_permission(
             p_actor_id, p_target_id, 'users.password_reset'
           )
       OR (v_domain_scope IS NOT NULL AND NOT EXISTS (
            SELECT 1
              FROM users
             WHERE id=p_target_id
               AND COALESCE(guest_account_host_domain(id), domain_id)
                   = v_domain_scope
       ))
    THEN
        RAISE EXCEPTION 'administrator password reset target not found'
            USING ERRCODE='BZ061',
                  HINT='{"type":"admin_reset_target_out_of_scope"}';
    END IF;

    -- Guest classification happens only after the privacy-preserving current
    -- reach decision, so an out-of-scope guest and an unknown member are
    -- indistinguishable. In-scope guests keep the friendly conflict contract.
    IF is_guest_account(p_target_id) THEN
        RAISE EXCEPTION 'guest accounts are managed through the guest console'
            USING ERRCODE='BZ221',
                  HINT='{"type":"guest_target_requires_guest_console"}';
    END IF;

    UPDATE users
       SET password_hash=p_password_hash,
           must_change_password=COALESCE(p_must_change, TRUE)
     WHERE id=p_target_id
       AND (v_domain_scope IS NULL
            OR COALESCE(guest_account_host_domain(id), domain_id)
               = v_domain_scope);

    IF NOT FOUND THEN
        RAISE EXCEPTION 'administrator password reset target not found'
            USING ERRCODE='BZ060',
                  HINT='{"type":"admin_reset_target_not_found"}';
    END IF;

    SELECT revoke_user_sessions(
        p_target_id,
        'all',
        'admin_password_reset',
        p_actor_id,
        NULL,
        NULL
    ) INTO v_revocation_id;

    -- WP3 audit coverage: a credential reset is a core lifecycle transition —
    -- durable evidence in the same transaction as the mutation and revocation
    -- (never the hash itself, only the fact + must_change flag).
    PERFORM audit_write(
        p_actor_id, 'admin_reset_password', 'user', p_target_id,
        NULL,
        jsonb_build_object('must_change_password', COALESCE(p_must_change, TRUE),
                           'sessions_revoked', v_revocation_id),
        NULL, NULL, 'core');

    RETURN v_revocation_id;
END;
$$;

SELECT apply_worker_ownership(
    'admin_reset_password(bigint,bigint,bigint,text,boolean)'::regprocedure
);
