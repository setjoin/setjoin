-- #336: an assertion signature has been verified against p_key. Revalidate
-- live ownership and counter under the canonical fence before claiming it.
CREATE OR REPLACE FUNCTION rust_identity_webauthn_login_claim(
    p_user_id bigint,p_id bytea,p_key bytea,p_count integer,p_challenge bytea
) RETURNS text LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_count integer;
BEGIN
    PERFORM identity_auth_local_mint_fence(p_user_id);
    SELECT sign_count INTO v_count FROM passkey_credentials
        WHERE user_id=p_user_id AND id=p_id AND public_key=p_key AND revoked_at IS NULL
        FOR UPDATE;
    IF NOT FOUND THEN RETURN 'credential unavailable'; END IF;
    -- SECURITY-ASSERTION-BEGIN: owner-approved security fix 2026-11-05.
    IF EXISTS(SELECT 1 FROM webauthn_login_replays WHERE user_id=p_user_id AND challenge_hash=p_challenge) THEN
        RETURN 'challenge already used';
    END IF;
    IF NOT ((v_count=0 AND p_count=0) OR p_count>v_count) THEN
        RETURN 'invalid credential counter';
    END IF;
    INSERT INTO webauthn_login_replays(user_id,challenge_hash) VALUES(p_user_id,p_challenge)
        ON CONFLICT(user_id,challenge_hash) DO NOTHING;
    IF NOT FOUND THEN RETURN 'challenge already used'; END IF;
    -- SECURITY-ASSERTION-END
    UPDATE passkey_credentials SET sign_count=greatest(v_count,p_count),last_used_at=now()
        WHERE user_id=p_user_id AND id=p_id AND public_key=p_key AND revoked_at IS NULL;
    RETURN 'accepted';
END;
$$;
