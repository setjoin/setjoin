-- Frozen Go issueTokensWithFactors: local identity fence + credential-version
-- recheck + TokenService.IssueTx refresh anchor, in the same transaction (#331).
-- p_user_id and p_password_hash come ONLY from a server-verified password proof.
-- No mailbox is invented for mailbox-less people. No state bump/notify in Go.
CREATE OR REPLACE FUNCTION rust_identity_login_mint(
    p_user_id bigint, p_password_hash text, p_token_hash bytea,
    p_expiry_seconds bigint, p_family_id uuid
) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
BEGIN
    PERFORM identity_auth_local_mint_fence(p_user_id);
    INSERT INTO oauth_tokens(user_id,token_hash,token_type,expires_at,family_id)
    SELECT id,p_token_hash,'refresh',now()+make_interval(secs=>p_expiry_seconds),p_family_id
      FROM users WHERE id=p_user_id AND enabled AND password_hash=p_password_hash;
    RETURN FOUND;
END;
$$;
