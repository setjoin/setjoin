-- #334: frozen MFA-completion mint transaction, independent of login's cycle.
CREATE OR REPLACE FUNCTION rust_identity_mfa_mint(
    p_user_id bigint,p_claims jsonb,p_token_hash bytea,p_expiry bigint,p_family uuid
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_stage text:='identity';v_hash text;v_hint text;
BEGIN
    IF p_claims->'identity_fence' IS NOT NULL AND p_claims->'identity_fence'<>'null'::jsonb THEN
        IF COALESCE((p_claims#>>'{identity_fence,source_id}')::bigint,0)<=0
           OR COALESCE((p_claims#>>'{identity_fence,source_generation}')::bigint,0)<=0
           OR COALESCE((p_claims#>>'{identity_fence,link_id}')::bigint,0)<=0
           OR COALESCE((p_claims#>>'{identity_fence,link_generation}')::bigint,0)<=0 THEN
            RETURN jsonb_build_object('status','identity_changed');
        END IF;
        PERFORM identity_auth_mint_fence(p_user_id,(p_claims#>>'{identity_fence,source_id}')::bigint,
            (p_claims#>>'{identity_fence,source_generation}')::bigint,(p_claims#>>'{identity_fence,link_id}')::bigint,
            (p_claims#>>'{identity_fence,link_generation}')::bigint);
    ELSE PERFORM identity_auth_local_mint_fence(p_user_id); END IF;
    v_stage:='credential';
    IF COALESCE(p_claims->>'credential_fence','')<>'' THEN
        SELECT password_hash INTO v_hash FROM users WHERE id=p_user_id AND enabled;
        IF NOT FOUND OR translate(rtrim(encode(digest(v_hash,'sha256'),'base64'),'='),'+/','-_')<>p_claims->>'credential_fence' THEN
            RETURN jsonb_build_object('status','credential_changed');
        END IF;
    END IF;

    -- SECURITY-REVOCATION-BEGIN: owner-approved security fix 2026-11-05.
    -- The identity/person fence serializes this check with session revocation.
    IF p_claims->>'typ'='mfa_pending' AND EXISTS(
        SELECT 1 FROM session_revocations WHERE user_id=p_user_id
        AND (expires_at IS NULL OR expires_at>now()) AND
        ((scope='jti' AND jti=COALESCE(p_claims->>'jti',''))
        OR (scope='family' AND family_id=COALESCE(p_claims->>'fam',''))
        OR (scope='all' AND (p_claims->>'iat' IS NULL OR to_timestamp((p_claims->>'iat')::double precision)<=not_before)))) THEN
        RETURN jsonb_build_object('status','revoked');
    END IF;
    -- SECURITY-REVOCATION-END

    v_stage:='store';
    INSERT INTO oauth_tokens(user_id,token_hash,token_type,expires_at,family_id)
        VALUES(p_user_id,p_token_hash,'refresh',now()+make_interval(secs=>p_expiry),p_family);
    IF NULLIF(current_setting('app.rust_operation_id',true),'') IS NOT NULL THEN
        INSERT INTO rust_operation_receipts(operation_id,family,command)
            VALUES(current_setting('app.rust_operation_id')::uuid,'F21','mfa-mint');
    END IF;
    RETURN jsonb_build_object('status','minted');
EXCEPTION WHEN OTHERS THEN
    GET STACKED DIAGNOSTICS v_hint=PG_EXCEPTION_HINT;
    RETURN jsonb_build_object('status',CASE WHEN v_stage='identity' THEN 'identity_changed' WHEN v_stage='credential' THEN 'credential_changed' ELSE 'store_failed' END,'sqlstate',SQLSTATE,'hint',v_hint);
END;
$$;
