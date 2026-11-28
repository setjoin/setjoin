-- #336: TOTP cycle and grant under the retained canonical fences.
DROP FUNCTION IF EXISTS rust_identity_possession_totp_issue(bigint,jsonb,text,text,text,boolean);
CREATE OR REPLACE FUNCTION rust_identity_possession_totp_issue(
    p_user_id bigint,p_claims jsonb,p_operation text,p_target text,p_hash text,p_valid boolean,p_counter bigint,p_secret_hash bytea
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_outcome text;
BEGIN
    v_outcome:=rust_identity_totp_cycle(p_user_id,p_valid,p_counter,p_secret_hash);
    IF v_outcome IS DISTINCT FROM 'accepted' THEN RETURN jsonb_build_object('status',v_outcome); END IF;
    IF p_target IS NOT NULL AND NOT EXISTS(SELECT 1 FROM passkey_credentials
        WHERE user_id=p_user_id AND id=decode(translate(p_target,'-_','+/') || repeat('=',(4-length(p_target)%4)%4),'base64')
        AND revoked_at IS NULL) THEN
        -- Go rolls the accepted cycle back when target ownership fails.
        RAISE EXCEPTION 'invalid possession target' USING ERRCODE='22023',HINT='possession_invalid_target';
    END IF;
    DELETE FROM mfa_reauth_step_ups WHERE user_id=p_user_id;
    INSERT INTO mfa_reauth_step_ups(token_hash,user_id,session_jti,operation,target_ref,
        proof_method,proving_factor_id,bound_factor_generation,token_scope,refresh_family_id,expires_at)
        SELECT p_hash,p_user_id,COALESCE(p_claims->>'jti',''),p_operation,p_target,'totp',NULL,
            factor_generation,'session',NULLIF(p_claims->>'fam',''),now()+interval '5 minutes'
        FROM users WHERE id=p_user_id;
    RETURN jsonb_build_object('status','issued');
END;
$$;
