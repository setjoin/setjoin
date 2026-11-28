-- #336: frozen session grant consumption, including committed mismatch cleanup.
CREATE OR REPLACE FUNCTION rust_identity_possession_consume(
    p_user_id bigint,p_claims jsonb,p_hash text,p_operation text,p_target_bound boolean,p_target text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE
    v_generation bigint; v_enabled boolean; v_grant mfa_reauth_step_ups%ROWTYPE;
    v_jti text:=COALESCE(p_claims->>'jti',''); v_family text:=NULLIF(p_claims->>'fam','');
    v_live boolean; v_notes text;
BEGIN
    PERFORM identity_auth_person_fence(p_user_id);
    SELECT factor_generation,COALESCE(totp_enabled,FALSE) INTO STRICT v_generation,v_enabled
        FROM users WHERE id=p_user_id FOR NO KEY UPDATE;
    IF EXISTS(SELECT 1 FROM session_revocations WHERE user_id=p_user_id
        AND (expires_at IS NULL OR expires_at>now()) AND
        ((scope='jti' AND jti=v_jti) OR (scope='family' AND family_id=COALESCE(v_family,''))
         OR (scope='all' AND (p_claims->>'iat' IS NULL OR to_timestamp((p_claims->>'iat')::double precision)<=not_before)))) THEN
        RETURN jsonb_build_object('status','revoked');
    END IF;
    IF p_hash IS NULL THEN RETURN jsonb_build_object('status','reauth','notes','factor mutation without a fresh possession proof'); END IF;
    -- A dead proving factor restores the consumed proof, as Go's rollback does.
    BEGIN
        DELETE FROM mfa_reauth_step_ups WHERE token_hash=p_hash AND user_id=p_user_id
            AND session_jti=v_jti AND operation=p_operation AND token_scope='session'
            AND refresh_family_id IS NOT DISTINCT FROM v_family
            AND (NOT p_target_bound OR target_ref IS NOT DISTINCT FROM p_target)
            AND expires_at>now() AND bound_factor_generation=v_generation RETURNING * INTO v_grant;
        IF NOT FOUND THEN
            DELETE FROM mfa_reauth_step_ups WHERE token_hash=p_hash AND user_id=p_user_id
                AND session_jti=v_jti AND expires_at>now();
            v_notes:=CASE WHEN FOUND THEN 'possession proof refused: operation/target/scope/generation mismatch'
                ELSE 'possession proof missing' END;
            RETURN jsonb_build_object('status','reauth','notes',v_notes);
        END IF;
        v_live:=TRUE;
        IF v_grant.proof_method='totp' THEN v_live:=v_enabled;
        ELSIF v_grant.proof_method='webauthn_uv' THEN
            SELECT EXISTS(SELECT 1 FROM passkey_credentials WHERE user_id=p_user_id
                AND id=v_grant.proving_factor_id AND revoked_at IS NULL) INTO v_live;
        END IF;
        IF NOT v_live THEN RAISE EXCEPTION 'rust possession proving factor dead' USING ERRCODE='22023'; END IF;
        RETURN jsonb_build_object('status','ready');
    EXCEPTION WHEN SQLSTATE '22023' THEN
        IF SQLERRM<>'rust possession proving factor dead' THEN RAISE; END IF;
        RETURN jsonb_build_object('status','reauth','notes','possession proof refused: proving factor no longer live');
    END;
END;
$$;
