-- #335: canonical factor person/users fence and durable established-session check.
CREATE OR REPLACE FUNCTION rust_identity_webauthn_fence(p_user_id bigint,p_claims jsonb)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_generation bigint;
BEGIN
    PERFORM identity_auth_person_fence(p_user_id);
    SELECT factor_generation INTO v_generation FROM users WHERE id=p_user_id FOR NO KEY UPDATE;
    IF NOT FOUND THEN RETURN jsonb_build_object('status','internal'); END IF;
    IF EXISTS(SELECT 1 FROM session_revocations WHERE user_id=p_user_id
        AND (expires_at IS NULL OR expires_at>now()) AND
        ((scope='jti' AND jti=COALESCE(p_claims->>'jti',''))
        OR (scope='family' AND family_id=COALESCE(p_claims->>'fam',''))
        OR (scope='all' AND (p_claims->>'iat' IS NULL OR to_timestamp((p_claims->>'iat')::double precision)<=not_before)))) THEN
        RETURN jsonb_build_object('status','revoked');
    END IF;
    RETURN jsonb_build_object('status','ready','generation',v_generation);
END;
$$;
