-- #336: TOTP issuance preparation, retaining the person/users fences through crypto.
CREATE OR REPLACE FUNCTION rust_identity_possession_totp_read(p_user_id bigint,p_claims jsonb)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_user users%ROWTYPE; v_outcome text; v_secret text;
BEGIN
    PERFORM identity_auth_person_fence(p_user_id);
    SELECT * INTO STRICT v_user FROM users WHERE id=p_user_id FOR NO KEY UPDATE;
    IF EXISTS(SELECT 1 FROM session_revocations WHERE user_id=p_user_id
        AND (expires_at IS NULL OR expires_at>now()) AND
        ((scope='jti' AND jti=COALESCE(p_claims->>'jti',''))
         OR (scope='family' AND family_id=COALESCE(p_claims->>'fam',''))
         OR (scope='all' AND (p_claims->>'iat' IS NULL OR to_timestamp((p_claims->>'iat')::double precision)<=not_before)))) THEN
        RETURN jsonb_build_object('status','revoked');
    END IF;
    IF NOT (COALESCE(v_user.totp_enabled,FALSE) OR EXISTS(SELECT 1 FROM passkey_credentials
        WHERE user_id=p_user_id AND revoked_at IS NULL AND uv_capable)) THEN
        RETURN jsonb_build_object('status','password');
    END IF;
    SELECT outcome,secret INTO v_outcome,v_secret FROM rust_identity_totp_cycle_read(p_user_id);
    IF v_outcome='locked' THEN RETURN jsonb_build_object('status','locked'); END IF;
    IF v_outcome<>'evaluate' OR v_secret IS NULL THEN RETURN jsonb_build_object('status','internal'); END IF;
    RETURN jsonb_build_object('status','ready','secret',v_secret);
END;
$$;
