-- #336: device proof is evaluated while both owned challenge/device locks live.
CREATE OR REPLACE FUNCTION rust_identity_push_approval_read(p_user_id bigint,p_nonce bytea,p_device_id bigint)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_row record;
BEGIN
    SELECT c.id,c.user_id,c.challenge_code,COALESCE(c.session_id,'') AS session_id,
        EXTRACT(EPOCH FROM c.expires_at)::bigint AS expires_at,c.failed_attempts,d.device_public_key
    INTO v_row FROM push_mfa_challenges c
    JOIN push_devices d ON d.id=p_device_id AND d.user_id=p_user_id AND d.user_id=c.user_id
    WHERE c.user_id=p_user_id AND c.nonce=p_nonce AND c.verified_at IS NULL
      AND c.expires_at>now() AND d.revoked_at IS NULL AND d.device_public_key IS NOT NULL
    ORDER BY c.created_at DESC LIMIT 1 FOR UPDATE OF c,d;
    IF NOT FOUND THEN RETURN jsonb_build_object('status','invalid'); END IF;
    RETURN jsonb_build_object('status','ready','id',v_row.id,'user',v_row.user_id,
        'code',v_row.challenge_code,'session',v_row.session_id,'expires',v_row.expires_at,
        'failures',v_row.failed_attempts,'key',encode(v_row.device_public_key,'hex'));
END;
$$;

CREATE OR REPLACE FUNCTION rust_identity_push_approval_finish(p_user_id bigint,p_challenge_id bigint,p_result text)
RETURNS text LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
BEGIN
    IF p_result='burn' THEN
        UPDATE push_mfa_challenges SET verified_at=now() WHERE id=p_challenge_id AND user_id=p_user_id;
    ELSIF p_result='wrong' THEN
        UPDATE push_mfa_challenges SET failed_attempts=failed_attempts+1,
            verified_at=CASE WHEN failed_attempts+1>=3 THEN now() ELSE verified_at END
            WHERE id=p_challenge_id AND user_id=p_user_id;
    ELSIF p_result='accepted' THEN
        UPDATE push_mfa_challenges SET verified_at=now(),approved_at=now()
            WHERE id=p_challenge_id AND user_id=p_user_id AND verified_at IS NULL AND expires_at>now();
        RETURN 'accepted';
    END IF;
    RETURN 'invalid';
END;
$$;
