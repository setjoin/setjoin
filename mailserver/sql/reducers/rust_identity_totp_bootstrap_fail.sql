-- #334: Go bootstrap confirmation reports the threshold-crossing failure as locked.
CREATE OR REPLACE FUNCTION rust_identity_totp_bootstrap_fail(p_user_id bigint)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_locked timestamptz;
BEGIN
    UPDATE users SET totp_failed_attempts=totp_failed_attempts+1,
        totp_locked_until=CASE WHEN totp_failed_attempts+1>=5 THEN now()+interval '15 minutes' ELSE totp_locked_until END
        WHERE id=p_user_id AND (totp_locked_until IS NULL OR totp_locked_until<=now()) RETURNING totp_locked_until INTO v_locked;
    IF NOT FOUND OR v_locked>clock_timestamp() THEN RETURN jsonb_build_object('status','locked'); END IF;
    RETURN jsonb_build_object('status','invalid_code');
END;
$$;
