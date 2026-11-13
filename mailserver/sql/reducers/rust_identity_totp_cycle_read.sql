-- #334: read-only preparation, holding the users fence through Rust crypto.
CREATE OR REPLACE FUNCTION rust_identity_totp_cycle_read(p_user_id bigint)
RETURNS TABLE(outcome text, secret text) LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_user users%ROWTYPE;
BEGIN
    SELECT * INTO v_user FROM users WHERE id=p_user_id FOR NO KEY UPDATE;
    IF NOT FOUND THEN RETURN QUERY SELECT 'invalid'::text,NULL::text; RETURN; END IF;
    IF v_user.totp_locked_until>clock_timestamp() THEN
        RETURN QUERY SELECT 'locked'::text,NULL::text; RETURN;
    END IF;
    IF NOT COALESCE(v_user.totp_enabled,FALSE) OR v_user.totp_secret_enc IS NULL THEN
        RETURN QUERY SELECT 'bookkeeping'::text,NULL::text; RETURN;
    END IF;
    RETURN QUERY SELECT 'evaluate'::text,pgp_sym_decrypt(v_user.totp_secret_enc::bytea,current_setting('app.encryption_key'));
END;
$$;
