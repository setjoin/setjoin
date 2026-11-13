-- #494: frozen-Go actor-owned default switch. Whole-function exception
-- rollback preserves every flag on failure; the outer command aborts its receipt.
CREATE OR REPLACE FUNCTION rust_identity_smime_cert_default(
    p_user_id bigint, p_cert_id bigint
) RETURNS text LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE
    v_phase text := 'lookup';
BEGIN
    IF NOT EXISTS (SELECT 1 FROM user_smime_certs
                   WHERE id = p_cert_id AND user_id = p_user_id) THEN
        RETURN 'not-found';
    END IF;
    v_phase := 'update';
    UPDATE user_smime_certs SET is_default = (id = p_cert_id)
    WHERE user_id = p_user_id;
    RETURN 'ok';
EXCEPTION WHEN OTHERS THEN
    RETURN v_phase;
END;
$$;
