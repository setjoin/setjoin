-- #494: frozen admin.SMIMEHandler.DeleteCert transaction. This is a USER
-- domain: p_user_id comes only from the verified actor, never a mailbox id.
-- Opaque phase verdicts preserve Go's HTTP projections without exposing SQL
-- details. The exception block rolls back the WHOLE delete/promote pair before
-- returning a failure; the Rust decoder also rolls back its outer receipt.
CREATE OR REPLACE FUNCTION rust_identity_smime_cert_delete(
    p_user_id bigint, p_cert_id bigint
) RETURNS text LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE
    v_default boolean;
    v_phase text := 'delete';
BEGIN
    DELETE FROM user_smime_certs
    WHERE id = p_cert_id AND user_id = p_user_id
    RETURNING is_default INTO v_default;
    IF NOT FOUND THEN
        RETURN 'delete';
    END IF;
    IF v_default THEN
        v_phase := 'promote';
        UPDATE user_smime_certs SET is_default = true
        WHERE user_id = p_user_id
          AND id = (SELECT id FROM user_smime_certs
                    WHERE user_id = p_user_id
                    ORDER BY created_at DESC LIMIT 1);
    END IF;
    RETURN 'ok';
EXCEPTION WHEN OTHERS THEN
    RETURN v_phase;
END;
$$;
