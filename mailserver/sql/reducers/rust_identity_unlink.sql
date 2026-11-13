-- #341: unchanged frozen unlink reducer and private COMMIT inspection receipt.
CREATE OR REPLACE FUNCTION rust_identity_unlink(
    p_actor bigint,p_link_id bigint,p_reason text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_result jsonb;
BEGIN
    v_result:=identity_auth_unlink(p_actor,p_link_id,p_reason);
    INSERT INTO rust_operation_receipts(operation_id,family,command)
    VALUES(current_setting('app.rust_operation_id')::uuid,'F21','identity-unlink');
    RETURN v_result;
END;
$$;
