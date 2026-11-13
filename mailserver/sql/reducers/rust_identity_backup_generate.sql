-- #336: frozen recovery-code replacement, generation and checked audit tail.
CREATE OR REPLACE FUNCTION rust_identity_backup_generate(p_user_id bigint,p_hashes text[],p_ip text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
BEGIN
    UPDATE users SET totp_backup_codes_enc=p_hashes WHERE id=p_user_id;
    UPDATE users SET factor_generation=factor_generation+1 WHERE id=p_user_id;
    INSERT INTO admin_audit_log(user_id,ip,action,target_type,target_id)
        VALUES(p_user_id,p_ip::inet,'backup_codes_regenerated','user',p_user_id);
    RETURN jsonb_build_object('status','generated');
END;
$$;
