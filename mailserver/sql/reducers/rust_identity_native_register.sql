-- #336: frozen native approval-device registration transaction.
CREATE OR REPLACE FUNCTION rust_identity_native_register(
    p_user_id bigint,p_claims jsonb,p_hash text,p_provider text,p_token text,
    p_key bytea,p_name text,p_ip text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_gate jsonb;
BEGIN
    v_gate:=rust_identity_possession_consume(p_user_id,p_claims,p_hash,'device.register.native',FALSE,NULL);
    IF v_gate->>'status' IS DISTINCT FROM 'ready' THEN
        RETURN COALESCE(v_gate,jsonb_build_object('status','internal'));
    END IF;
    INSERT INTO push_devices(user_id,push_provider,push_token_enc,device_public_key,device_name)
        VALUES(p_user_id,p_provider,pgp_sym_encrypt(p_token,current_setting('app.encryption_key'))::bytea,p_key,p_name)
        ON CONFLICT DO NOTHING;
    UPDATE users SET factor_generation=factor_generation+1 WHERE id=p_user_id;
    INSERT INTO admin_audit_log(user_id,ip,action,target_type,target_id)
        VALUES(p_user_id,p_ip::inet,'device_registered','user',p_user_id);
    RETURN jsonb_build_object('status','registered');
END;
$$;
