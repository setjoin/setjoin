-- #333: frozen device.RegisterDevice transaction. Principal comes only from
-- RequireUserAuth; caller sets transaction-local app.current_user_id to it.
-- A re-registration updates metadata but never replaces/re-emits the trust root.
CREATE OR REPLACE FUNCTION rust_identity_device_register(
    p_user_id bigint, p_name text, p_platform text, p_os_version text,
    p_app_version text, p_fingerprint text, p_secret_enc bytea
) RETURNS TABLE(device_id bigint, created boolean)
LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE
    v_device_id bigint;
    v_created boolean;
BEGIN
    INSERT INTO devices(user_id,device_name,platform,os_version,app_version,
                        fingerprint,hmac_secret_enc,hmac_secret_key_id,last_seen)
    VALUES(p_user_id,p_name,p_platform,p_os_version,p_app_version,p_fingerprint,
           p_secret_enc,'v1',now())
    ON CONFLICT(user_id,fingerprint) DO UPDATE
       SET device_name=EXCLUDED.device_name,platform=EXCLUDED.platform,
           os_version=EXCLUDED.os_version,app_version=EXCLUDED.app_version,
           last_seen=now()
    RETURNING devices.id,(xmax=0) INTO v_device_id,v_created;
    INSERT INTO device_events(device_id,event_type,event_data)
    VALUES(v_device_id,'registered',jsonb_build_object('platform',p_platform,
           'os_version',p_os_version,'app_version',p_app_version));
    RETURN QUERY SELECT v_device_id,v_created;
END;
$$;
