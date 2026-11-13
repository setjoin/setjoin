-- Frozen upsertDevice's scoped SELECT+upsert transaction; audit remains a later
-- independent statement in Rust, like Go. The principal is credential-verified.
CREATE OR REPLACE FUNCTION rust_threat_device(p_user_id bigint,p_hash text,
    p_agent text,p_prefix text,p_country text)
RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER AS $$
DECLARE v_country text; v_new boolean;
BEGIN
    PERFORM set_config('app.current_user_id',p_user_id::text,true);
    SELECT country INTO v_country FROM device_registry
    WHERE user_id=p_user_id AND device_hash=p_hash;
    -- Go scans into a string: a stored NULL is a scan error and counts as new.
    v_new := NOT FOUND OR v_country IS NULL;
    INSERT INTO device_registry(user_id,device_hash,user_agent,ip_prefix,country,first_seen,last_seen,auth_count)
    VALUES(p_user_id,p_hash,p_agent,p_prefix,p_country,now(),now(),1)
    ON CONFLICT(user_id,device_hash) DO UPDATE SET last_seen=now(),
        auth_count=device_registry.auth_count+1,country=EXCLUDED.country;
    RETURN jsonb_build_object('new',v_new,'changed',NOT v_new AND p_country<>'' AND v_country<>p_country,'from',v_country);
END;
$$;
