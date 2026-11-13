-- Frozen threat.RecordSignIn: one independent best-effort auth-time transaction.
CREATE OR REPLACE FUNCTION rust_threat_signin(p_user_id bigint,p_success boolean,
    p_protocol text,p_method text,p_ip text,p_country text)
RETURNS void LANGUAGE plpgsql SECURITY INVOKER AS $$
BEGIN
    IF p_user_id > 0 THEN
        PERFORM set_config('app.current_user_id',p_user_id::text,true);
    END IF;
    INSERT INTO login_events(user_id,source_ip,location,success,client,protocol,auth_method,occurred_at)
    VALUES(NULLIF(p_user_id,0),NULLIF(p_ip,'')::inet,NULLIF(p_country,''),p_success,p_protocol,p_protocol,p_method,now());
END;
$$;
