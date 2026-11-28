-- Frozen Go's per-user sign-in history (admin_signin.go): login_events keys its
-- row-level security on app.current_user_id, which Go sets to the TARGET user with
-- dbscope.RunUserScoped. The verified-actor executor cannot set that key, so this
-- read sets it (transaction-local) to the target and returns Go's columns.
CREATE OR REPLACE FUNCTION rust_admin_user_sign_ins(p_target bigint,p_domain_scope bigint)
RETURNS TABLE(id bigint,occurred_at timestamptz,source_ip text,location text,
 device_name text,platform text,client text,protocol text,auth_method text,
 success boolean,fail_reason text)
LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
BEGIN
 PERFORM set_config('app.current_user_id',p_target::text,true);
 RETURN QUERY
 SELECT e.id,e.occurred_at,COALESCE(host(e.source_ip),''),COALESCE(e.location,''),
  COALESCE(e.device_name,''),COALESCE(e.platform,''),COALESCE(e.client,''),
  COALESCE(e.protocol,''),COALESCE(e.auth_method,''),e.success,COALESCE(e.fail_reason,'')
  FROM login_events e WHERE e.user_id=p_target
   AND (p_domain_scope<=0 OR EXISTS (SELECT 1 FROM users u WHERE u.id=p_target AND u.domain_id=p_domain_scope))
  ORDER BY e.occurred_at DESC LIMIT 200;
END;
$$;
