-- Frozen Go's UpdateGroupMappings in one transaction, in Go's check order. When a
-- mapping carries an admin_role label: roles.manage held, authority fence, then per
-- label (sorted; Go iterates a map) the governed role id, the role row lock, Rule A
-- against the actor's live permissions and the scope arm via admin_scope_within; the
-- SAML row update or the OIDC config merge; and the mint-authority refresh (a
-- `||` merge of {label:{authorized_by,authorized_at,authorized_perms}}). Mappings
-- without a role label skip the fence. Returns {status,detail}: 204 on success, any
-- other status means nothing was written. Edge validation (body, bounds) stays in
-- Rust, as in Go. An unknown SAML idp still answers 204 (Go ignores the row count).
CREATE OR REPLACE FUNCTION rust_admin_group_mappings_put(
 p_actor bigint,p_type text,p_id text,p_mappings text,p_actor_perms text[]
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE
 v_mappings jsonb := p_mappings::jsonb;
 v_labels text[];
 v_label text;
 v_group bigint;
 v_perms text[];
 v_scope bigint;
 v_missing text;
 v_ok boolean;
 v_authority jsonb := '{}'::jsonb;
 v_config jsonb;
 v_key text;
BEGIN
 SELECT COALESCE(array_agg(DISTINCT m->>'admin_role' ORDER BY m->>'admin_role'),'{}')
  INTO v_labels FROM jsonb_array_elements(v_mappings) m
  WHERE COALESCE(m->>'admin_role','')<>'';
 IF cardinality(v_labels)>0 THEN
  IF NOT ('roles.manage' = ANY(p_actor_perms)) THEN
   RETURN jsonb_build_object('status',403,'detail','roles.manage required to map IdP groups to admin roles');
  END IF;
  PERFORM admin_authority_fence();
  FOREACH v_label IN ARRAY v_labels LOOP
   v_group := CASE v_label WHEN 'super_admin' THEN 1 WHEN 'user_admin' THEN 2
               WHEN 'auditor' THEN 4 WHEN 'read_only' THEN 8 END;
   IF v_group IS NULL THEN
    RETURN jsonb_build_object('status',400,'detail','unknown admin role label: '||v_label);
   END IF;
   SELECT permissions,domain_scope INTO v_perms,v_scope
    FROM admin_role_groups WHERE id=v_group FOR UPDATE;
   IF NOT FOUND THEN
    RETURN jsonb_build_object('status',400,'detail','unknown admin role label: '||v_label);
   END IF;
   SELECT p INTO v_missing FROM unnest(v_perms) WITH ORDINALITY u(p,o)
    WHERE NOT (p = ANY(p_actor_perms)) ORDER BY o LIMIT 1;
   IF v_missing IS NOT NULL THEN
    RETURN jsonb_build_object('status',403,'detail',
     'cannot map a role granting a permission you do not hold: '||v_missing);
   END IF;
   v_ok := admin_scope_within(p_actor,NULL,NULL,v_scope);
   IF NOT v_ok THEN
    RETURN jsonb_build_object('status',403,'detail',
     'cannot map a role granting a scope broader than your own reach');
   END IF;
   v_authority := v_authority || jsonb_build_object(v_label,jsonb_build_object(
    'authorized_by',p_actor,
    'authorized_at',to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),
    'authorized_perms',to_jsonb(v_perms)));
  END LOOP;
 END IF;
 IF p_type='saml' THEN
  UPDATE saml_sp_registrations SET group_mappings=v_mappings WHERE idp_entity_id=p_id;
 ELSIF p_type='oidc' THEN
  v_key := 'oidc_provider_'||p_id||'_config';
  SELECT value INTO v_config FROM system_config WHERE key=v_key;
  IF NOT FOUND THEN
   RETURN jsonb_build_object('status',404,'detail','provider not found');
  END IF;
  IF jsonb_typeof(v_config)<>'object' THEN
   RETURN jsonb_build_object('status',500,'detail','update failed');
  END IF;
  UPDATE system_config SET value=v_config||jsonb_build_object('group_mappings',v_mappings)
   WHERE key=v_key;
 ELSE
  RETURN jsonb_build_object('status',400,'detail','invalid provider type');
 END IF;
 IF cardinality(v_labels)>0 THEN
  INSERT INTO system_config(key,value,updated_at)
   VALUES('sso_admin_role_grant_authority',v_authority,now())
   ON CONFLICT (key) DO UPDATE
    SET value=system_config.value||EXCLUDED.value,updated_at=now();
 END IF;
 RETURN jsonb_build_object('status',204);
END;
$$;
