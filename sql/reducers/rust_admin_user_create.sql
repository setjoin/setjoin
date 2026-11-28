-- Frozen Go's admin user Create (admin_users.go), one transaction on the worker
-- credential: resolve the local domain from the RAW request address, domain-scope
-- gate, provision_account (create-only), then the user.created publication.
-- Edge validation (JSON, canonical address, display name, password policy, hash)
-- stays in Rust, in Go's order. Returns {status,detail|id,queued}; the adapter
-- rolls back every non-201 status, so refusals leave no rows or receipt.
CREATE OR REPLACE FUNCTION rust_admin_user_create(
 p_actor bigint,p_raw_email text,p_email text,p_display_name text,
 p_hash text,p_is_local_admin boolean,p_domain_scope bigint
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_tail int; v_domain bigint; v_prov jsonb; v_user bigint; v_queued boolean;
BEGIN
 v_tail:=strpos(reverse(p_raw_email),'@');
 IF v_tail=0 OR v_tail=1 THEN
  RETURN jsonb_build_object('status',400,'detail','email domain is not a local domain');
 END IF;
 SELECT id INTO v_domain FROM domains
  WHERE lower(name)=lower(right(p_raw_email,v_tail-1)) AND is_local=TRUE LIMIT 1;
 IF NOT FOUND THEN
  RETURN jsonb_build_object('status',400,'detail','email domain is not a local domain');
 END IF;
 IF p_domain_scope>0 AND v_domain<>p_domain_scope THEN
  RETURN jsonb_build_object('status',403,'detail','email domain is not in your domain scope');
 END IF;
 BEGIN
  v_prov:=provision_account(p_email=>p_email,p_display_name=>p_display_name,
   p_password_hash=>p_hash,p_is_local_admin=>p_is_local_admin,p_enabled=>TRUE,
   p_sync_source=>'local',p_create_only=>TRUE,p_actor=>p_actor);
 EXCEPTION WHEN unique_violation THEN
  RETURN jsonb_build_object('status',409,'detail','user already exists');
 END;
 IF NOT COALESCE((v_prov->>'created')::boolean,false) THEN
  RETURN jsonb_build_object('status',409,'detail','user already exists');
 END IF;
 v_user:=(v_prov->>'user_id')::bigint;
 v_queued:=webhook_user_changed_publish(p_actor,v_user,'user.created');
 RETURN jsonb_build_object('status',201,'id',v_user,'queued',v_queued);
END;
$$;
