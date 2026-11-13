-- Frozen Go's admin user Update transaction (admin_users.go): the suspend
-- protection check when disabling, an UPDATE that names only the supplied columns
-- (Go's UpdateBuilder; a column named in SET fires UPDATE OF triggers, so the SET
-- list is built from what the request carries) with the domain scope in the same
-- WHERE, then the user.updated publication. Returns {status,detail|queued};
-- the adapter rolls back every non-204 status. admin_protection_check errors
-- propagate so the adapter can audit the denial after the rollback.
CREATE OR REPLACE FUNCTION rust_admin_user_update(
 p_actor bigint,p_id bigint,p_domain_scope bigint,
 p_display_name text,p_enabled boolean,p_is_local_admin boolean
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_sets text[]:=ARRAY[]::text[]; v_sql text; v_rows bigint; v_queued boolean;
BEGIN
 IF p_enabled IS NOT NULL AND NOT p_enabled THEN
  PERFORM admin_protection_check(p_actor,p_id,'suspend',NULL);
 END IF;
 IF p_display_name IS NOT NULL THEN v_sets:=array_append(v_sets,'display_name=$3'); END IF;
 IF p_enabled IS NOT NULL THEN v_sets:=array_append(v_sets,'enabled=$4'); END IF;
 IF p_is_local_admin IS NOT NULL THEN v_sets:=array_append(v_sets,'is_local_admin=$5'); END IF;
 IF cardinality(v_sets)=0 THEN
  RETURN jsonb_build_object('status',400,'detail','no fields to update');
 END IF;
 v_sql:='UPDATE users SET '||array_to_string(v_sets,', ')||' WHERE id=$1 AND ($2<=0 OR domain_id=$2)';
 EXECUTE v_sql USING p_id,p_domain_scope,p_display_name,p_enabled,p_is_local_admin;
 GET DIAGNOSTICS v_rows=ROW_COUNT;
 IF v_rows=0 THEN
  RETURN jsonb_build_object('status',404,'detail','admin user not found');
 END IF;
 v_queued:=webhook_user_changed_publish(p_actor,p_id,'user.updated');
 RETURN jsonb_build_object('status',204,'queued',v_queued);
END;
$$;
