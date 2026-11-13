-- Frozen Go's DELETE /admin/terms-of-use/{id} (admin.ToUHandler.Delete): capture the row,
-- DELETE it (acceptances cascade) and write the tou.delete core audit row in ONE
-- transaction. Returns {"status":204} or {"status":404} (nothing written).
CREATE OR REPLACE FUNCTION rust_platform_tou_delete(
 p_actor bigint,p_id bigint,p_ip text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_name text; v_version int;
BEGIN
 SELECT name, version INTO v_name, v_version FROM terms_of_use WHERE id=p_id;
 IF NOT FOUND THEN RETURN jsonb_build_object('status',404); END IF;
 DELETE FROM terms_of_use WHERE id=p_id;
 IF NOT FOUND THEN RETURN jsonb_build_object('status',404); END IF;
 PERFORM audit_write(p_actor,'tou.delete','terms_of_use',p_id,
  jsonb_build_object('name',v_name,'version',v_version),NULL,NULLIF(p_ip,'')::inet,'','core');
 RETURN jsonb_build_object('status',204);
END;
$$;
