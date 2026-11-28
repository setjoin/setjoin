-- Frozen Go's PUT /admin/terms-of-use/{id} (admin.ToUHandler.Update): the UPDATE and the
-- tou.update core audit row in ONE transaction. Returns {"status":204} or {"status":404}
-- (nothing written); a database error propagates (Go answers 500 "request failed").
CREATE OR REPLACE FUNCTION rust_platform_tou_update(
 p_actor bigint,p_id bigint,p_name text,p_version bigint,p_body text,p_lang text,
 p_scroll boolean,p_enabled boolean,p_ip text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
BEGIN
 UPDATE terms_of_use SET name=p_name, version=p_version::int, body_md=p_body, lang=p_lang,
   require_scroll=p_scroll, enabled=p_enabled WHERE id=p_id;
 IF NOT FOUND THEN RETURN jsonb_build_object('status',404); END IF;
 PERFORM audit_write(p_actor,'tou.update','terms_of_use',p_id,NULL,
  jsonb_build_object('name',p_name,'version',p_version),NULLIF(p_ip,'')::inet,'','core');
 RETURN jsonb_build_object('status',204);
END;
$$;
