-- Frozen Go's POST /admin/terms-of-use (admin.ToUHandler.Create): the terms_of_use INSERT and
-- the tou.create core audit row in ONE transaction. p_actor is the verified token's user.
-- Returns {"id":n}; any database error propagates (Go answers 500 "request failed").
CREATE OR REPLACE FUNCTION rust_platform_tou_create(
 p_actor bigint,p_name text,p_version bigint,p_body text,p_lang text,
 p_scroll boolean,p_enabled boolean,p_ip text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_id bigint;
BEGIN
 INSERT INTO terms_of_use (name, version, body_md, lang, require_scroll, enabled)
 VALUES (p_name, p_version::int, p_body, p_lang, p_scroll, p_enabled) RETURNING id INTO v_id;
 PERFORM audit_write(p_actor,'tou.create','terms_of_use',v_id,NULL,
  jsonb_build_object('name',p_name,'version',p_version),NULLIF(p_ip,'')::inet,'','core');
 RETURN jsonb_build_object('id',v_id);
END;
$$;
