-- Read-only render of ONE policy for ONE recipient. Returns
--   {"primary": text, "additionals": text[], "collided": bool, "suffix": int}
-- BZ075 eap_collision_exhausted; BZ076 eap_empty_local_part.
CREATE OR REPLACE FUNCTION email_address_policy_render(
  p_policy_id BIGINT, p_user_id BIGINT, p_mailbox_id BIGINT
) RETURNS JSONB LANGUAGE plpgsql AS $$
DECLARE
  v_primary_tpl TEXT; v_addl_tpls TEXT[];
  v_first TEXT; v_last TEXT; v_uname TEXT; v_dept TEXT;
  v_dom_id BIGINT; v_dom TEXT;
  v_email TEXT; v_base_local TEXT; v_suffix INT := 1;
  v_out_addl TEXT[] := ARRAY[]::TEXT[]; v_t TEXT; v_collided BOOLEAN := FALSE;
BEGIN
  SELECT primary_template, additional_templates INTO v_primary_tpl, v_addl_tpls
    FROM email_address_policies WHERE id = p_policy_id;
  IF v_primary_tpl IS NULL THEN RETURN NULL; END IF;

  SELECT u.first_name, u.last_name, u.username, d.name
    INTO v_first, v_last, v_uname, v_dept
    FROM users u LEFT JOIN departments d ON d.id = u.department_id
    WHERE u.id = p_user_id;
  SELECT m.domain_id INTO v_dom_id FROM mailboxes m WHERE m.id = p_mailbox_id;
  SELECT dom.name INTO v_dom FROM domains dom WHERE dom.id = v_dom_id;

  v_email := email_address_policy_render_one(v_primary_tpl, v_first, v_last, v_uname, v_dept, v_dom);
  IF split_part(v_email,'@',1) = '' THEN
    RAISE EXCEPTION 'email_address_policy_render: empty local-part for policy %', p_policy_id
      USING ERRCODE='BZ076', HINT=jsonb_build_object('type','eap_empty_local_part','policy_id',p_policy_id)::TEXT;
  END IF;
  v_base_local := split_part(v_email,'@',1);

  WHILE EXISTS (
      SELECT 1 FROM mailboxes WHERE lower(email)=lower(v_email) AND id <> p_mailbox_id
      UNION ALL
      SELECT 1 FROM aliases   WHERE lower(email)=lower(v_email) AND mailbox_id <> p_mailbox_id
      UNION ALL
      SELECT 1 FROM users WHERE lower(email)=lower(v_email) AND id <> p_user_id
  ) LOOP
    v_collided := TRUE; v_suffix := v_suffix + 1;
    IF v_suffix > 999 THEN
      RAISE EXCEPTION 'email_address_policy_render: collision suffix exhausted'
        USING ERRCODE='BZ075', HINT=jsonb_build_object('type','eap_collision_exhausted','policy_id',p_policy_id)::TEXT;
    END IF;
    v_email := v_base_local || v_suffix::TEXT || '@' || v_dom;
  END LOOP;

  IF v_addl_tpls IS NOT NULL THEN
    FOREACH v_t IN ARRAY v_addl_tpls LOOP
      v_out_addl := array_append(v_out_addl, email_address_policy_render_one(v_t, v_first, v_last, v_uname, v_dept, v_dom));
    END LOOP;
  END IF;

  RETURN jsonb_build_object('primary', v_email, 'additionals', to_jsonb(v_out_addl),
                            'collided', v_collided, 'suffix', CASE WHEN v_collided THEN v_suffix ELSE 0 END);
END;
$$;
