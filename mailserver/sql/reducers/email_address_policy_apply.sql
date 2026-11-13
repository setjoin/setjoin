-- Email-only. BZ077 eap_alias_conflict — prior primary already owned elsewhere.
-- BZ078 eap_nonlocal_domain — rendered address is not in a local domain.
-- Additional-template aliases are best-effort: a colliding one is coalesced
-- (ON CONFLICT DO NOTHING); only the PRIMARY gets numeric-suffix disambiguation.
CREATE OR REPLACE FUNCTION email_address_policy_apply(
  p_mailbox_id BIGINT, p_user_id BIGINT
) RETURNS TEXT LANGUAGE plpgsql AS $$
DECLARE
  v_optout BOOLEAN; v_dept TEXT; v_dom_id BIGINT; v_mtype TEXT; v_ou TEXT;
  v_policy BIGINT; v_render JSONB; v_new TEXT; v_old TEXT; v_addl JSONB; v_a TEXT;
BEGIN
  SELECT u.address_policy_enabled, d.name, d.ldap_ou
    INTO v_optout, v_dept, v_ou
    FROM users u LEFT JOIN departments d ON d.id = u.department_id
    WHERE u.id = p_user_id;
  IF v_optout IS DISTINCT FROM TRUE THEN RETURN NULL; END IF;

  SELECT m.domain_id, mailbox_effective_type(m.id) INTO v_dom_id, v_mtype
    FROM mailboxes m WHERE m.id = p_mailbox_id;

  SELECT id INTO v_policy FROM email_address_policies p
   WHERE p.enabled
     AND (p.cond_department   IS NULL OR v_dept   = ANY(p.cond_department))
     AND (p.cond_domain_ids   IS NULL OR v_dom_id = ANY(p.cond_domain_ids))
     AND (p.cond_mailbox_type IS NULL OR v_mtype  = ANY(p.cond_mailbox_type))
     AND (p.cond_ad_ou        IS NULL OR v_ou     = ANY(p.cond_ad_ou))
   ORDER BY p.priority ASC LIMIT 1;
  IF v_policy IS NULL THEN RETURN NULL; END IF;

  v_render := email_address_policy_render(v_policy, p_user_id, p_mailbox_id);
  v_new := v_render ->> 'primary';
  SELECT email INTO v_old FROM mailboxes WHERE id = p_mailbox_id;

  -- SECURITY: EAP must only ever assign an address in a LOCAL domain. The renderer
  -- pins the domain, but assert it here too so a non-local address can never reach
  -- mailboxes.email/users.email (which send.sql trusts for send-as authorization).
  IF NOT EXISTS (SELECT 1 FROM domains
                 WHERE lower(name) = lower(split_part(v_new,'@',2)) AND is_local) THEN
    RAISE EXCEPTION 'eap: rendered address % is not in a local domain', v_new
      USING ERRCODE='BZ078', HINT=jsonb_build_object('type','eap_nonlocal_domain','addr',v_new)::TEXT;
  END IF;

  IF lower(v_old) IS DISTINCT FROM lower(v_new) THEN
    INSERT INTO aliases (mailbox_id, email, domain_id)
      SELECT p_mailbox_id, v_old, domain_id FROM mailboxes WHERE id = p_mailbox_id
      ON CONFLICT (lower(email)) DO NOTHING;
    -- If the prior primary could not be retained as THIS mailbox's alias (the
    -- ON CONFLICT above did nothing because another mailbox already owns it),
    -- abort rather than silently strand the old address. The second clause that
    -- used to be AND'd here ("... AND this mailbox's primary isn't v_old") was
    -- always false — v_old is read from this mailbox at line 33 and the primary
    -- isn't replaced until after this guard — so BZ077 was unreachable.
    IF NOT EXISTS (SELECT 1 FROM aliases WHERE lower(email)=lower(v_old) AND mailbox_id=p_mailbox_id) THEN
      RAISE EXCEPTION 'eap: prior primary % already owned elsewhere, cannot retain', v_old
        USING ERRCODE='BZ077', HINT=jsonb_build_object('type','eap_alias_conflict','addr',v_old)::TEXT;
    END IF;
    UPDATE mailboxes SET email = v_new, updated_at = now() WHERE id = p_mailbox_id;
    UPDATE users SET email = v_new WHERE id = p_user_id AND email = v_old;
    INSERT INTO field_policy (user_id, field, policy)
      VALUES (p_user_id, 'email', 'local_only')
      ON CONFLICT (user_id, field) DO UPDATE SET policy = 'local_only', set_at = now();
  END IF;

  v_addl := v_render -> 'additionals';
  IF v_addl IS NOT NULL THEN
    FOR v_a IN SELECT jsonb_array_elements_text(v_addl) LOOP
      -- SECURITY: only install an additional alias if it is in a local domain.
      IF EXISTS (SELECT 1 FROM domains
                 WHERE lower(name) = lower(split_part(v_a,'@',2)) AND is_local) THEN
        INSERT INTO aliases (mailbox_id, email, domain_id)
          SELECT p_mailbox_id, v_a, domain_id FROM mailboxes WHERE id = p_mailbox_id
          ON CONFLICT (lower(email)) DO NOTHING;
      END IF;
    END LOOP;
  END IF;

  PERFORM bump_mailbox_set_state(p_mailbox_id, 'address_policy_applied');

  RETURN v_new;
END;
$$;
