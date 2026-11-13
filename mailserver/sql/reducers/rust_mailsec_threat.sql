-- Frozen Go's admin IP-rule writes (admin.IPRulesHandler.Create and .Delete, F06 slice threat) as
-- one transaction each: the ip_rules change and the best-effort audit row Go writes after it.
-- ip_rules is a global admin table (no tenant column); the gateway has already checked the
-- caller's security.write grant. The actor (created_by, audit actor) is the verified token's
-- user (R2), never a request field.

-- POST /admin/threat/ip-rules. Go binds the CIDR to $1::inet and the expiry text to the
-- timestamptz column, so a value PostgreSQL rejects (including an empty expiry) fails the call.
CREATE OR REPLACE FUNCTION rust_mailsec_ip_rule_create(
 p_actor bigint,p_cidr text,p_action text,p_description text,p_expires text,p_ip text
) RETURNS bigint LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_id bigint;
BEGIN
 INSERT INTO ip_rules (cidr, action, description, expires_at, created_by)
  VALUES (p_cidr::inet, p_action, p_description, p_expires::timestamptz, p_actor)
  RETURNING id INTO v_id;
 PERFORM audit_write(p_actor, 'ip_rule_create', 'ip_rule', v_id,
  jsonb_build_object('cidr', p_cidr, 'action_value', p_action, 'description', p_description),
  NULL, NULLIF(p_ip, '')::inet, '', 'core');
 RETURN v_id;
END;
$$;

-- DELETE /admin/threat/ip-rules/{id}: the audit row records the deleted rule's CIDR and action;
-- a missing id changes nothing (false).
CREATE OR REPLACE FUNCTION rust_mailsec_ip_rule_delete(p_actor bigint,p_id bigint,p_ip text)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_cidr text; v_action text;
BEGIN
 DELETE FROM ip_rules WHERE id = p_id RETURNING cidr::text, action INTO v_cidr, v_action;
 IF NOT FOUND THEN
  RETURN false;
 END IF;
 PERFORM audit_write(p_actor, 'ip_rule_delete', 'ip_rule', p_id,
  jsonb_build_object('cidr', v_cidr, 'action_value', v_action),
  NULL, NULLIF(p_ip, '')::inet, '', 'core');
 RETURN true;
END;
$$;
