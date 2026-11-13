-- Frozen Go's AddMember in Go's check order (set lookup, per-type reach and
-- eligibility checks against the actor), the idempotent insert and the
-- scope_set_member_add audit, as one transaction. Returns {status,detail}:
-- 201 added, 200 already a member (no audit), otherwise Go's refusal.
-- Body validation (memberType/memberId present) happens at the edge, as in Go.
--
-- Owner-approved security fix 2026-11-05 (#384, #510): the actor is restricted to sets owned
-- by its domain, derived here from its live scope_sets.manage grants (0 = org-wide grant,
-- -1 = none); the set's domain comes from its row, and a foreign or domain-less set
-- answers 404 as if missing.
DROP FUNCTION IF EXISTS rust_admin_scope_set_member_add(bigint,bigint,text,bigint,text);
DROP FUNCTION IF EXISTS rust_admin_scope_set_member_add(bigint,bigint,text,bigint,text,bigint);
CREATE OR REPLACE FUNCTION rust_admin_scope_set_member_add(
 p_actor bigint,p_set bigint,p_type text,p_member bigint,p_ip text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_scope bigint := admin_domain_restriction(p_actor,ARRAY['scope_sets.manage']); v_domain bigint; v_dynamic boolean; v_eligible boolean; v_rows bigint;
BEGIN
 SELECT domain_id INTO v_domain FROM admin_scope_sets WHERE id=p_set AND (v_scope=0 OR domain_id=v_scope);
 IF NOT FOUND THEN RETURN jsonb_build_object('status',404,'detail','scope set not found'); END IF;
 IF p_type='ou' THEN
  IF NOT admin_scope_within(p_actor,'ou',p_member,v_domain) THEN
   RETURN jsonb_build_object('status',403,'detail','OU is outside your admin reach');
  END IF;
 ELSIF p_type='user' THEN
  IF NOT admin_can_reach(p_actor,p_member) THEN
   RETURN jsonb_build_object('status',403,'detail','user is outside your admin reach');
  END IF;
 ELSIF p_type='group' THEN
  SELECT is_dynamic,(scim_external_id IS NOT NULL OR usable_as_admin_scope)
   INTO v_dynamic,v_eligible FROM distribution_groups WHERE id=p_member;
  IF NOT FOUND THEN RETURN jsonb_build_object('status',404,'detail','group not found'); END IF;
  IF v_dynamic THEN
   RETURN jsonb_build_object('status',400,'detail','dynamic groups cannot be used as admin scope members');
  END IF;
  IF NOT v_eligible THEN
   RETURN jsonb_build_object('status',400,'detail','group is not usable as admin scope (set usable_as_admin_scope or provision via SCIM)');
  END IF;
  IF EXISTS(SELECT 1 FROM distribution_group_members dgm
             JOIN mailboxes mb ON mb.id=dgm.mailbox_id AND mb.is_primary
             WHERE dgm.group_id=p_member AND NOT admin_can_reach(p_actor,mb.user_id)) THEN
   RETURN jsonb_build_object('status',403,'detail','group contains members outside your admin reach');
  END IF;
 ELSE
  RETURN jsonb_build_object('status',400,'detail','memberType must be ou, group, or user');
 END IF;
 INSERT INTO admin_scope_set_members(set_id,member_type,member_id,added_by)
  VALUES(p_set,p_type,p_member,p_actor) ON CONFLICT (set_id,member_type,member_id) DO NOTHING;
 GET DIAGNOSTICS v_rows=ROW_COUNT;
 IF v_rows=0 THEN RETURN jsonb_build_object('status',200); END IF;
 PERFORM audit_write(p_actor,'scope_set_member_add','admin_scope_set',p_set,NULL,
  jsonb_build_object('setId',p_set,'memberType',p_type,'memberId',p_member),
  NULLIF(p_ip,'')::inet,'','core');
 RETURN jsonb_build_object('status',201);
END;
$$;
