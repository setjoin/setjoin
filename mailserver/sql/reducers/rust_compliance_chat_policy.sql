-- Frozen-Go policy data + best-effort core audit (#291). The HTTP adapter
-- passes only its verified actor and whether Go trusts that non-admin token's
-- signed grant. Live governed admin grants are fenced in each mutation.
CREATE OR REPLACE FUNCTION rust_compliance_chat_policy(
 p_actor bigint,p_signed boolean,p_action text,p_id bigint,p_data jsonb,
 p_confirm text,p_ip text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
 SET search_path=pg_catalog,public AS $$
DECLARE
 v_id bigint;
 v_effective text;
 v_after jsonb;
 v_current record;
 v_exposed bigint;
 v_more boolean;
BEGIN
 IF p_actor IS NULL OR p_actor<=0 THEN RETURN '{"status":403}'::jsonb; END IF;
 IF NOT (p_actor>0 AND (p_signed OR EXISTS (SELECT 1 FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id=ra.role_group_id WHERE ra.user_id=p_actor AND 'chat.compliance_manage'=ANY(rg.permissions) AND (ra.expires_at IS NULL OR ra.expires_at>now()) AND admin_assignment_active(ra.eligible,ra.activated_until)))) THEN RETURN '{"status":403}'::jsonb; END IF;
 IF p_action='create' THEN
  INSERT INTO chat_retention_policies(name,applies_to,duration_days,enabled)
  SELECT p_data->>'name',p_data->>'appliesTo',(p_data->>'durationDays')::int,(p_data->>'enabled')::boolean
  WHERE p_actor>0 AND (p_signed OR EXISTS (
   SELECT 1 FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id=ra.role_group_id
   WHERE ra.user_id=p_actor AND 'chat.compliance_manage'=ANY(rg.permissions)
    AND (ra.expires_at IS NULL OR ra.expires_at>now())
    AND admin_assignment_active(ra.eligible,ra.activated_until)))
  RETURNING id,effective_at::text INTO v_id,v_effective;
  IF v_id IS NULL THEN RETURN '{"status":403}'::jsonb; END IF;
  v_after:=jsonb_build_object('id',v_id,'name',p_data->>'name','appliesTo',p_data->>'appliesTo',
   'durationDays',(p_data->>'durationDays')::bigint,'enabled',(p_data->>'enabled')::boolean);
  BEGIN
   PERFORM audit_write(p_actor,'chat_retention_policy_create','chat_retention_policy',v_id,
    NULL,v_after,NULLIF(p_ip,'')::inet,'','core');
  EXCEPTION WHEN OTHERS THEN NULL; -- frozen Go ignores audit.Write failure
  END;
  RETURN jsonb_build_object('status',201,'body',jsonb_build_object('id',v_id,'effectiveAt',v_effective));
 END IF;
 IF p_action='update' THEN
  SELECT name,applies_to,duration_days,enabled INTO v_current FROM chat_retention_policies WHERE id=p_id;
  IF NOT FOUND THEN RETURN '{"status":404,"error":"policy not found"}'::jsonb; END IF;

WITH before_pol AS (
  SELECT applies_to, duration_days FROM chat_retention_policies
   WHERE enabled AND effective_at <= now()
), after_pol AS (
  SELECT applies_to, duration_days FROM chat_retention_policies
   WHERE id <> p_id AND enabled AND effective_at <= now()
  UNION ALL
  SELECT (p_data->>'appliesTo')::text, (p_data->>'durationDays')::int::int WHERE (p_data->>'enabled')::boolean::boolean
)
SELECT count(*) INTO v_exposed FROM chat_channels c
WHERE COALESCE(c.retention_days,
        (SELECT min(duration_days) FROM after_pol p WHERE p.applies_to = c.kind),
        (SELECT min(duration_days) FROM after_pol p WHERE p.applies_to = 'all'),
        2147483647)
    < COALESCE(c.retention_days,
        (SELECT min(duration_days) FROM before_pol p WHERE p.applies_to = c.kind),
        (SELECT min(duration_days) FROM before_pol p WHERE p.applies_to = 'all'),
        2147483647);
  v_more:=(p_data->>'durationDays')::bigint<v_current.duration_days
   OR ((p_data->>'enabled')::boolean AND NOT v_current.enabled)
   OR p_data->>'appliesTo'<>v_current.applies_to OR v_exposed>0;
  UPDATE chat_retention_policies SET name=p_data->>'name',applies_to=p_data->>'appliesTo',
   duration_days=(p_data->>'durationDays')::int,enabled=(p_data->>'enabled')::boolean,
   effective_at=CASE WHEN v_more THEN GREATEST(effective_at,now()+interval '7 days') ELSE effective_at END,
   updated_at=now()
  WHERE id=p_id AND p_actor>0 AND (p_signed OR EXISTS (SELECT 1 FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id=ra.role_group_id WHERE ra.user_id=p_actor AND 'chat.compliance_manage'=ANY(rg.permissions) AND (ra.expires_at IS NULL OR ra.expires_at>now()) AND admin_assignment_active(ra.eligible,ra.activated_until)))
  RETURNING effective_at::text INTO v_effective;
  IF NOT FOUND THEN RAISE EXCEPTION 'policy update failed' USING ERRCODE='P0002'; END IF;
  BEGIN
   PERFORM audit_write(p_actor,'chat_retention_policy_update','chat_retention_policy',p_id,
    NULL,p_data||jsonb_build_object('id',p_id,'moreDestructive',v_more),NULLIF(p_ip,'')::inet,'','core');
  EXCEPTION WHEN OTHERS THEN NULL;
  END;
  RETURN jsonb_build_object('status',200,'body',jsonb_build_object('effectiveAt',v_effective));
 END IF;
 IF p_action='delete' THEN

WITH before_pol AS (
  SELECT applies_to, duration_days FROM chat_retention_policies
   WHERE enabled AND effective_at <= now()
), after_pol AS (
  SELECT applies_to, duration_days FROM chat_retention_policies
   WHERE id <> p_id AND enabled AND effective_at <= now()
  UNION ALL
  SELECT ''::text, 0::int WHERE false::boolean
)
SELECT count(*) INTO v_exposed FROM chat_channels c
WHERE COALESCE(c.retention_days,
        (SELECT min(duration_days) FROM after_pol p WHERE p.applies_to = c.kind),
        (SELECT min(duration_days) FROM after_pol p WHERE p.applies_to = 'all'),
        2147483647)
    < COALESCE(c.retention_days,
        (SELECT min(duration_days) FROM before_pol p WHERE p.applies_to = c.kind),
        (SELECT min(duration_days) FROM before_pol p WHERE p.applies_to = 'all'),
        2147483647);
  IF v_exposed>0 AND p_confirm<>'DESTROY' THEN
   RETURN jsonb_build_object('status',409,'body',jsonb_build_object('code','exposure','exposedChannels',v_exposed));
  END IF;
  DELETE FROM chat_retention_policies WHERE id=p_id AND p_actor>0 AND (p_signed OR EXISTS (SELECT 1 FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id=ra.role_group_id WHERE ra.user_id=p_actor AND 'chat.compliance_manage'=ANY(rg.permissions) AND (ra.expires_at IS NULL OR ra.expires_at>now()) AND admin_assignment_active(ra.eligible,ra.activated_until)));
  IF NOT FOUND THEN RETURN '{"status":404,"error":"policy not found"}'::jsonb; END IF;
  BEGIN
   PERFORM audit_write(p_actor,'chat_retention_policy_delete','chat_retention_policy',p_id,
    NULL,NULL,NULLIF(p_ip,'')::inet,'','core');
  EXCEPTION WHEN OTHERS THEN NULL;
  END;
  RETURN '{"status":204}'::jsonb;
 END IF;
 RAISE EXCEPTION 'unsupported chat policy operation' USING ERRCODE='22023';
END;
$$;
SELECT apply_worker_ownership('rust_compliance_chat_policy(bigint,boolean,text,bigint,jsonb,text,text)'::regprocedure);
