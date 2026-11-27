-- Frozen-Go case-bound chat oversight: canonical business reducer plus the
-- handler's independent best-effort core audit, exposed as one Rust statement.
CREATE OR REPLACE FUNCTION rust_compliance_chat_command(
 p_actor bigint,p_signed boolean,p_action text,p_data jsonb,p_ip text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
 SET search_path=pg_catalog,public AS $$
DECLARE
 v_hold bigint;
 v_result jsonb;
 v_custodian bigint:=(p_data->>'custodianUserId')::bigint;
BEGIN
 IF p_actor IS NULL OR p_actor<=0 THEN RETURN '{"status":403}'::jsonb; END IF;
 IF p_action='hold' THEN
  IF v_custodian IS NOT NULL AND NOT admin_can_reach(p_actor,v_custodian) THEN
   RETURN '{"status":403,"error":"target user is outside your administrative scope"}'::jsonb;
  END IF;
  SELECT chat_case_hold_set(p_actor,(p_data->>'caseId')::bigint,v_custodian,
   (p_data->>'channelId')::bigint,p_data->>'reason') INTO v_hold
  WHERE p_actor>0 AND (p_signed OR EXISTS (
   SELECT 1 FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id=ra.role_group_id
   WHERE ra.user_id=p_actor AND 'chat.compliance_manage'=ANY(rg.permissions)
    AND (ra.expires_at IS NULL OR ra.expires_at>now())
    AND admin_assignment_active(ra.eligible,ra.activated_until)));
  IF NOT FOUND THEN RETURN '{"status":403}'::jsonb; END IF;
  BEGIN
   PERFORM audit_write(p_actor,'chat_case_hold_set','chat_case_hold',v_hold,
    NULL,NULL,NULLIF(p_ip,'')::inet,'','core');
  EXCEPTION WHEN OTHERS THEN NULL;
  END;
  RETURN jsonb_build_object('status',201,'body',jsonb_build_object('holdId',v_hold));
 END IF;
 IF p_action='release' THEN
  v_hold:=(p_data->>'holdId')::bigint;
  PERFORM chat_case_hold_release(p_actor,v_hold,p_data->>'reason')
   WHERE p_actor>0 AND (p_signed OR EXISTS (SELECT 1 FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id=ra.role_group_id WHERE ra.user_id=p_actor AND 'chat.compliance_manage'=ANY(rg.permissions) AND (ra.expires_at IS NULL OR ra.expires_at>now()) AND admin_assignment_active(ra.eligible,ra.activated_until)));
  IF NOT FOUND THEN RETURN '{"status":403}'::jsonb; END IF;
  BEGIN
   PERFORM audit_write(p_actor,'chat_case_hold_release','chat_case_hold',v_hold,
    NULL,NULL,NULLIF(p_ip,'')::inet,'','core');
  EXCEPTION WHEN OTHERS THEN NULL;
  END;
  RETURN '{"status":204}'::jsonb;
 END IF;
 IF p_action='search' THEN
  SELECT chat_ediscovery_search(p_actor,(p_data->>'caseId')::bigint,p_data->'query',
   (p_data->>'beforeId')::bigint,(p_data->>'han')::boolean,(p_data->>'limit')::int)
  INTO v_result WHERE p_actor>0 AND (p_signed OR EXISTS (SELECT 1 FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id=ra.role_group_id WHERE ra.user_id=p_actor AND 'chat.ediscovery'=ANY(rg.permissions) AND (ra.expires_at IS NULL OR ra.expires_at>now()) AND admin_assignment_active(ra.eligible,ra.activated_until)));
  IF NOT FOUND THEN RETURN '{"status":403}'::jsonb; END IF;
  BEGIN
   PERFORM audit_write(p_actor,'chat_ediscovery_search','ediscovery_case',(p_data->>'caseId')::bigint,
    NULL,NULL,NULLIF(p_ip,'')::inet,'','core');
  EXCEPTION WHEN OTHERS THEN NULL;
  END;
  RETURN jsonb_build_object('status',200,'raw',v_result::text);
 END IF;
 IF p_action='read' THEN
  SELECT chat_ediscovery_read(p_actor,(p_data->>'caseId')::bigint,(p_data->>'channelId')::bigint,
   (p_data->>'beforeId')::bigint,(p_data->>'limit')::int)
  INTO v_result WHERE p_actor>0 AND (p_signed OR EXISTS (SELECT 1 FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id=ra.role_group_id WHERE ra.user_id=p_actor AND 'chat.ediscovery'=ANY(rg.permissions) AND (ra.expires_at IS NULL OR ra.expires_at>now()) AND admin_assignment_active(ra.eligible,ra.activated_until)));
  IF NOT FOUND THEN RETURN '{"status":403}'::jsonb; END IF;
  BEGIN
   PERFORM audit_write(p_actor,'chat_ediscovery_read','channel',(p_data->>'channelId')::bigint,
    NULL,NULL,NULLIF(p_ip,'')::inet,'','core');
  EXCEPTION WHEN OTHERS THEN NULL;
  END;
  RETURN jsonb_build_object('status',200,'raw',v_result::text);
 END IF;
 IF p_action='export' THEN
  SELECT chat_ediscovery_export_begin(p_actor,(p_data->>'caseId')::bigint,
   ARRAY(SELECT value::bigint FROM jsonb_array_elements_text(p_data->'query'->'channels')),p_data->'query')
  INTO v_result WHERE p_actor>0 AND (p_signed OR EXISTS (SELECT 1 FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id=ra.role_group_id WHERE ra.user_id=p_actor AND 'chat.ediscovery'=ANY(rg.permissions) AND (ra.expires_at IS NULL OR ra.expires_at>now()) AND admin_assignment_active(ra.eligible,ra.activated_until)));
  IF NOT FOUND THEN RETURN '{"status":403}'::jsonb; END IF;
  BEGIN
   PERFORM audit_write(p_actor,'chat_ediscovery_export','ediscovery_case',(p_data->>'caseId')::bigint,
    NULL,NULL,NULLIF(p_ip,'')::inet,'','core');
  EXCEPTION WHEN OTHERS THEN NULL;
  END;
  RETURN jsonb_build_object('status',200,'raw',v_result::text);
 END IF;
 RAISE EXCEPTION 'unsupported chat oversight operation' USING ERRCODE='22023';
END;
$$;
SELECT apply_worker_ownership('rust_compliance_chat_command(bigint,boolean,text,jsonb,text)'::regprocedure);
