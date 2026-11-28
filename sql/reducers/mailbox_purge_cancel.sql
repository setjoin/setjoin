-- Cancel an unclaimed mailbox purge without weakening retained-mailbox state.

CREATE OR REPLACE FUNCTION mailbox_purge_cancel(
  p_actor bigint,p_purge_request_id uuid,p_operation_id uuid,p_request_digest text,p_reason text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_p mailbox_purge_requests%ROWTYPE; v_l mailbox_lifecycle%ROWTYPE;
  v_existing mailbox_lifecycle_operations%ROWTYPE; v_before text; v_after text; v_result jsonb;
BEGIN
  IF p_operation_id IS NULL OR p_request_digest!~'^[0-9a-f]{64}$' OR p_reason IS NULL
     OR octet_length(p_reason) NOT BETWEEN 1 AND 1024 OR p_reason~'[[:cntrl:]]' THEN
    RAISE EXCEPTION 'invalid purge cancellation' USING ERRCODE='BZ301';
  END IF;
  SELECT * INTO v_p FROM mailbox_purge_requests WHERE id=p_purge_request_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'purge request not found' USING ERRCODE='BZ310'; END IF;
  IF p_actor<>v_p.requested_by
     AND NOT admin_can_manage_with_permission(p_actor,v_p.requested_by,'users.delete')
     AND NOT EXISTS(SELECT 1 FROM admin_role_assignments
                    WHERE user_id=p_actor AND role_group_id=1
                      AND (expires_at IS NULL OR expires_at>statement_timestamp())
                      AND admin_assignment_active(eligible,activated_until)) THEN
    RAISE EXCEPTION 'purge request not found' USING ERRCODE='BZ310';
  END IF;
  SELECT * INTO v_existing FROM mailbox_lifecycle_operations WHERE operation_id=p_operation_id;
  IF FOUND THEN
    IF v_existing.mailbox_id=v_p.mailbox_id AND v_existing.action='purge_cancel'
       AND v_existing.request_digest=p_request_digest THEN RETURN v_existing.result||'{"replayed":true}'::jsonb; END IF;
    RAISE EXCEPTION 'mailbox lifecycle idempotency conflict' USING ERRCODE='BZ303';
  END IF;
  IF v_p.state NOT IN ('pending','approved','blocked') THEN
    RAISE EXCEPTION 'purge can no longer be cancelled' USING ERRCODE='BZ313';
  END IF;
  SELECT * INTO v_l FROM mailbox_lifecycle WHERE mailbox_id=v_p.mailbox_id FOR UPDATE;
  IF NOT FOUND OR v_l.binding_state<>'retained' THEN RAISE EXCEPTION 'mailbox is not retained' USING ERRCODE='BZ305'; END IF;
  v_before:=encode(digest(jsonb_build_object('purge',to_jsonb(v_p),'lifecycle',to_jsonb(v_l))::text,'sha256'),'hex');
  UPDATE mailbox_purge_requests SET state='cancelled',lease_until=NULL WHERE id=v_p.id;
  UPDATE approval_requests SET status='cancelled',decided_at=COALESCE(decided_at,statement_timestamp())
    WHERE id=v_p.approval_request_id AND status IN ('pending','approved');
  UPDATE mailbox_lifecycle SET generation=generation+1,last_operation_id=p_operation_id,
    updated_by=p_actor,updated_at=statement_timestamp(),reason=p_reason
    WHERE mailbox_id=v_p.mailbox_id RETURNING * INTO v_l;
  v_after:=encode(digest(jsonb_build_object('purgeState','cancelled','lifecycle',to_jsonb(v_l))::text,'sha256'),'hex');
  v_result:=jsonb_build_object('purgeRequestId',v_p.id,'mailboxId',v_p.mailbox_id::text,
    'state','cancelled','generation',v_l.generation::text,'replayed',false);
  INSERT INTO mailbox_lifecycle_operations(operation_id,mailbox_id,action,actor_user_id,expected_generation,
    request_digest,before_digest,after_digest,result) VALUES(p_operation_id,v_p.mailbox_id,'purge_cancel',p_actor,
    v_l.generation-1,p_request_digest,v_before,v_after,v_result);
  INSERT INTO mailbox_lifecycle_outbox(operation_id,event_kind,dedupe_key,payload) VALUES(
    p_operation_id,'mailbox.purge_cancelled','mailbox-lifecycle:'||p_operation_id::text,v_result-'replayed');
  INSERT INTO mailbox_lifecycle_effects(operation_id,mailbox_id,effect_kind)
    VALUES(p_operation_id,v_p.mailbox_id,'lifecycle_webhook');
  PERFORM audit_write(p_actor,'mailbox_purge_cancelled','mailbox',v_p.mailbox_id,NULL,v_result,NULL,p_reason,'core');
  PERFORM app_notify('mailbox_lifecycle',json_build_object('mailbox_id',v_p.mailbox_id,'generation',v_l.generation)::text);
  RETURN v_result;
END $$;

ALTER FUNCTION mailbox_purge_cancel(bigint,uuid,uuid,text,text) OWNER TO setjoin_worker;
