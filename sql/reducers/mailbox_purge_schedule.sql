-- Mailbox Lifecycle & Retention authority: mailbox_purge_schedule.

CREATE OR REPLACE FUNCTION mailbox_purge_schedule(
  p_actor bigint,p_mailbox_id bigint,p_operation_id uuid,p_expected_generation bigint,
  p_preview_digest text,p_request_digest text,p_reason text,p_approver_user_id bigint
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_l mailbox_lifecycle%ROWTYPE; v_preview jsonb; v_approval bigint; v_id uuid; v_result jsonb; v_before text;
BEGIN
  IF NOT mailbox_lifecycle_enabled() THEN RAISE EXCEPTION 'mailbox lifecycle is disabled' USING ERRCODE='BZ300'; END IF;
  SELECT * INTO v_l FROM mailbox_lifecycle WHERE mailbox_id=p_mailbox_id FOR UPDATE;
  IF NOT FOUND OR v_l.binding_state<>'retained' THEN RAISE EXCEPTION 'mailbox is not retained' USING ERRCODE='BZ305'; END IF;
  IF v_l.generation<>p_expected_generation THEN RAISE EXCEPTION 'mailbox lifecycle generation is stale' USING ERRCODE='BZ304'; END IF;
  IF p_actor=p_approver_user_id OR p_reason IS NULL OR octet_length(p_reason) NOT BETWEEN 1 AND 1024 THEN
    RAISE EXCEPTION 'independent purge approval is required' USING ERRCODE='BZ308'; END IF;
  v_preview:=mailbox_lifecycle_preview(p_actor,p_mailbox_id);
  IF v_preview->>'previewDigest'<>lower(p_preview_digest) THEN RAISE EXCEPTION 'purge preview is stale' USING ERRCODE='BZ309'; END IF;
  IF EXISTS(SELECT 1 FROM mailbox_lifecycle_operations WHERE operation_id=p_operation_id) THEN
    SELECT result INTO v_result FROM mailbox_lifecycle_operations WHERE operation_id=p_operation_id AND mailbox_id=p_mailbox_id
      AND action='purge_schedule' AND request_digest=p_request_digest;
    IF FOUND THEN RETURN v_result||'{"replayed":true}'::jsonb; END IF;
    RAISE EXCEPTION 'mailbox lifecycle idempotency conflict' USING ERRCODE='BZ303';
  END IF;
  v_approval:=approval_request_create('mailbox.purge',p_actor,'Purge retained mailbox '||p_mailbox_id,
    jsonb_build_object('mailboxId',p_mailbox_id::text,'generation',v_l.generation::text,'previewDigest',p_preview_digest),
    NULL,'user',p_approver_user_id,2880);
  INSERT INTO mailbox_purge_requests(mailbox_id,operation_id,lifecycle_generation,preview_digest,requested_by,
    eligible_at,approval_request_id,reason,blocker_snapshot)
    VALUES(p_mailbox_id,p_operation_id,v_l.generation,p_preview_digest,p_actor,
      GREATEST(v_l.retention_until,statement_timestamp()),v_approval,p_reason,v_preview->'blockers') RETURNING id INTO v_id;
  v_before:=encode(digest(to_jsonb(v_l)::text,'sha256'),'hex');
  UPDATE mailbox_lifecycle SET generation=generation+1,last_operation_id=p_operation_id,updated_by=p_actor,
    updated_at=statement_timestamp() WHERE mailbox_id=p_mailbox_id RETURNING * INTO v_l;
  v_result:=jsonb_build_object('purgeRequestId',v_id,'approvalRequestId',v_approval,
    'mailboxId',p_mailbox_id::text,'generation',v_l.generation::text,'eligibleAt',GREATEST(v_l.retention_until,statement_timestamp()),'replayed',false);
  INSERT INTO mailbox_lifecycle_operations(operation_id,mailbox_id,action,actor_user_id,expected_generation,
    request_digest,before_digest,after_digest,result) VALUES(p_operation_id,p_mailbox_id,'purge_schedule',p_actor,
    p_expected_generation,p_request_digest,v_before,encode(digest(to_jsonb(v_l)::text,'sha256'),'hex'),v_result);
  INSERT INTO mailbox_lifecycle_outbox(operation_id,event_kind,dedupe_key,payload) VALUES(
    p_operation_id,'mailbox.purge_scheduled','mailbox-lifecycle:'||p_operation_id::text,
    jsonb_build_object('mailboxId',p_mailbox_id::text,'purgeRequestId',v_id));
  INSERT INTO mailbox_lifecycle_effects(operation_id,mailbox_id,effect_kind)
    VALUES(p_operation_id,p_mailbox_id,'lifecycle_webhook');
  RETURN v_result;
END $$;

ALTER FUNCTION mailbox_purge_schedule(bigint,bigint,uuid,bigint,text,text,text,bigint) OWNER TO setjoin_worker;
