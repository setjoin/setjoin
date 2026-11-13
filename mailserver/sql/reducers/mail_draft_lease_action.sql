CREATE OR REPLACE FUNCTION mail_draft_lease_action(
  p_mailbox_id bigint,
  p_actor_user_id bigint,
  p_operation_id uuid,
  p_draft_session_id uuid,
  p_action text,
  p_expected_epoch bigint,
  p_target_user_id bigint,
  p_reason text,
  p_request_digest text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_existing mail_work_operations%ROWTYPE; v_draft mail_draft_collaboration%ROWTYPE;
  v_result jsonb; v_kind text; v_state bigint; v_full boolean;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.shared_mail_drafts'),false) THEN
    RAISE EXCEPTION 'shared mail drafts are disabled' USING ERRCODE='BZ300';
  END IF;
  IF p_operation_id IS NULL OR p_draft_session_id IS NULL OR p_action NOT IN ('renew','release','handoff','takeover')
     OR p_expected_epoch<1 OR p_reason IS NULL OR octet_length(p_reason) NOT BETWEEN 1 AND 1024
     OR p_request_digest!~'^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'invalid shared draft lease action' USING ERRCODE='BZ301';
  END IF;
  IF NOT mail_work_can_collaborate(p_mailbox_id,p_actor_user_id) THEN
    RAISE EXCEPTION 'shared draft collaboration permission required' USING ERRCODE='BZ005';
  END IF;
  v_full:=EXISTS(SELECT 1 FROM mailbox_delegates WHERE mailbox_id=p_mailbox_id
    AND user_id=p_actor_user_id AND permission='full_access');
  SELECT * INTO v_existing FROM mail_work_operations WHERE operation_id=p_operation_id;
  IF FOUND THEN
    IF v_existing.mailbox_id=p_mailbox_id AND v_existing.actor_user_id=p_actor_user_id
       AND v_existing.operation_kind IN ('draft_renew','draft_release','draft_handoff','draft_takeover')
       AND v_existing.request_digest=p_request_digest THEN RETURN v_existing.result||'{"replayed":true}'::jsonb; END IF;
    RAISE EXCEPTION 'shared draft idempotency conflict' USING ERRCODE='BZ303';
  END IF;
  SELECT * INTO v_draft FROM mail_draft_collaboration WHERE draft_session_id=p_draft_session_id
    AND mailbox_id=p_mailbox_id FOR UPDATE;
  IF NOT FOUND OR v_draft.state<>'active' THEN RAISE EXCEPTION 'shared draft not found' USING ERRCODE='BZ007'; END IF;
  IF v_draft.lease_epoch<>p_expected_epoch THEN RAISE EXCEPTION 'shared draft lease is stale' USING ERRCODE='BZ304'; END IF;
  IF p_action='renew' THEN
    IF v_draft.lease_holder_user_id<>p_actor_user_id OR v_draft.lease_expires_at<=statement_timestamp() THEN
      RAISE EXCEPTION 'shared draft lease is stale' USING ERRCODE='BZ304'; END IF;
    UPDATE mail_draft_collaboration SET lease_expires_at=statement_timestamp()+interval '2 minutes',
      generation=generation+1,last_operation_id=p_operation_id,updated_at=statement_timestamp()
      WHERE draft_session_id=p_draft_session_id RETURNING * INTO v_draft; v_kind:='draft_renew';
  ELSIF p_action='release' THEN
    IF v_draft.lease_holder_user_id<>p_actor_user_id AND NOT v_full THEN
      RAISE EXCEPTION 'only the lease holder or full-access delegate may release' USING ERRCODE='BZ005'; END IF;
    UPDATE mail_draft_collaboration SET lease_holder_user_id=NULL,lease_expires_at=NULL,
      generation=generation+1,last_operation_id=p_operation_id,updated_at=statement_timestamp()
      WHERE draft_session_id=p_draft_session_id RETURNING * INTO v_draft; v_kind:='draft_release';
  ELSIF p_action='handoff' THEN
    IF v_draft.lease_holder_user_id<>p_actor_user_id OR p_target_user_id IS NULL
       OR NOT mail_work_can_collaborate(p_mailbox_id,p_target_user_id) THEN
      RAISE EXCEPTION 'lease holder and eligible target are required' USING ERRCODE='BZ005'; END IF;
    UPDATE mail_draft_collaboration SET lease_epoch=lease_epoch+1,lease_holder_user_id=p_target_user_id,
      lease_expires_at=statement_timestamp()+interval '2 minutes',generation=generation+1,
      last_operation_id=p_operation_id,updated_at=statement_timestamp()
      WHERE draft_session_id=p_draft_session_id RETURNING * INTO v_draft; v_kind:='draft_handoff';
  ELSE
    IF NOT v_full OR (v_draft.lease_holder_user_id IS NOT NULL AND v_draft.lease_expires_at>statement_timestamp()) THEN
      RAISE EXCEPTION 'takeover requires full access and an expired lease' USING ERRCODE='BZ005'; END IF;
    UPDATE mail_draft_collaboration SET lease_epoch=lease_epoch+1,lease_holder_user_id=p_actor_user_id,
      lease_expires_at=statement_timestamp()+interval '2 minutes',generation=generation+1,
      last_operation_id=p_operation_id,updated_at=statement_timestamp()
      WHERE draft_session_id=p_draft_session_id RETURNING * INTO v_draft; v_kind:='draft_takeover';
  END IF;
  v_state:=notify_mailwork_state(p_mailbox_id,'draft',p_draft_session_id::text,'updated');
  v_result:=jsonb_build_object('accountId',p_mailbox_id::text,'id',p_draft_session_id,
    'leaseEpoch',v_draft.lease_epoch::text,'leaseHolderUserId',CASE WHEN v_draft.lease_holder_user_id IS NULL THEN NULL ELSE v_draft.lease_holder_user_id::text END,
    'leaseExpiresAt',v_draft.lease_expires_at,'contentRevision',v_draft.content_revision::text,
    'state',v_state::text,'replayed',false);
  INSERT INTO mail_work_operations(operation_id,mailbox_id,actor_user_id,operation_kind,request_digest,result)
    VALUES(p_operation_id,p_mailbox_id,p_actor_user_id,v_kind,p_request_digest,v_result);
  RETURN v_result;
END $$;

ALTER FUNCTION mail_draft_lease_action(bigint,bigint,uuid,uuid,text,bigint,bigint,text,text) OWNER TO setjoin_worker;
