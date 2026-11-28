CREATE OR REPLACE FUNCTION mail_draft_revision_accept(
  p_mailbox_id bigint,p_actor_user_id bigint,p_operation_id uuid,p_draft_session_id uuid,
  p_expected_epoch bigint,p_base_revision bigint,p_message_id bigint,p_received_at timestamptz,
  p_content_digest text,p_attachment_digest text,p_request_digest text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_existing mail_work_operations%ROWTYPE; v_draft mail_draft_collaboration%ROWTYPE;
  v_result jsonb; v_state bigint;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.shared_mail_drafts'),false) THEN
    RAISE EXCEPTION 'shared mail drafts are disabled' USING ERRCODE='BZ300';
  END IF;
  IF p_operation_id IS NULL OR p_draft_session_id IS NULL OR p_expected_epoch<1 OR p_base_revision<1
     OR p_message_id IS NULL OR p_received_at IS NULL OR p_content_digest!~'^[0-9a-f]{64}$'
     OR p_attachment_digest!~'^[0-9a-f]{64}$' OR p_request_digest!~'^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'invalid shared draft revision' USING ERRCODE='BZ301';
  END IF;
  SELECT * INTO v_existing FROM mail_work_operations WHERE operation_id=p_operation_id;
  IF FOUND THEN
    IF v_existing.mailbox_id=p_mailbox_id AND v_existing.actor_user_id=p_actor_user_id
       AND v_existing.operation_kind='draft_save' AND v_existing.request_digest=p_request_digest THEN
      RETURN v_existing.result||jsonb_build_object('replayed',true,'current',
        mail_draft_get(p_mailbox_id,p_actor_user_id,ARRAY[p_draft_session_id])->'list'->0); END IF;
    RAISE EXCEPTION 'shared draft idempotency conflict' USING ERRCODE='BZ303';
  END IF;
  SELECT * INTO v_draft FROM mail_draft_collaboration WHERE draft_session_id=p_draft_session_id
    AND mailbox_id=p_mailbox_id FOR UPDATE;
  IF NOT FOUND OR v_draft.state<>'active' OR v_draft.lease_holder_user_id<>p_actor_user_id
     OR v_draft.lease_expires_at<=statement_timestamp() OR v_draft.lease_epoch<>p_expected_epoch
     OR v_draft.content_revision<>p_base_revision OR v_draft.message_id<>p_message_id
     OR v_draft.received_at<>p_received_at THEN
    RAISE EXCEPTION 'shared draft revision or lease is stale' USING ERRCODE='BZ304';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM messages m WHERE m.mailbox_id=p_mailbox_id AND m.id=p_message_id
      AND m.received_at=p_received_at AND m.is_draft AND NOT m.is_deleted) THEN
    RAISE EXCEPTION 'shared draft not found' USING ERRCODE='BZ007';
  END IF;
  INSERT INTO mail_draft_revisions(draft_session_id,revision,message_id,received_at,editor_user_id,
    content_digest,attachment_digest) VALUES(p_draft_session_id,p_base_revision+1,p_message_id,p_received_at,
    p_actor_user_id,p_content_digest,p_attachment_digest);
  UPDATE mail_draft_collaboration SET content_revision=p_base_revision+1,
    lease_expires_at=statement_timestamp()+interval '2 minutes',generation=generation+1,
    last_operation_id=p_operation_id,updated_at=statement_timestamp()
    WHERE draft_session_id=p_draft_session_id RETURNING * INTO v_draft;
  v_state:=notify_mailwork_state(p_mailbox_id,'draft',p_draft_session_id::text,'updated');
  v_result:=jsonb_build_object('accountId',p_mailbox_id::text,'id',p_draft_session_id,
    'contentRevision',v_draft.content_revision::text,'leaseEpoch',v_draft.lease_epoch::text,
    'leaseExpiresAt',v_draft.lease_expires_at,'messageId',v_draft.message_id::text,
    'receivedAt',v_draft.received_at,'state',v_state::text,'replayed',false);
  INSERT INTO mail_work_operations(operation_id,mailbox_id,actor_user_id,operation_kind,request_digest,result)
    VALUES(p_operation_id,p_mailbox_id,p_actor_user_id,'draft_save',p_request_digest,v_result);
  RETURN v_result;
END $$;

ALTER FUNCTION mail_draft_revision_accept(bigint,bigint,uuid,uuid,bigint,bigint,bigint,timestamptz,text,text,text) OWNER TO setjoin_worker;
