CREATE OR REPLACE FUNCTION mail_draft_session_open(
  p_mailbox_id bigint,
  p_actor_user_id bigint,
  p_operation_id uuid,
  p_message_id bigint,
  p_received_at timestamptz,
  p_final_sender_address text,
  p_request_digest text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_existing mail_work_operations%ROWTYPE; v_draft mail_draft_collaboration%ROWTYPE;
  v_content_digest text; v_attachment_digest text; v_result jsonb; v_state bigint;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.shared_mail_drafts'),false) THEN
    RAISE EXCEPTION 'shared mail drafts are disabled' USING ERRCODE='BZ300';
  END IF;
  IF p_operation_id IS NULL OR p_message_id IS NULL OR p_received_at IS NULL
     OR p_final_sender_address IS NULL OR octet_length(p_final_sender_address) NOT BETWEEN 3 AND 254
     OR p_request_digest!~'^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'invalid shared draft open request' USING ERRCODE='BZ301';
  END IF;
  IF NOT mail_work_can_collaborate(p_mailbox_id,p_actor_user_id) THEN
    RAISE EXCEPTION 'shared draft collaboration permission required' USING ERRCODE='BZ005';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM mailbox_delegates d WHERE d.mailbox_id=p_mailbox_id
      AND d.user_id=p_actor_user_id AND d.permission IN ('send_as','send_on_behalf','full_access')) THEN
    RAISE EXCEPTION 'shared draft send permission required' USING ERRCODE='BZ005';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM mailboxes m WHERE m.id=p_mailbox_id AND m.user_id IS NULL) OR
     NOT EXISTS(SELECT 1 FROM messages m WHERE m.mailbox_id=p_mailbox_id AND m.id=p_message_id
       AND m.received_at=p_received_at AND m.is_draft AND NOT m.is_deleted) THEN
    RAISE EXCEPTION 'shared draft not found' USING ERRCODE='BZ007';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM mailboxes m WHERE m.id=p_mailbox_id AND lower(m.email)=lower(p_final_sender_address))
     AND NOT EXISTS(SELECT 1 FROM aliases a WHERE a.mailbox_id=p_mailbox_id AND lower(a.email)=lower(p_final_sender_address))
     AND NOT EXISTS(SELECT 1 FROM users u WHERE u.id=p_actor_user_id AND lower(u.email)=lower(p_final_sender_address))
     AND NOT EXISTS(SELECT 1 FROM aliases a JOIN mailboxes m ON m.id=a.mailbox_id
       WHERE m.user_id=p_actor_user_id AND lower(a.email)=lower(p_final_sender_address)) THEN
    RAISE EXCEPTION 'final sender is not authorized' USING ERRCODE='BZ005';
  END IF;
  SELECT * INTO v_existing FROM mail_work_operations WHERE operation_id=p_operation_id;
  IF FOUND THEN
    IF v_existing.mailbox_id=p_mailbox_id AND v_existing.actor_user_id=p_actor_user_id
       AND v_existing.operation_kind='draft_acquire' AND v_existing.request_digest=p_request_digest THEN
      RETURN v_existing.result||'{"replayed":true}'::jsonb;
    END IF;
    RAISE EXCEPTION 'shared draft idempotency conflict' USING ERRCODE='BZ303';
  END IF;
  SELECT encode(digest(jsonb_build_object('rawRef',m.raw_ref,'subject',m.subject,'from',m.from_addr,
    'to',m.to_addrs,'cc',m.cc_addrs,'bcc',m.bcc_addrs,'text',m.body_text,'html',m.body_html)::text,'sha256'),'hex')
    INTO v_content_digest FROM messages m WHERE m.mailbox_id=p_mailbox_id AND m.id=p_message_id AND m.received_at=p_received_at;
  SELECT encode(digest(COALESCE(string_agg(ma.blob_sha256||':'||ma.size_bytes::text,',' ORDER BY ma.blob_sha256,ma.size_bytes),'empty'),'sha256'),'hex')
    INTO v_attachment_digest FROM message_attachments ma WHERE ma.message_id=p_message_id AND ma.received_at=p_received_at;
  SELECT * INTO v_draft FROM mail_draft_collaboration
    WHERE mailbox_id=p_mailbox_id AND message_id=p_message_id AND received_at=p_received_at FOR UPDATE;
  IF NOT FOUND THEN
    INSERT INTO mail_draft_collaboration(draft_session_id,mailbox_id,message_id,received_at,
      lease_epoch,lease_holder_user_id,lease_expires_at,final_sender_address,last_operation_id)
    VALUES(gen_random_uuid(),p_mailbox_id,p_message_id,p_received_at,1,p_actor_user_id,
      statement_timestamp()+interval '2 minutes',lower(p_final_sender_address),p_operation_id)
    RETURNING * INTO v_draft;
    INSERT INTO mail_draft_revisions(draft_session_id,revision,message_id,received_at,editor_user_id,
      content_digest,attachment_digest) VALUES(v_draft.draft_session_id,1,p_message_id,p_received_at,
      p_actor_user_id,v_content_digest,v_attachment_digest);
  ELSE
    IF v_draft.state<>'active' THEN RAISE EXCEPTION 'shared draft session is terminal' USING ERRCODE='BZ304'; END IF;
    IF v_draft.lease_holder_user_id IS NOT NULL AND v_draft.lease_expires_at>statement_timestamp()
       AND v_draft.lease_holder_user_id<>p_actor_user_id THEN
      RAISE EXCEPTION 'shared draft lease is held by another editor' USING ERRCODE='BZ304';
    END IF;
    UPDATE mail_draft_collaboration SET lease_epoch=lease_epoch+1,
      lease_holder_user_id=p_actor_user_id,lease_expires_at=statement_timestamp()+interval '2 minutes',
      final_sender_address=lower(p_final_sender_address),generation=generation+1,
      last_operation_id=p_operation_id,updated_at=statement_timestamp()
    WHERE draft_session_id=v_draft.draft_session_id RETURNING * INTO v_draft;
  END IF;
  v_state:=notify_mailwork_state(p_mailbox_id,'draft',v_draft.draft_session_id::text,'updated');
  v_result:=jsonb_build_object('accountId',p_mailbox_id::text,'id',v_draft.draft_session_id,
    'messageId',v_draft.message_id::text,'receivedAt',v_draft.received_at,
    'contentRevision',v_draft.content_revision::text,'leaseEpoch',v_draft.lease_epoch::text,
    'leaseHolderUserId',p_actor_user_id::text,'leaseExpiresAt',v_draft.lease_expires_at,
    'finalSenderAddress',v_draft.final_sender_address,'state',v_state::text,'replayed',false);
  INSERT INTO mail_work_operations(operation_id,mailbox_id,actor_user_id,operation_kind,request_digest,result)
  VALUES(p_operation_id,p_mailbox_id,p_actor_user_id,'draft_acquire',p_request_digest,v_result);
  RETURN v_result;
END $$;

ALTER FUNCTION mail_draft_session_open(bigint,bigint,uuid,bigint,timestamptz,text,text) OWNER TO setjoin_worker;
