-- Atomically replace the mutable JMAP draft row while preserving one stable
-- collaboration session. Message content remains owned by the existing Email
-- reducers; this reducer owns only the lease/revision/retarget transaction.
CREATE OR REPLACE FUNCTION mail_draft_replace(
  p_mailbox_id bigint,p_actor_user_id bigint,p_operation_id uuid,p_draft_session_id uuid,
  p_expected_epoch bigint,p_base_revision bigint,p_draft jsonb,p_request_digest text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_existing mail_work_operations%ROWTYPE; v_session mail_draft_collaboration%ROWTYPE;
  v_create jsonb; v_new_id bigint; v_new_received timestamptz; v_content_digest text;
  v_attachment_digest text; v_result jsonb; v_state bigint; v_sender text;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.shared_mail_drafts'),false) THEN
    RAISE EXCEPTION 'shared mail drafts are disabled' USING ERRCODE='BZ300';
  END IF;
  IF p_operation_id IS NULL OR p_draft_session_id IS NULL OR p_expected_epoch<1
     OR p_base_revision<1 OR jsonb_typeof(p_draft)<>'object'
     OR octet_length(p_draft::text)>1048576 OR p_request_digest!~'^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'invalid shared draft replacement' USING ERRCODE='BZ301';
  END IF;
  SELECT * INTO v_existing FROM mail_work_operations WHERE operation_id=p_operation_id;
  IF FOUND THEN
    IF v_existing.mailbox_id=p_mailbox_id AND v_existing.actor_user_id=p_actor_user_id
       AND v_existing.operation_kind='draft_save' AND v_existing.request_digest=p_request_digest THEN
      RETURN v_existing.result||jsonb_build_object('replayed',true,'current',
        mail_draft_get(p_mailbox_id,p_actor_user_id,ARRAY[p_draft_session_id])->'list'->0);
    END IF;
    RAISE EXCEPTION 'shared draft idempotency conflict' USING ERRCODE='BZ303';
  END IF;
  SELECT * INTO v_session FROM mail_draft_collaboration
   WHERE draft_session_id=p_draft_session_id AND mailbox_id=p_mailbox_id FOR UPDATE;
  IF NOT FOUND OR v_session.state<>'active' OR v_session.lease_holder_user_id<>p_actor_user_id
     OR v_session.lease_expires_at<=statement_timestamp() OR v_session.lease_epoch<>p_expected_epoch
     OR v_session.content_revision<>p_base_revision THEN
    RAISE EXCEPTION 'shared draft revision or lease is stale' USING ERRCODE='BZ304';
  END IF;
  IF NOT mail_work_can_collaborate(p_mailbox_id,p_actor_user_id)
     OR NOT EXISTS(SELECT 1 FROM mailbox_delegates d WHERE d.mailbox_id=p_mailbox_id
       AND d.user_id=p_actor_user_id AND d.permission IN ('send_as','send_on_behalf','full_access')) THEN
    RAISE EXCEPTION 'shared draft send permission required' USING ERRCODE='BZ005';
  END IF;
  v_sender:=lower(p_draft->'from'->0->>'email');
  IF v_sender IS NULL OR v_sender<>lower(v_session.final_sender_address)
     OR (NOT EXISTS(SELECT 1 FROM mailboxes m WHERE m.id=p_mailbox_id AND lower(m.email)=v_sender)
       AND NOT EXISTS(SELECT 1 FROM aliases a WHERE a.mailbox_id=p_mailbox_id AND lower(a.email)=v_sender)
       AND NOT EXISTS(SELECT 1 FROM users u WHERE u.id=p_actor_user_id AND lower(u.email)=v_sender)
       AND NOT EXISTS(SELECT 1 FROM aliases a JOIN mailboxes m ON m.id=a.mailbox_id
         WHERE m.user_id=p_actor_user_id AND lower(a.email)=v_sender)) THEN
    RAISE EXCEPTION 'final sender is not authorized' USING ERRCODE='BZ005';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM messages m WHERE m.mailbox_id=p_mailbox_id
      AND m.id=v_session.message_id AND m.received_at=v_session.received_at
      AND m.is_draft AND NOT m.is_deleted) THEN
    RAISE EXCEPTION 'shared draft not found' USING ERRCODE='BZ007';
  END IF;

  v_create:=jmap_email_set_create(p_mailbox_id,jsonb_build_object('replacement',p_draft));
  v_new_id:=(v_create->'created'->'replacement'->>'id')::bigint;
  IF v_new_id IS NULL THEN
    RAISE EXCEPTION 'shared draft replacement was rejected' USING ERRCODE='BZ301';
  END IF;
  SELECT received_at INTO v_new_received FROM messages
   WHERE mailbox_id=p_mailbox_id AND id=v_new_id AND is_draft AND NOT is_deleted;
  IF NOT FOUND THEN RAISE EXCEPTION 'replacement draft is unavailable' USING ERRCODE='BZ304'; END IF;
  SELECT encode(digest(jsonb_build_object('rawRef',m.raw_ref,'subject',m.subject,'from',m.from_addr,
    'to',m.to_addrs,'cc',m.cc_addrs,'bcc',m.bcc_addrs,'text',m.body_text,'html',m.body_html)::text,'sha256'),'hex')
    INTO v_content_digest FROM messages m WHERE m.mailbox_id=p_mailbox_id AND m.id=v_new_id AND m.received_at=v_new_received;
  SELECT encode(digest(COALESCE(string_agg(ma.blob_sha256||':'||ma.size_bytes::text,',' ORDER BY ma.blob_sha256,ma.size_bytes),'empty'),'sha256'),'hex')
    INTO v_attachment_digest FROM message_attachments ma WHERE ma.message_id=v_new_id AND ma.received_at=v_new_received;
  INSERT INTO mail_draft_revisions(draft_session_id,revision,message_id,received_at,editor_user_id,
    content_digest,attachment_digest) VALUES(p_draft_session_id,p_base_revision+1,v_new_id,v_new_received,
    p_actor_user_id,v_content_digest,v_attachment_digest);
  PERFORM delete_draft_message(v_session.message_id,v_session.received_at,p_mailbox_id,false);
  UPDATE mail_draft_collaboration SET message_id=v_new_id,received_at=v_new_received,
    content_revision=p_base_revision+1,lease_expires_at=statement_timestamp()+interval '2 minutes',
    generation=generation+1,last_operation_id=p_operation_id,updated_at=statement_timestamp()
   WHERE draft_session_id=p_draft_session_id RETURNING * INTO v_session;
  v_state:=notify_mailwork_state(p_mailbox_id,'draft',p_draft_session_id::text,'updated');
  v_result:=jsonb_build_object('accountId',p_mailbox_id::text,'id',p_draft_session_id,
    'contentRevision',v_session.content_revision::text,'leaseEpoch',v_session.lease_epoch::text,
    'leaseExpiresAt',v_session.lease_expires_at,'messageId',v_new_id::text,'receivedAt',v_new_received,
    'state',v_state::text,'replayed',false);
  INSERT INTO mail_work_operations(operation_id,mailbox_id,actor_user_id,operation_kind,request_digest,result)
    VALUES(p_operation_id,p_mailbox_id,p_actor_user_id,'draft_save',p_request_digest,v_result);
  RETURN v_result;
END $$;

ALTER FUNCTION mail_draft_replace(bigint,bigint,uuid,uuid,bigint,bigint,jsonb,text) OWNER TO setjoin_worker;
