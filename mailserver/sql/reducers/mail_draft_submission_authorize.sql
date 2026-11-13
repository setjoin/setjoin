CREATE OR REPLACE FUNCTION mail_draft_submission_authorize(
  p_mailbox_id bigint,p_actor_user_id bigint,p_draft_session_id uuid,
  p_expected_epoch bigint,p_expected_revision bigint,p_message_id bigint,p_received_at timestamptz
) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_draft mail_draft_collaboration%ROWTYPE;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.shared_mail_drafts'),false) THEN
    RAISE EXCEPTION 'shared mail drafts are disabled' USING ERRCODE='BZ300';
  END IF;
  SELECT * INTO v_draft FROM mail_draft_collaboration WHERE draft_session_id=p_draft_session_id
    AND mailbox_id=p_mailbox_id FOR UPDATE;
  IF NOT FOUND OR v_draft.state<>'active' OR v_draft.lease_holder_user_id<>p_actor_user_id
     OR v_draft.lease_expires_at<=statement_timestamp() OR v_draft.lease_epoch<>p_expected_epoch
     OR v_draft.content_revision<>p_expected_revision OR v_draft.message_id<>p_message_id
     OR v_draft.received_at<>p_received_at THEN
    RAISE EXCEPTION 'shared draft submission lease or revision is stale' USING ERRCODE='BZ304';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM mailbox_delegates d WHERE d.mailbox_id=p_mailbox_id
      AND d.user_id=p_actor_user_id AND d.permission IN ('send_as','send_on_behalf','full_access')) THEN
    RAISE EXCEPTION 'shared draft send permission was revoked' USING ERRCODE='BZ005';
  END IF;
  UPDATE mail_draft_collaboration SET state='submitted',lease_holder_user_id=NULL,lease_expires_at=NULL,
    generation=generation+1,updated_at=statement_timestamp() WHERE draft_session_id=p_draft_session_id;
  PERFORM notify_mailwork_state(p_mailbox_id,'draft',p_draft_session_id::text,'updated');
  RETURN true;
END $$;

ALTER FUNCTION mail_draft_submission_authorize(bigint,bigint,uuid,bigint,bigint,bigint,timestamptz) OWNER TO setjoin_worker;
