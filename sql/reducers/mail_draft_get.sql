CREATE OR REPLACE FUNCTION mail_draft_get(
  p_mailbox_id bigint,
  p_actor_user_id bigint,
  p_ids uuid[] DEFAULT NULL
) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_state bigint; v_list jsonb;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.shared_mail_drafts'),false) THEN
    RAISE EXCEPTION 'shared mail drafts are disabled' USING ERRCODE='BZ300';
  END IF;
  IF NOT mail_work_can_read(p_mailbox_id,p_actor_user_id) OR COALESCE(cardinality(p_ids),0)>256 THEN
    RAISE EXCEPTION 'shared mailbox not found' USING ERRCODE='BZ006';
  END IF;
  SELECT jmap_mailwork_state INTO v_state FROM mailboxes WHERE id=p_mailbox_id;
  SELECT COALESCE(jsonb_agg(jsonb_build_object(
    'id',d.draft_session_id,'messageId',d.message_id::text,'receivedAt',d.received_at,
    'contentRevision',d.content_revision::text,'leaseEpoch',d.lease_epoch::text,
    'leaseHolderUserId',CASE WHEN d.lease_holder_user_id IS NULL THEN NULL ELSE d.lease_holder_user_id::text END,
    'leaseExpiresAt',d.lease_expires_at,'finalSenderAddress',d.final_sender_address,
    'generation',d.generation::text,'state',d.state,'updatedAt',d.updated_at
  ) ORDER BY d.updated_at,d.draft_session_id),'[]'::jsonb) INTO v_list
  FROM mail_draft_collaboration d WHERE d.mailbox_id=p_mailbox_id
    AND (p_ids IS NULL OR d.draft_session_id=ANY(p_ids));
  RETURN jsonb_build_object('accountId',p_mailbox_id::text,'state',v_state::text,'list',v_list,
    'notFound',COALESCE((SELECT jsonb_agg(i) FROM unnest(COALESCE(p_ids,ARRAY[]::uuid[])) i
      WHERE NOT EXISTS(SELECT 1 FROM mail_draft_collaboration d
        WHERE d.mailbox_id=p_mailbox_id AND d.draft_session_id=i)),'[]'::jsonb));
END $$;

ALTER FUNCTION mail_draft_get(bigint,bigint,uuid[]) OWNER TO setjoin_worker;
