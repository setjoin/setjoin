-- Mailbox Lifecycle & Retention authority: mailbox_lifecycle_preview.

CREATE OR REPLACE FUNCTION mailbox_lifecycle_preview(p_actor bigint,p_mailbox_id bigint)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_state jsonb; v_addresses jsonb; v_messages bigint; v_blobs bigint; v_blockers jsonb; v_digest text;
  v_target_user bigint;
BEGIN
  SELECT user_id INTO v_target_user FROM mailboxes WHERE id=p_mailbox_id;
  IF NOT FOUND OR (
     NOT admin_can_manage_with_permission(p_actor,COALESCE(v_target_user,0),'users.delete')
     AND NOT EXISTS(SELECT 1 FROM admin_role_assignments
                    WHERE user_id=p_actor AND role_group_id=1
                      AND (expires_at IS NULL OR expires_at>statement_timestamp())
                      AND admin_assignment_active(eligible,activated_until))
  ) THEN
    RAISE EXCEPTION 'mailbox lifecycle target not found' USING ERRCODE='BZ302';
  END IF;
  v_state:=mailbox_lifecycle_read(p_mailbox_id);
  IF v_state IS NULL THEN RAISE EXCEPTION 'mailbox lifecycle target not found' USING ERRCODE='BZ302'; END IF;
  SELECT COALESCE(jsonb_agg(normalized_address ORDER BY normalized_address),'[]'::jsonb)
    INTO v_addresses FROM mailbox_address_claims WHERE mailbox_id=p_mailbox_id AND claim_state<>'released';
  SELECT count(*) INTO v_messages FROM messages WHERE mailbox_id=p_mailbox_id;
  SELECT count(DISTINCT ma.blob_sha256) INTO v_blobs FROM message_attachments ma
    JOIN messages m ON m.id=ma.message_id AND m.received_at=ma.received_at WHERE m.mailbox_id=p_mailbox_id;
  v_blockers:=mailbox_purge_blockers(p_mailbox_id);
  v_digest:=encode(digest(jsonb_build_object('state',v_state,'addresses',v_addresses,
    'messageCount',v_messages,'blobCount',v_blobs,'blockers',v_blockers)::text,'sha256'),'hex');
  RETURN jsonb_build_object('state',v_state,'addresses',v_addresses,'messageCount',v_messages,
    'blobCount',v_blobs,'blockers',v_blockers,'previewDigest',v_digest);
END $$;

ALTER FUNCTION mailbox_lifecycle_preview(bigint,bigint) OWNER TO setjoin_worker;
