-- The only owner of the independent MailWork state/journal/push tuple.
CREATE OR REPLACE FUNCTION notify_mailwork_state(
  p_mailbox_id bigint,
  p_object_kind text,
  p_object_id text,
  p_op text
) RETURNS bigint LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_state bigint;
BEGIN
  IF p_object_kind NOT IN ('work','comment','draft','policy','resync')
     OR p_op NOT IN ('created','updated','destroyed','resync')
     OR p_object_id IS NULL OR octet_length(p_object_id) NOT BETWEEN 1 AND 256 THEN
    RAISE EXCEPTION 'invalid mail-work state change' USING ERRCODE='BZ301';
  END IF;

  UPDATE mailboxes SET jmap_mailwork_state=jmap_mailwork_state+1
   WHERE id=p_mailbox_id RETURNING jmap_mailwork_state INTO v_state;
  IF v_state IS NULL THEN
    RAISE EXCEPTION 'mailbox not found' USING ERRCODE='BZ006';
  END IF;

  INSERT INTO mail_work_changes(mailbox_id,state_seq,object_kind,object_id,op)
  VALUES(p_mailbox_id,v_state,p_object_kind,p_object_id,p_op);

  PERFORM app_notify('tag:'||p_mailbox_id,
    jsonb_build_object(
      'type','MailWorkEvent','accountId',p_mailbox_id::text,
      'state',v_state::text,'objectKind',p_object_kind,
      'objectId',p_object_id,'op',p_op
    )::text);
  RETURN v_state;
END $$;

ALTER FUNCTION notify_mailwork_state(bigint,text,text,text) OWNER TO setjoin_worker;
