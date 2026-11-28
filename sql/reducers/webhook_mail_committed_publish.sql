-- Enroll one committed mailbox fact in the durable webhook publication ledger.
-- The caller supplies only the committed message identity, a closed production
-- origin and the legacy envelope payload.  Subject authority is always derived
-- from messages -> mailboxes inside this function.  Ownerless shared/group
-- mailboxes are deliberately suppressed because V211 requires a user subject.
CREATE OR REPLACE FUNCTION webhook_mail_committed_publish(
  p_message_pk bigint,
  p_event_type text,
  p_origin text,
  p_envelope_from text,
  p_envelope_to text,
  p_recipient_ordinal integer DEFAULT 1
) RETURNS TABLE(
  publication_enrolled boolean,
  subject_user_id bigint,
  subject_mailbox_id bigint
) LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE
  v_message_id bigint;
  v_user_id bigint;
  v_mailbox_id bigint;
  v_event_id text;
BEGIN
  IF p_event_type='mail.received' THEN
    IF p_origin<>'smtp_inbound' OR p_recipient_ordinal<>1 THEN
      RAISE EXCEPTION 'unsupported received-mail publication origin'
        USING ERRCODE='BZ301';
    END IF;
  ELSIF p_event_type='mail.sent' THEN
    IF p_origin NOT IN ('smtp_submission','jmap_submission','approval_replay','scheduled_send')
       OR p_recipient_ordinal<1 OR p_recipient_ordinal>10000 THEN
      RAISE EXCEPTION 'unsupported sent-mail publication origin'
        USING ERRCODE='BZ301';
    END IF;
  ELSE
    RAISE EXCEPTION 'unsupported mail webhook event type'
      USING ERRCODE='BZ301';
  END IF;

  IF p_message_pk IS NULL OR p_envelope_from IS NULL OR p_envelope_to IS NULL
     OR octet_length(p_envelope_from)>4096 OR octet_length(p_envelope_to) NOT BETWEEN 1 AND 4096 THEN
    RAISE EXCEPTION 'invalid mail webhook publication payload'
      USING ERRCODE='BZ301';
  END IF;

  SELECT m.id,mb.user_id,mb.id
    INTO v_message_id,v_user_id,v_mailbox_id
    FROM messages m
    JOIN mailboxes mb ON mb.id=m.mailbox_id
   WHERE m.id=p_message_pk
   ORDER BY m.received_at DESC
   LIMIT 1
   FOR UPDATE OF m;

  IF v_message_id IS NULL OR v_user_id IS NULL THEN
    RETURN QUERY SELECT false,v_user_id,v_mailbox_id;
    RETURN;
  END IF;

  -- A sent fact is valid only after the committed message has reached Sent.
  -- Inbound copies never acquire this tag through the smtp_inbound wrapper.
  IF p_event_type='mail.sent' AND NOT EXISTS (
    SELECT 1
      FROM message_tags mt
      JOIN tags t ON t.id=mt.tag_id AND t.mailbox_id=v_mailbox_id
     WHERE mt.message_id=v_message_id AND t.name='Sent'
  ) THEN
    RAISE EXCEPTION 'mail.sent publication requires a Sent message'
      USING ERRCODE='BZ301';
  END IF;

  IF NOT COALESCE((SELECT enabled FROM feature_toggles
                    WHERE key='feature.webhook_publication_outbox'),false) THEN
    RETURN QUERY SELECT false,v_user_id,v_mailbox_id;
    RETURN;
  END IF;

  IF p_event_type='mail.received' THEN
    v_event_id := 'mail-received-' || v_message_id::text;
  ELSE
    v_event_id := 'mail-sent-' || v_message_id::text || '-' || p_recipient_ordinal::text;
  END IF;

  INSERT INTO webhook_publications(
    event_id,event_type,source,audience,subject_user_id,subject_mailbox_id,payload)
  VALUES(
    v_event_id,p_event_type,'mailserver/gateway','mailbox',v_user_id,v_mailbox_id,
    jsonb_build_object('from',p_envelope_from,'to',p_envelope_to)
  ) ON CONFLICT(event_id) DO NOTHING;

  RETURN QUERY SELECT true,v_user_id,v_mailbox_id;
END $$;

ALTER FUNCTION webhook_mail_committed_publish(bigint,text,text,text,text,integer) OWNER TO setjoin_worker;
REVOKE ALL ON FUNCTION webhook_mail_committed_publish(bigint,text,text,text,text,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION webhook_mail_committed_publish(bigint,text,text,text,text,integer) FROM setjoin_app;
GRANT EXECUTE ON FUNCTION webhook_mail_committed_publish(bigint,text,text,text,text,integer) TO setjoin_worker;
