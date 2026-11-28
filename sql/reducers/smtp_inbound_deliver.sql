-- SMTP-inbound transaction wrapper.  deliver_json owns delivery; this wrapper
-- enrolls the direct mailbox fact in the same transaction and returns the exact
-- OFF compatibility subject to the Go gateway.  A distribution-group delivery
-- returns NULL and therefore preserves the historical zero-event contract.
CREATE OR REPLACE FUNCTION smtp_inbound_deliver(
  p_params jsonb,
  p_envelope_from text,
  p_envelope_to text
) RETURNS TABLE(
  message_id bigint,
  subject_user_id bigint,
  subject_mailbox_id bigint,
  publication_enrolled boolean
) LANGUAGE plpgsql VOLATILE AS $$
DECLARE
  v_message_id bigint;
  v_publication record;
BEGIN
  v_message_id := deliver_json(p_params);
  IF v_message_id IS NULL THEN
    RETURN QUERY SELECT NULL::bigint,NULL::bigint,NULL::bigint,false;
    RETURN;
  END IF;

  SELECT * INTO v_publication
    FROM webhook_mail_committed_publish(
      v_message_id,'mail.received','smtp_inbound',p_envelope_from,p_envelope_to,1);
  RETURN QUERY SELECT v_message_id,v_publication.subject_user_id,
    v_publication.subject_mailbox_id,v_publication.publication_enrolled;
END $$;

ALTER FUNCTION smtp_inbound_deliver(jsonb,text,text) OWNER TO setjoin_worker;
REVOKE ALL ON FUNCTION smtp_inbound_deliver(jsonb,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION smtp_inbound_deliver(jsonb,text,text) FROM setjoin_app;
GRANT EXECUTE ON FUNCTION smtp_inbound_deliver(jsonb,text,text) TO setjoin_worker;
