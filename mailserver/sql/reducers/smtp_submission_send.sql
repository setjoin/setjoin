-- SMTP-submission transaction wrapper.  The nullable send() result is
-- load-bearing: NULL means accepted-and-held, so neither durable enrollment nor
-- the post-commit legacy compatibility path may emit mail.sent.
CREATE OR REPLACE FUNCTION smtp_submission_send(
  p_user_id bigint,
  p_mailbox_id bigint,
  p_raw_ref text,
  p_message_id text,
  p_from_addr text,
  p_to_addrs jsonb,
  p_cc_addrs jsonb,
  p_bcc_addrs jsonb,
  p_subject text,
  p_in_reply_to text,
  p_references_hdr text,
  p_body_text text,
  p_body_html text,
  p_size_bytes bigint,
  p_has_attachments boolean,
  p_send_at timestamptz,
  p_envelope_rcpts jsonb
) RETURNS TABLE(
  message_id bigint,
  subject_user_id bigint,
  subject_mailbox_id bigint,
  publication_enrolled boolean
) LANGUAGE plpgsql VOLATILE AS $$
DECLARE
  v_message_id bigint;
  v_recipient text;
  v_ordinal bigint;
  v_publication record;
  v_subject_user_id bigint;
  v_subject_mailbox_id bigint;
  v_enrolled boolean := false;
BEGIN
  IF jsonb_typeof(p_envelope_rcpts)<>'array' OR jsonb_array_length(p_envelope_rcpts)=0 THEN
    RAISE EXCEPTION 'SMTP submission requires envelope recipients'
      USING ERRCODE='BZ301';
  END IF;

  PERFORM set_config('app.webhook_origin','smtp_submission',true);
  PERFORM set_config('app.webhook_envelope_rcpts',p_envelope_rcpts::text,true);
  v_message_id := send(
    p_user_id,p_mailbox_id,p_raw_ref,p_message_id,p_from_addr,
    p_to_addrs,p_cc_addrs,p_bcc_addrs,p_subject,p_in_reply_to,p_references_hdr,
    p_body_text,p_body_html,p_size_bytes,p_has_attachments,p_send_at);

  IF v_message_id IS NULL THEN
    RETURN QUERY SELECT NULL::bigint,NULL::bigint,NULL::bigint,false;
    RETURN;
  END IF;

  FOR v_recipient,v_ordinal IN
    SELECT value,ordinality
      FROM jsonb_array_elements_text(p_envelope_rcpts) WITH ORDINALITY
  LOOP
    SELECT * INTO v_publication
      FROM webhook_mail_committed_publish(
        v_message_id,'mail.sent','smtp_submission',p_from_addr,v_recipient,v_ordinal::integer);
    v_subject_user_id := v_publication.subject_user_id;
    v_subject_mailbox_id := v_publication.subject_mailbox_id;
    v_enrolled := v_enrolled OR v_publication.publication_enrolled;
  END LOOP;

  RETURN QUERY SELECT v_message_id,v_subject_user_id,v_subject_mailbox_id,v_enrolled;
END $$;

ALTER FUNCTION smtp_submission_send(bigint,bigint,text,text,text,jsonb,jsonb,jsonb,text,text,text,text,text,bigint,boolean,timestamptz,jsonb)
  OWNER TO setjoin_worker;
REVOKE ALL ON FUNCTION smtp_submission_send(bigint,bigint,text,text,text,jsonb,jsonb,jsonb,text,text,text,text,text,bigint,boolean,timestamptz,jsonb)
  FROM PUBLIC;
REVOKE ALL ON FUNCTION smtp_submission_send(bigint,bigint,text,text,text,jsonb,jsonb,jsonb,text,text,text,text,text,bigint,boolean,timestamptz,jsonb)
  FROM setjoin_app;
GRANT EXECUTE ON FUNCTION smtp_submission_send(bigint,bigint,text,text,text,jsonb,jsonb,jsonb,text,text,text,text,text,bigint,boolean,timestamptz,jsonb)
  TO setjoin_worker;
