-- Frozen Go storeAndDeliver: moderation + delivery + condemnation in one call.
-- Worker-only, cross-tenant transport: recipient and each copy's mailbox are
-- resolved by reducers, never supplied as a client-owned identity.
CREATE OR REPLACE FUNCTION rust_smtp_inbound_security(
  p_params jsonb,
  p_envelope_from text,
  p_envelope_to text,
  p_moderation boolean,
  p_condemned text
) RETURNS TABLE(
  message_id bigint,
  subject_user_id bigint,
  subject_mailbox_id bigint,
  publication_enrolled boolean,
  outcome text
) LANGUAGE plpgsql VOLATILE AS $$
DECLARE
  v_group_id bigint;
  v_sender_domain text;
  v_external boolean := true;
  v_verdict text;
  v_result record;
  v_copy record;
  v_mailbox_id bigint;
  v_reason text;
BEGIN
  IF p_moderation THEN
    SELECT dg.id INTO v_group_id
      FROM distribution_groups dg
      JOIN mailboxes mb ON mb.id=dg.mailbox_id
      LEFT JOIN aliases a ON a.mailbox_id=mb.id
     WHERE mailbox_lifecycle_delivery_mode(mb.id)<>'rejecting'
       AND (mb.email=lower(p_envelope_to) OR a.email=lower(p_envelope_to))
     LIMIT 1;
    IF v_group_id IS NOT NULL THEN
      IF position('@' IN p_envelope_from)>0 THEN
        v_sender_domain := reverse(split_part(reverse(p_envelope_from),'@',1));
        IF v_sender_domain<>'' THEN
          SELECT NOT EXISTS(SELECT 1 FROM domains d WHERE d.is_local=TRUE AND lower(d.name)=lower(v_sender_domain)) INTO v_external;
        END IF;
      END IF;
      SELECT group_moderation_check(v_group_id,v_external) INTO v_verdict;
      IF v_verdict='reject' THEN
        RETURN QUERY SELECT NULL::bigint,NULL::bigint,NULL::bigint,false,'rejected'::text;
        RETURN;
      ELSIF v_verdict='hold' THEN
        IF coalesce(p_condemned,'')<>'' THEN
          RETURN QUERY SELECT NULL::bigint,NULL::bigint,NULL::bigint,false,'deferred'::text;
          RETURN;
        END IF;
        PERFORM group_moderation_hold(v_group_id,p_envelope_from,p_params->>'p_raw_ref',
          jsonb_build_object('mail_from',p_envelope_from,'rcpt_to',p_envelope_to),p_params);
        RETURN QUERY SELECT NULL::bigint,NULL::bigint,NULL::bigint,false,'held'::text;
        RETURN;
      END IF;
    END IF;
  END IF;

  SELECT * INTO v_result FROM smtp_inbound_deliver(p_params,p_envelope_from,p_envelope_to);
  IF coalesce(p_condemned,'')<>'' THEN
    v_reason := CASE p_condemned
      WHEN 'ClamAV:unavailable' THEN 'Malware scan unavailable — quarantined fail-closed (message never verified clean)'
      WHEN 'MIME:unparseable' THEN 'MIME structure failed safe parsing — quarantined fail-closed (body never link-protect rewritten)'
      ELSE 'Virus detected: '||p_condemned END;
    IF v_result.message_id IS NOT NULL THEN
      -- ID is the authoritative result of THIS delivery, not a request-owned ID.
      SELECT m.mailbox_id INTO STRICT v_mailbox_id FROM messages m WHERE m.id=v_result.message_id;
      PERFORM quarantine_message(v_result.message_id,v_mailbox_id,v_reason,'virus',p_condemned);
    ELSE
      -- Group expansion returns no message ID. Select only copies this same
      -- transaction inserted (including member subtransactions), as frozen Go.
      FOR v_copy IN SELECT m.id,m.mailbox_id FROM messages m
        WHERE m.raw_ref=p_params->>'p_raw_ref' AND m.message_id=p_params->>'p_message_id'
          AND pg_xact_status(m.xmin::text::xid8) IN ('in progress','subcommitted')
      LOOP
        PERFORM quarantine_message(v_copy.id,v_copy.mailbox_id,v_reason,'virus',p_condemned);
      END LOOP;
    END IF;
  END IF;
  RETURN QUERY SELECT v_result.message_id,v_result.subject_user_id,
    v_result.subject_mailbox_id,v_result.publication_enrolled,'delivered'::text;
END $$;
ALTER FUNCTION rust_smtp_inbound_security(jsonb,text,text,boolean,text) OWNER TO setjoin_worker;
REVOKE ALL ON FUNCTION rust_smtp_inbound_security(jsonb,text,text,boolean,text) FROM PUBLIC,setjoin_app;
GRANT EXECUTE ON FUNCTION rust_smtp_inbound_security(jsonb,text,text,boolean,text) TO setjoin_worker;
