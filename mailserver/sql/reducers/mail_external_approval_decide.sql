-- mail_external_approval_decide: outbound external-send approval consumer wrapper (T7).
-- Delegates to approval_decide (SoD + approver-authorization + audit + notify), then:
--   approved → REPLAY the held send verbatim via send(..., p_skip_approval => true). The
--              replay runs the FULL send path (Sent copy, quota bump, outbound queue) the
--              hold deferred; the request is marked 'applied'.
--   denied   → deliver a non-delivery notification (NDR) to the sender's own mailbox
--              (mailer-daemon system message), mirroring scheduled_action_dsn.
-- SECURITY INVOKER (no privilege elevation beyond the caller). Returns the final
-- lifecycle status ('applied' | 'denied'). Errors propagate from approval_decide
-- (BZ106 SoD / BZ107 not-the-approver / BZ108 not-found-or-not-pending).
CREATE OR REPLACE FUNCTION mail_external_approval_decide(
  p_request_id bigint,
  p_actor      bigint,
  p_decision   text,
  p_comment    text
) RETURNS text AS $$
DECLARE
  v_status text;
  v_p      jsonb;
  v_sent_id bigint;
  v_rcpts jsonb;
  v_recipient jsonb;
  v_ordinal bigint;
  v_origin text;
BEGIN
  v_status := approval_decide(p_request_id, p_actor, p_decision, p_comment);

  IF v_status = 'approved' THEN
    -- only the consumer wrapper reads payload; it holds every send() arg verbatim.
    SELECT payload INTO v_p FROM approval_requests WHERE id = p_request_id;

    -- Replay the original submission. p_skip_approval => true bypasses the hold so this
    -- runs the Sent copy + quota bump + outbound queue exactly as a fresh send would.
    v_rcpts := COALESCE(NULLIF(v_p->'p_webhook_envelope_rcpts','null'::jsonb),
      COALESCE(v_p->'p_to_addrs','[]'::jsonb)
        || COALESCE(v_p->'p_cc_addrs','[]'::jsonb)
        || COALESCE(v_p->'p_bcc_addrs','[]'::jsonb));
    v_origin := v_p->>'p_webhook_origin';
    PERFORM set_config('app.webhook_origin',COALESCE(v_origin,''),true);
    PERFORM set_config('app.webhook_envelope_rcpts',v_rcpts::text,true);
    v_sent_id := send(
      (v_p->>'p_user_id')::bigint,
      (v_p->>'p_mailbox_id')::bigint,
      v_p->>'p_raw_ref',
      v_p->>'p_message_id',
      v_p->>'p_from_addr',
      v_p->'p_to_addrs',
      v_p->'p_cc_addrs',
      v_p->'p_bcc_addrs',
      v_p->>'p_subject',
      v_p->>'p_in_reply_to',
      v_p->>'p_references_hdr',
      v_p->>'p_body_text',
      v_p->>'p_body_html',
      (v_p->>'p_size_bytes')::bigint,
      (v_p->>'p_has_attachments')::boolean,
      (v_p->>'p_send_at')::timestamptz,
      (v_p->>'p_is_encrypted')::boolean,
      true,                                  -- p_skip_approval: do not re-hold
      (v_p->>'p_source_message_id')::bigint,
      (v_p->>'p_source_received_at')::timestamptz
    );

    IF v_sent_id IS NOT NULL AND v_origin IN ('smtp_submission','jmap_submission') THEN
      FOR v_recipient,v_ordinal IN
        SELECT value,ordinality FROM jsonb_array_elements(v_rcpts) WITH ORDINALITY
      LOOP
        PERFORM webhook_mail_committed_publish(
          v_sent_id,'mail.sent','approval_replay',v_p->>'p_from_addr',
          CASE WHEN jsonb_typeof(v_recipient)='string' THEN v_recipient #>> '{}'
               ELSE v_recipient->>'email' END,
          v_ordinal::integer);
      END LOOP;
    END IF;

    UPDATE approval_requests SET status = 'applied' WHERE id = p_request_id;

    PERFORM audit_write(
      p_actor, 'approval_applied', 'approval_request', p_request_id,
      NULL, jsonb_build_object('consumer_type', 'mail.external_send'),
      NULL, p_comment, 'core'
    );

    RETURN 'applied';
  END IF;

  IF v_status = 'denied' THEN
    -- Notify the sender their message did not go out. Shared NDR helper so the
    -- expiry sweep (approval_expire_due) can reuse the same path without duplication.
    PERFORM mail_external_ndr(p_request_id, p_comment);
  END IF;

  RETURN v_status;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY INVOKER;
