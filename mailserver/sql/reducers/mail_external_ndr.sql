-- mail_external_ndr: deliver a mailer-daemon NDR to the sender of a held
-- mail.external_send approval request. Shared by the deny path
-- (mail_external_approval_decide) and the expiry sweep (approval_expire_due)
-- to avoid duplicating the deliver() block.
-- p_reason appears in the NDR body. No-op if the sender mailbox is not found.
CREATE OR REPLACE FUNCTION mail_external_ndr(
  p_request_id bigint,
  p_reason     text
) RETURNS void AS $$
DECLARE
  v_p      jsonb;
  v_sender text;
BEGIN
  SELECT payload INTO v_p   FROM approval_requests WHERE id = p_request_id;
  SELECT email   INTO v_sender FROM mailboxes    WHERE id = (v_p->>'p_mailbox_id')::bigint;

  IF v_sender IS NOT NULL THEN
    PERFORM deliver(
      'ndr/approval/' || p_request_id::text,
      '<approval-ndr-' || p_request_id::text || '@mailserver.local>',
      'mailer-daemon@mailserver.local', 'Mail Delivery System',
      v_sender,
      jsonb_build_array(jsonb_build_object('email', v_sender)),
      '[]'::jsonb, '[]'::jsonb,
      'Your message was not approved',
      NULL, NULL,
      'Your message "' || COALESCE(v_p->>'p_subject', '(no subject)') ||
        '" to an external recipient was not approved.' ||
        CASE WHEN COALESCE(btrim(p_reason), '') <> ''
             THEN E'\n\nReason: ' || p_reason
             ELSE '' END,
      NULL,
      0, FALSE, now(),
      'pass', NULL, NULL, 0.0, NULL
    );
  END IF;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY INVOKER;
