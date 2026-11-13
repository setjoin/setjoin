-- Cross-tenant SMTP iMIP; no request-owned user/mailbox IDs. Gate commits the
-- rate charge before the later import, matching Go's separate statements.
-- #544 (owner-approved security fix 2026-11-05): the attendee must be the owner of
-- the mailbox the delivered envelope recipient resolves to (alias, direct mailbox
-- address or catch-all, as deliver() resolves it). The body's attendee list is
-- sender-controlled and must not pick another tenant's calendar.
DROP FUNCTION IF EXISTS rust_smtp_imip_request_gate(jsonb);
CREATE OR REPLACE FUNCTION rust_smtp_imip_request_gate(p_attendees jsonb, p_recipient text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE AS $$
DECLARE v_attendee jsonb; v_user bigint; v_mailbox bigint; v_email text; v_owner bigint; v_rcpt_mailbox bigint;
BEGIN
 IF coalesce(p_recipient,'')='' THEN RETURN NULL; END IF;
 SELECT mb.id INTO v_rcpt_mailbox FROM mailboxes mb JOIN aliases a ON a.mailbox_id=mb.id
  WHERE lower(a.email)=lower(p_recipient) AND mailbox_lifecycle_delivery_mode(mb.id)<>'rejecting' LIMIT 1;
 IF v_rcpt_mailbox IS NULL THEN
  SELECT id INTO v_rcpt_mailbox FROM mailboxes
   WHERE lower(email)=lower(p_recipient) AND mailbox_lifecycle_delivery_mode(id)<>'rejecting' LIMIT 1;
 END IF;
 IF v_rcpt_mailbox IS NULL THEN
  SELECT mb.id INTO v_rcpt_mailbox FROM mailboxes mb JOIN domains d ON d.catch_all_mailbox_id=mb.id
   WHERE lower(d.name)=lower(split_part(p_recipient,'@',2)) AND mailbox_lifecycle_delivery_mode(mb.id)<>'rejecting' LIMIT 1;
 END IF;
 IF v_rcpt_mailbox IS NULL THEN RETURN NULL; END IF;
 SELECT user_id INTO v_owner FROM mailboxes WHERE id=v_rcpt_mailbox;
 IF v_owner IS NULL THEN RETURN NULL; END IF;
 FOR v_attendee IN SELECT value FROM jsonb_array_elements(p_attendees) LOOP
  v_email:=v_attendee->>'email';
  IF coalesce(v_email,'')<>'' THEN
   SELECT id INTO v_user FROM users WHERE email=lower(v_email) AND enabled=TRUE AND id=v_owner LIMIT 1;
   EXIT WHEN v_user IS NOT NULL;
  END IF;
 END LOOP;
 IF v_user IS NULL THEN RETURN NULL; END IF;
 IF NOT rate_limit_check('itip:recipient:'||v_user,20,60) THEN RETURN NULL; END IF;
 SELECT id INTO v_mailbox FROM mailboxes WHERE user_id=v_user AND is_primary=TRUE LIMIT 1;
 IF v_mailbox IS NULL THEN RETURN NULL; END IF;
 RETURN jsonb_build_object('user',v_user,'mailbox',v_mailbox,'email',v_email);
END $$;
CREATE OR REPLACE FUNCTION rust_smtp_imip_request_apply(p_context jsonb,p_event jsonb,p_recurrence timestamptz)
RETURNS jsonb LANGUAGE plpgsql VOLATILE AS $$
DECLARE v_user bigint; v_mailbox bigint; v_master bigint;
BEGIN
 SELECT m.id,u.id INTO v_mailbox,v_user FROM mailboxes m JOIN users u ON u.id=m.user_id
 WHERE m.id=(p_context->>'mailbox')::bigint AND u.id=(p_context->>'user')::bigint
 AND u.email=lower(p_context->>'email') AND m.is_primary=TRUE;
 IF v_mailbox IS NULL THEN RETURN NULL; END IF;
 IF p_recurrence IS NOT NULL THEN
  SELECT ce.id INTO v_master FROM calendar_events ce JOIN calendars c ON c.id=ce.calendar_id
   WHERE ce.uid=p_event->>'uid' AND c.mailbox_id=v_mailbox AND ce.recurrence_override IS NULL LIMIT 1;
  IF v_master IS NOT NULL THEN
   RETURN jmap_calendar_event_set_occurrence(v_mailbox,v_master,p_recurrence,'this',
     (p_event-'uid'-'timeZone'-'recurrenceRule')||jsonb_build_object('description',coalesce(p_event->>'description',''),'location',coalesce(p_event->>'location','')));
  END IF;
 END IF;
 IF EXISTS(SELECT 1 FROM calendar_events ce JOIN calendars c ON c.id=ce.calendar_id
  WHERE ce.uid=p_event->>'uid' AND c.mailbox_id=v_mailbox) THEN RETURN NULL; END IF;
 RETURN jmap_calendar_event_set_create(v_mailbox,v_user,p_context->>'email',jsonb_build_object('k1',p_event));
END $$;
ALTER FUNCTION rust_smtp_imip_request_gate(jsonb,text) OWNER TO setjoin_worker;
ALTER FUNCTION rust_smtp_imip_request_apply(jsonb,jsonb,timestamptz) OWNER TO setjoin_worker;
REVOKE ALL ON FUNCTION rust_smtp_imip_request_gate(jsonb,text),rust_smtp_imip_request_apply(jsonb,jsonb,timestamptz) FROM PUBLIC,setjoin_app;
GRANT EXECUTE ON FUNCTION rust_smtp_imip_request_gate(jsonb,text),rust_smtp_imip_request_apply(jsonb,jsonb,timestamptz) TO setjoin_worker;

-- Role was bound to p_organizer by transport crypto. Re-prove the target under
-- that same organizer and recipient mailbox, locking it through the mutation.
CREATE OR REPLACE FUNCTION rust_smtp_imip_cancel_occurrence(p_uid text,p_mailbox_id bigint,p_organizer text,p_recurrence timestamptz)
RETURNS jsonb LANGUAGE plpgsql VOLATILE AS $$
DECLARE v_master bigint;
BEGIN
 SELECT ce.id INTO v_master FROM calendar_events ce JOIN calendars c ON c.id=ce.calendar_id
 WHERE ce.uid=p_uid AND c.mailbox_id=p_mailbox_id AND ce.recurrence_override IS NULL
 AND lower(ce.organizer_email)=lower(p_organizer) LIMIT 1 FOR UPDATE OF ce;
 IF v_master IS NULL THEN RETURN NULL; END IF;
 RETURN jmap_calendar_event_set_occurrence(p_mailbox_id,v_master,p_recurrence,'this','{"excluded":true}'::jsonb);
END $$;
ALTER FUNCTION rust_smtp_imip_cancel_occurrence(text,bigint,text,timestamptz) OWNER TO setjoin_worker;
REVOKE ALL ON FUNCTION rust_smtp_imip_cancel_occurrence(text,bigint,text,timestamptz) FROM PUBLIC,setjoin_app;
GRANT EXECUTE ON FUNCTION rust_smtp_imip_cancel_occurrence(text,bigint,text,timestamptz) TO setjoin_worker;
