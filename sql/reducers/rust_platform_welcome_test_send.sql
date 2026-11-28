-- Frozen Go's POST /admin/system/welcome-email/test (notify.SendWelcomeEmailWithConfig):
-- resolve the caller's primary mailbox and personalization values, substitute the
-- whitelisted {{Placeholders}} in that order, and deliver the system message into the
-- caller's own inbox through deliver(). p_user is the verified token's user and the only
-- recipient (R2); no primary mailbox raises, as Go's error (its 500). No idempotency guard.
-- Under native RLS Go's call never succeeds (see the set_config below).
CREATE OR REPLACE FUNCTION rust_platform_welcome_test_send(
 p_user bigint,p_subject text,p_body_text text,p_body_html text
) RETURNS bigint LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE
 v_mailbox bigint;
 v_name text;
 v_username text;
 v_email text;
 v_local text;
 v_domain text;
 v_subject text;
 v_text text;
 v_html text;
BEGIN
 SELECT id INTO v_mailbox FROM mailboxes WHERE user_id = p_user AND is_primary = TRUE LIMIT 1;
 IF v_mailbox IS NULL THEN
  RAISE EXCEPTION 'welcome: no primary mailbox for user %', p_user;
 END IF;
 SELECT u.display_name, u.username, COALESCE(mb.email, u.email)
   INTO STRICT v_name, v_username, v_email
   FROM mailboxes mb JOIN users u ON u.id = mb.user_id WHERE mb.id = v_mailbox;
 IF position('@' IN v_email) = 0 THEN
  v_local := '';
  v_domain := v_email;
 ELSE
  v_local := regexp_replace(v_email, '@[^@]*$', '');
  v_domain := substring(v_email FROM '[^@]*$');
 END IF;
 IF v_name = '' THEN
  v_name := CASE WHEN v_local <> '' THEN v_local ELSE v_email END;
 END IF;
 v_subject := p_subject; v_text := p_body_text; v_html := p_body_html;
 v_subject := replace(v_subject, '{{DisplayName}}', v_name);
 v_text := replace(v_text, '{{DisplayName}}', v_name);
 v_html := replace(v_html, '{{DisplayName}}', v_name);
 v_subject := replace(v_subject, '{{Email}}', v_email);
 v_text := replace(v_text, '{{Email}}', v_email);
 v_html := replace(v_html, '{{Email}}', v_email);
 v_subject := replace(v_subject, '{{Username}}', v_username);
 v_text := replace(v_text, '{{Username}}', v_username);
 v_html := replace(v_html, '{{Username}}', v_username);
 v_subject := replace(v_subject, '{{OrgName}}', v_domain);
 v_text := replace(v_text, '{{OrgName}}', v_domain);
 v_html := replace(v_html, '{{OrgName}}', v_domain);
 v_subject := replace(v_subject, '{{WebmailURL}}', 'https://' || v_domain);
 v_text := replace(v_text, '{{WebmailURL}}', 'https://' || v_domain);
 v_html := replace(v_html, '{{WebmailURL}}', 'https://' || v_domain);
 -- Frozen Go calls deliver() on the plain pool, with no mailbox scope, so FORCE RLS on
 -- messages refuses the insert and its endpoint answers 500 (parity, ARCH-029; BUGS_FOUND
 -- of #443). Delete this one statement to deliver into the caller's own mailbox.
 PERFORM set_config('app.current_mailbox_id', '', true);
 PERFORM deliver(
  'system:welcome:' || p_user,
  'welcome-' || p_user || '-' || floor(extract(epoch FROM clock_timestamp()) * 1000000000)::bigint || '@setjoin',
  'noreply@' || v_domain, 'SetJoin Team', v_email,
  jsonb_build_array(jsonb_build_object('email', v_email, 'name', '')),
  '[]'::jsonb, '[]'::jsonb, v_subject, '', '', v_text, v_html,
  (octet_length(v_text) + octet_length(v_html))::bigint, FALSE, now(),
  'none', 'none', 'none', 0.0::real, '{}'::jsonb);
 RETURN v_mailbox;
END;
$$;
