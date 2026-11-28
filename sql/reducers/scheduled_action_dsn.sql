-- scheduled_action_dsn.sql: the `dsn` handler — the bounce Delivery Status
-- Notification that used to be synthesized + delivered SYNCHRONOUSLY inside the
-- AFTER UPDATE trigger on outbound_queue (schema/013_queues.sql). WAVE 9 relocated
-- it here so the bounce email is async, retried, crash-reclaimable, idempotent, and
-- tested (the trigger now only enqueues a `dsn` action — no MIME, no deliver(), no
-- rollback-of-the-bounce-status risk).
--
-- payload = {queue_id}; mailbox_id is the owner column (the sender's mailbox when
-- the enqueuer could resolve it, else NULL — this handler defer-resolves the sender
-- from the queue row's from_addr). The bounce recipient is the ORIGINAL SENDER,
-- resolved through the ADR-004 `resolve_identity` seam (address-aware: from_addr may
-- be an alias / UPN, not the person's primary email) so an aliased sender still gets
-- their bounce. deliver() is then called with the from_addr as the recipient (deliver
-- itself re-resolves alias→mailbox), landing the DSN in the sender's mailbox.
--
-- Idempotency: dedup_key = 'dsn:'||queue_id (set by the trigger's enqueue). A
-- post-crash reclaim re-runs this handler; the "already delivered?" guard keys on a
-- deterministic DSN Message-ID derived from the queue id, so a second run is a no-op
-- and never double-bounces — mirroring scheduled_action_send's dedup discipline.
--
-- Returns the dispatcher status JSON: ok | retry | permanent_fail (+ note).
--   * unresolvable / non-local / external sender → permanent_fail (was a SILENT
--     swallow in the trigger; now a logged terminal action — behavior improves).
--   * a deliver() raise → propagates → the dispatcher records 'retry' (NOT a status
--     rollback of the bounce; the bounce status was already committed by the Go
--     egress worker independently).
CREATE OR REPLACE FUNCTION scheduled_action_dsn(p_action scheduled_actions)
RETURNS JSONB AS $$
DECLARE
    v_queue_id    BIGINT;
    v_q           RECORD;
    v_sender_mb   BIGINT;
    v_sender_addr TEXT;
    v_dsn_body    TEXT;
    v_raw_ref     TEXT;
    v_dsn_msgid   TEXT;
BEGIN
    v_queue_id := (p_action.payload->>'queue_id')::BIGINT;
    IF v_queue_id IS NULL THEN
        RETURN jsonb_build_object('status', 'permanent_fail',
                                  'note', 'dsn action missing queue_id');
    END IF;

    -- Load the bounced queue row (status must be 'bounced' — the only state that
    -- warrants a DSN). A row that isn't bounced (or vanished) is a permanent no-op.
    SELECT * INTO v_q FROM outbound_queue WHERE id = v_queue_id;
    IF v_q.id IS NULL THEN
        RETURN jsonb_build_object('status', 'permanent_fail',
                                  'note', 'queue row not found');
    END IF;
    IF v_q.status <> 'bounced' THEN
        RETURN jsonb_build_object('status', 'permanent_fail',
                                  'note', 'queue row not in bounced state');
    END IF;

    -- The deterministic DSN Message-ID (also the idempotency key). A reclaim that
    -- re-runs after the DSN already landed finds the message and no-ops.
    v_dsn_msgid := '<dsn-' || v_q.id::TEXT || '@mailserver.local>';

    -- Resolve the ORIGINAL SENDER through the ADR-004 identity seam (address-aware:
    -- from_addr may be an alias or UPN). A non-local / unknown / disabled sender does
    -- not resolve → permanent_fail (we do not bounce to external senders, matching
    -- the trigger's old "only deliver if a local mailbox matched" behavior).
    SELECT primary_mailbox INTO v_sender_mb
    FROM resolve_identity(v_q.from_addr);

    IF v_sender_mb IS NULL THEN
        RETURN jsonb_build_object('status', 'permanent_fail',
                                  'note', 'sender not a local resolvable identity');
    END IF;

    -- Deliver to the resolved person's PRIMARY mailbox EMAIL — NOT the raw from_addr.
    -- from_addr may be an alias/UPN that deliver()'s own recipient resolution (mailbox
    -- email ∪ alias, lower-cased) cannot match (a UPN frequently differs from any SMTP
    -- address); routing to the primary address makes the two seams agree (ADR-004).
    SELECT email INTO v_sender_addr FROM mailboxes WHERE id = v_sender_mb;
    IF v_sender_addr IS NULL THEN
        RETURN jsonb_build_object('status', 'permanent_fail',
                                  'note', 'resolved sender mailbox has no address');
    END IF;

    -- Idempotency guard: if this DSN already landed (same deterministic Message-ID in
    -- the sender's mailbox), a reclaim re-ran us — report ok, do nothing.
    IF EXISTS (
        SELECT 1 FROM messages
        WHERE mailbox_id = v_sender_mb AND message_id = v_dsn_msgid
    ) THEN
        RETURN jsonb_build_object('status', 'ok', 'note', 'already delivered (dedup)');
    END IF;

    -- Build the multipart/report DSN body — PRESERVED BYTE-FOR-BYTE from the original
    -- trigger (schema/013_queues.sql) so the on-the-wire report is unchanged.
    v_dsn_body := 'MIME-Version: 1.0\r\n' ||
        'Content-Type: multipart/report; report-type=delivery-status;\r\n' ||
        '      boundary="====dsn.' || v_q.id::TEXT || '"\r\n' ||
        'Date: ' || to_char(now(), 'Dy, DD Mon YYYY HH24:MI:SS TZ') || '\r\n' ||
        'From: Mail Delivery System <mailer-daemon@mailserver.local>\r\n' ||
        'To: ' || v_q.from_addr || '\r\n' ||
        'Subject: Delivery Status Notification (Failure)\r\n' ||
        'Auto-Submitted: auto-generated\r\n' ||
        '\r\n' ||
        '--====dsn.' || v_q.id::TEXT || '\r\n' ||
        'Content-Type: text/plain; charset=utf-8\r\n' ||
        '\r\n' ||
        'Your message could not be delivered to:\r\n' ||
        '\r\n' ||
        '  ' || array_to_string(v_q.rcpt_addrs, ', ') || '\r\n' ||
        '\r\n' ||
        'Error: ' || COALESCE(v_q.last_error, 'unknown') || '\r\n' ||
        'Message-ID: ' || v_q.message_id || '\r\n' ||
        '\r\n' ||
        'This is a permanent delivery failure.\r\n' ||
        '\r\n' ||
        '--====dsn.' || v_q.id::TEXT || '\r\n' ||
        'Content-Type: message/delivery-status\r\n' ||
        '\r\n' ||
        'Reporting-MTA: dns; mailserver.local\r\n' ||
        'Original-Recipient: rfc822; ' || array_to_string(v_q.rcpt_addrs, ', ') || '\r\n' ||
        'Action: failed\r\n' ||
        'Status: 5.0.0\r\n' ||
        'Diagnostic-Code: smtp; ' || COALESCE(v_q.last_error, 'unknown') || '\r\n' ||
        '\r\n' ||
        '--====dsn.' || v_q.id::TEXT || '--\r\n';

    v_raw_ref := 'dsn/' || v_q.message_id || '/' || v_q.id::TEXT;

    -- Deliver the DSN to the sender via deliver() (the heaviest reducer — now run from
    -- the dispatcher's privileged connection with retry, not from inside the bounce
    -- writer's txn). The 21 positional args match deliver()'s required params; the 7
    -- defaulted params are correctly omitted (deliver_group_vacation.sql:5-33).
    PERFORM deliver(
        v_raw_ref,
        v_dsn_msgid,
        'mailer-daemon@mailserver.local',
        'Mail Delivery System',
        v_sender_addr,
        jsonb_build_array(jsonb_build_object('email', v_q.from_addr)),
        '[]'::JSONB, '[]'::JSONB,
        'Delivery Status Notification (Failure)',
        NULL, NULL,
        v_dsn_body, NULL,
        octet_length(v_dsn_body)::BIGINT, FALSE,
        now(),
        'pass', NULL, NULL, 0.0, NULL
    );

    RETURN jsonb_build_object('status', 'ok', 'note', 'dsn delivered to sender');
END;
$$ LANGUAGE plpgsql;
