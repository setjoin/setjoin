-- Journaling reducers: BCC-style archiving of mail into a dedicated journal mailbox.
-- Policies live in journaling_policies; queue lives in journal_queue.

-- journal_if_policy_matches: evaluates journaling policies for one message event.
-- If an enabled policy matches the (domain, direction) pair, enqueue a journal_queue row.
-- Domain-specific policies take precedence; a NULL-domain policy acts as a global fallback.
-- Called from deliver() with direction='inbound' and from send() with direction='outbound'.
CREATE OR REPLACE FUNCTION journal_if_policy_matches(
  p_message_id      TEXT,
  p_from_addr       TEXT,
  p_rcpt_addr       TEXT,
  p_raw_ref         TEXT,
  p_domain_id       BIGINT,
  p_direction       TEXT            -- 'inbound' | 'outbound'
) RETURNS VOID AS $$
DECLARE
  v_policy        RECORD;
  v_pending_count INT;
BEGIN
  IF p_direction NOT IN ('inbound','outbound') THEN
    RAISE EXCEPTION 'journal_if_policy_matches: invalid direction %', p_direction;
  END IF;

  -- Prefer domain-specific policy; fall back to global (domain_id IS NULL).
  SELECT * INTO v_policy
  FROM journaling_policies
  WHERE enabled = TRUE
    AND direction IN (p_direction, 'both')
    AND (domain_id = p_domain_id OR domain_id IS NULL)
  ORDER BY (domain_id IS NOT NULL) DESC, id ASC
  LIMIT 1;

  IF v_policy.id IS NULL THEN
    RETURN;
  END IF;

  INSERT INTO journal_queue
    (message_id, envelope_from, envelope_to, raw_ref, journal_mailbox_id, status)
  VALUES
    (p_message_id, p_from_addr, p_rcpt_addr, p_raw_ref, v_policy.journal_mailbox_id, 'pending');

  -- Backpressure: fire admin alert when journal queue exceeds 10,000 pending rows
  SELECT COUNT(*) INTO v_pending_count FROM journal_queue WHERE status = 'pending';
  IF v_pending_count > 10000 THEN
    PERFORM app_notify('admin:alert',
      json_build_object('type','journal_backlog','count', v_pending_count)::text);
  END IF;
END;
$$ LANGUAGE plpgsql;

-- drain_journal_queue: pg_cron worker. Materialises pending (and due deferred)
-- journal_queue rows as messages in their destination journal mailbox. Each
-- failure routes through settle_job (F2): capped exp backoff → deferred | dead +
-- audit row; a 'dead' row fires app_notify('admin:alert', journal_dead_letter).
-- Mail is HELD on dead-letter, never deleted (compliance posture (a)).
--
-- p_retry_only: when TRUE, only due-deferred rows are processed (the retry-pass
-- cron task), mirroring drain_outbound_queue(true). When FALSE (default), both
-- pending and due-deferred rows are drained.
CREATE OR REPLACE FUNCTION drain_journal_queue(
  p_batch_size INT     DEFAULT 100,
  p_retry_only BOOLEAN DEFAULT FALSE
) RETURNS INT AS $$
DECLARE
  v_row           RECORD;
  v_tag_id        BIGINT;
  v_size          BIGINT;
  v_inserted_id   BIGINT;
  v_delivered     INT := 0;
  v_settled       RECORD;
  v_audit_id      UUID;
  v_err           TEXT;
BEGIN
  FOR v_row IN
    SELECT * FROM journal_queue
    WHERE (NOT p_retry_only AND status = 'pending')
       OR (status = 'deferred' AND next_attempt_at <= now())
    ORDER BY id
    LIMIT p_batch_size
    FOR UPDATE SKIP LOCKED
  LOOP
    BEGIN
      v_tag_id := get_tag_id('Inbox', v_row.journal_mailbox_id);

      IF v_tag_id IS NULL THEN
        -- deterministic missing-tag failure → ride the retry→dead path.
        RAISE EXCEPTION 'journal mailbox % has no Inbox tag', v_row.journal_mailbox_id;
      END IF;

      v_size := 0;

      INSERT INTO messages (
        mailbox_id, folder_id,
        message_id, subject, from_addr,
        to_addrs, cc_addrs, bcc_addrs,
        body_text, size_bytes, has_attachments,
        thread_id, raw_ref, sent_at,
        is_read, held, received_at
      ) VALUES (
        v_row.journal_mailbox_id, v_tag_id,
        v_row.message_id, NULL, v_row.envelope_from,
        jsonb_build_array(jsonb_build_object('email', v_row.envelope_to)),
        '[]'::JSONB, '[]'::JSONB,
        NULL, v_size, FALSE,
        v_row.message_id, v_row.raw_ref, v_row.queued_at,
        TRUE,
        coalesce((SELECT litigation_hold FROM mailboxes WHERE id = v_row.journal_mailbox_id), TRUE),
        now()
      ) RETURNING id INTO v_inserted_id;

      PERFORM tag_message(
        v_inserted_id,
        now()::TIMESTAMPTZ, 'Inbox', v_row.journal_mailbox_id, 'journal', TRUE
      );

      UPDATE journal_queue SET
        status = 'delivered',
        delivered_at = now()
      WHERE id = v_row.id;

      v_delivered := v_delivered + 1;

    EXCEPTION WHEN OTHERS THEN
      -- Don't let one bad row kill the batch. Settle via the shared helper:
      -- attempt_count was the count BEFORE this attempt; this attempt makes it +1.
      v_err := SQLERRM;
      v_audit_id := gen_random_uuid();
      SELECT * INTO v_settled
      FROM settle_job('retry', v_row.attempt_count + 1, v_err,
                       5, interval '1 hour', v_audit_id,
                       'dead', 'deferred', 'delivered');

      UPDATE journal_queue SET
        status          = v_settled.resolved_status,
        attempt_count   = attempt_count + 1,
        next_attempt_at = v_settled.next_attempt_at,
        last_error      = v_err
      WHERE id = v_row.id;

      IF v_settled.is_terminal THEN
        PERFORM app_notify('admin:alert',
          json_build_object('type','journal_dead_letter',
                            'id', v_row.id,
                            'last_error', v_err)::text);
      END IF;
    END;
  END LOOP;

  RETURN v_delivered;
END;
$$ LANGUAGE plpgsql;

-- Register pg_cron drainer: runs every minute.
-- [pg_cron→Go cron worker] SELECT cron.schedule('drain-journal-queue', '* * * * *',
--   $$ SELECT drain_journal_queue(); $$);
