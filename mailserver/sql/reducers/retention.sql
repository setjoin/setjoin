-- Retention reducers: tag messages with their governing retention policy
-- at delivery time, then purge expired tags on a daily schedule.

-- tag_retention: pick the most specific applicable retention_policy for the
-- target mailbox's domain, or the global default if none is domain-specific.
-- No policy → no tag (retention silently disabled for that domain).
-- Called from deliver() and send() after the message row is committed.
CREATE OR REPLACE FUNCTION tag_retention(
  p_message_id  BIGINT,
  p_received_at TIMESTAMPTZ,
  p_mailbox_id  BIGINT
) RETURNS VOID AS $$
DECLARE
  v_domain_id BIGINT;
  v_policy    RECORD;
  v_expires   TIMESTAMPTZ;
BEGIN
  -- Domain behind the mailbox via the one resolver seam (ADR-003), not a
  -- hand-join of `mailboxes`. Same lookup; centralises the mapping.
  SELECT domain_id INTO v_domain_id FROM account_scope(p_mailbox_id);

  -- Domain-specific policy wins over global default.
  SELECT * INTO v_policy
  FROM retention_policies
  WHERE (domain_id = v_domain_id) OR (domain_id IS NULL AND is_default)
  ORDER BY (domain_id IS NOT NULL) DESC, id ASC
  LIMIT 1;

  IF v_policy.id IS NULL THEN
    RETURN;
  END IF;

  v_expires := CASE
                 WHEN v_policy.retain_days IS NULL THEN NULL  -- keep forever
                 ELSE p_received_at + make_interval(days => v_policy.retain_days)
               END;

  INSERT INTO message_retention_tags (message_id, received_at, policy_id, expires_at)
  VALUES (p_message_id, p_received_at, v_policy.id, v_expires)
  ON CONFLICT (message_id, received_at) DO NOTHING;
END;
$$ LANGUAGE plpgsql;

-- enforce_retention: pg_cron worker. Processes message_retention_tags whose
-- expires_at is in the past. Only the 'delete' action is processed; 'hold'
-- is a no-op (leave the message in place).
--
-- Messages under litigation_hold fail the DELETE trigger — we catch the
-- exception per row so one held message doesn't stop the batch.
CREATE OR REPLACE FUNCTION enforce_retention(p_batch_size INT DEFAULT 1000) RETURNS INT AS $$
DECLARE
  v_row             RECORD;
  v_new_email_state BIGINT;
  v_deleted         INT := 0;
BEGIN
  FOR v_row IN
    SELECT t.message_id, t.received_at, p.action,
           m.message_id AS rfc_msgid, m.from_addr, m.mailbox_id,
           m.size_bytes
    FROM message_retention_tags t
    JOIN retention_policies p ON p.id = t.policy_id
    JOIN messages m ON m.id = t.message_id AND m.received_at = t.received_at
    WHERE t.expires_at IS NOT NULL
      AND t.expires_at <= now()
      AND p.action = 'delete'
    ORDER BY t.expires_at
    LIMIT p_batch_size
  LOOP
    BEGIN
      DELETE FROM message_retention_tags
      WHERE message_id = v_row.message_id AND received_at = v_row.received_at;

      DELETE FROM messages
      WHERE id = v_row.message_id AND received_at = v_row.received_at;

      PERFORM trace(v_row.rfc_msgid, 'expired', v_row.from_addr, '',
        NULL, jsonb_build_object('policy_action', 'delete',
                                 'mailbox_id', v_row.mailbox_id));

      -- Free the mailbox quota + advance JMAP state so the delete surfaces via
      -- Email/changes. The message_tags ON DELETE CASCADE counter trigger
      -- (trg_message_tags_counters) already decrements tags.total_count/unread_count
      -- for this message — it derives the unread delta from is_read itself, so we
      -- neither read is_read here nor touch any folder counter (there is none).
      UPDATE mailboxes
      SET used_bytes         = GREATEST(0, used_bytes - v_row.size_bytes),
          jmap_mailbox_state = jmap_mailbox_state + 1,
          jmap_email_state   = jmap_email_state + 1
      WHERE id = v_row.mailbox_id
      RETURNING jmap_email_state INTO v_new_email_state;
      PERFORM append_email_change(v_row.mailbox_id, v_new_email_state, NULL, 'resync');

      v_deleted := v_deleted + 1;

    EXCEPTION WHEN SQLSTATE 'BZ015' THEN
      -- ONLY the litigation-hold trigger (trg_messages_hold_check raises BZ015) is a
      -- "skip this row, keep going" outcome. Catching WHEN OTHERS silently miscounted
      -- every other failure (OOM, constraint/permission error, replication lag) as a
      -- litigation hold and reported apparent success. Let any non-BZ015 exception
      -- propagate so the enforcer fails loudly instead of lying. (Mirrors
      -- content_purge_messages, which had this exact hazard and was narrowed first.)
      NULL;
    END;
  END LOOP;

  RETURN v_deleted;
END;
$$ LANGUAGE plpgsql;

-- Register pg_cron enforcer: runs daily at 02:05.
-- Batch size scales dynamically with queue depth to prevent multi-year backlogs.
-- [pg_cron→Go cron worker] SELECT cron.schedule('enforce-retention', '5 2 * * *',
--   $$ SELECT enforce_retention(LEAST(GREATEST(1000,
