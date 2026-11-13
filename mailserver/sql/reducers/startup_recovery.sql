-- startup_recovery(): called by the Go gateway before it accepts connections.
-- Detects and repairs any state left in inconsistent form by a crash or power loss.
-- Returns a JSON summary of what was fixed so the gateway can alert admins.
CREATE OR REPLACE FUNCTION startup_recovery() RETURNS JSONB AS $$
DECLARE
  v_reset_queue    INT := 0;
  v_repaired_counts INT := 0;
  v_row_count      INT;
  v_summary        JSONB;
BEGIN
  -- 1. Reset outbound queue items stuck in 'sending' for more than 5 minutes.
  --    These were mid-delivery when the crash happened. Reset to 'pending' so
  --    the delivery worker retries them.
  UPDATE outbound_queue
  SET status = 'pending', last_error = 'reset by startup_recovery after crash'
  WHERE status = 'sending'
    AND queued_at < now() - interval '5 minutes';
  GET DIAGNOSTICS v_reset_queue = ROW_COUNT;

  -- 2. Sessions table is unlogged so it was already cleared on restart — nothing to do.

  -- 3. (folder counter recompute removed in V077 — folders.*_count are dropped;
  --    the live counters are the tag counters repaired in step 3b below.)

  -- 3b. Repair tag counters from message_tags junction.
  WITH tag_recount AS (
    SELECT t0.id AS tag_id,
           COUNT(m.id) FILTER (WHERE NOT m.is_deleted) AS total,
           COUNT(m.id) FILTER (WHERE NOT m.is_deleted AND NOT m.is_read) AS unread,
           COALESCE(SUM(m.size_bytes) FILTER (WHERE NOT m.is_deleted), 0) AS sz
    FROM tags t0
    LEFT JOIN message_tags mt ON mt.tag_id = t0.id
    LEFT JOIN messages m ON m.id = mt.message_id AND m.received_at = mt.received_at
    GROUP BY t0.id
  )
  UPDATE tags t
  SET total_count  = r.total,
      unread_count = r.unread,
      size_bytes   = r.sz
  FROM tag_recount r
  WHERE t.id = r.tag_id
    AND (t.total_count != r.total OR t.unread_count != r.unread OR t.size_bytes != r.sz);
  GET DIAGNOSTICS v_row_count = ROW_COUNT;
  v_repaired_counts := v_row_count;

  -- 4. Recompute mailbox used_bytes from each live message exactly once. A
  --    message can carry multiple tags, so summing tag counters overcharges
  --    labelled messages. Include empty mailboxes so stale quota reaches zero.
  WITH message_sums AS (
    SELECT mb0.id AS mailbox_id,
           COALESCE(SUM(m.size_bytes) FILTER (WHERE NOT m.is_deleted), 0) AS sz
    FROM mailboxes mb0
    LEFT JOIN messages m ON m.mailbox_id = mb0.id
    GROUP BY mb0.id
  )
  UPDATE mailboxes mb
  SET used_bytes = ms.sz
  FROM message_sums ms
  WHERE mb.id = ms.mailbox_id AND mb.used_bytes != ms.sz;

  -- 5. Reset any journal_queue items stuck in 'failed' or 'pending' with high
  --    attempt count so drain_journal_queue can retry them.
  UPDATE journal_queue SET status = 'pending', attempt_count = 0
  WHERE status = 'failed' AND attempt_count >= 3;

  -- 6. Build summary
  v_summary := jsonb_build_object(
    'reset_outbound_queue',   v_reset_queue,
    'repaired_folder_counts', v_repaired_counts,
    'recovered_at',           now()
  );

  -- 7. Record in crash_events if anything was actually fixed
  IF v_reset_queue > 0 OR v_repaired_counts > 0 THEN
    INSERT INTO crash_events (
      component, severity, description, recovery_action, recovered_at
    ) VALUES (
      'postgresql',
      'warn',
      'Startup recovery detected inconsistent state (likely caused by unclean shutdown)',
      v_summary::TEXT,
      now()
    );
  END IF;

  RETURN v_summary;
END;
$$ LANGUAGE plpgsql;
