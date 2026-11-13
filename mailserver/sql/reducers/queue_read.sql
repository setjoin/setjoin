-- queue_read.sql: F3 shared read interface for the Background Jobs console.
-- Normalizes each bespoke queue's per-queue terminal status onto a common
-- {active, failed, dead, done} vocabulary so one console read path serves every
-- queue WITHOUT unifying storage. Cross-mailbox/operational — admin-gated at the
-- Go route layer (JobsHandler on workerPool), takes no p_mailbox_id.
--
-- Status mapping (per spec F3):
--   journal_queue:     pending|deferred -> active, failed -> failed, dead -> dead, delivered -> done
--   outbound_queue:    pending|sending|deferred -> active, bounced -> failed, delivered -> done
--   scheduled_actions: pending|processing -> active, failed -> failed, done -> done
--   bulk_role_jobs:    queued|running -> active, done -> done, error -> failed

CREATE OR REPLACE VIEW queue_status_normalized AS
  SELECT
    'journal'::TEXT                         AS queue,
    jq.id::TEXT                             AS id,
    jq.status                               AS status,
    CASE jq.status
      WHEN 'pending'   THEN 'active'
      WHEN 'deferred'  THEN 'active'
      WHEN 'failed'    THEN 'failed'
      WHEN 'dead'      THEN 'dead'
      WHEN 'delivered' THEN 'done'
      ELSE 'active'
    END                                     AS normalized,
    jq.attempt_count                        AS attempt_count,
    jq.next_attempt_at                      AS next_attempt_at,
    jq.last_error                           AS last_error,
    jq.queued_at                            AS queued_at,
    jq.message_id                           AS label
  FROM journal_queue jq
  UNION ALL
  SELECT
    'outbound'::TEXT,
    oq.id::TEXT,
    oq.status,
    CASE oq.status
      WHEN 'pending'   THEN 'active'
      WHEN 'sending'   THEN 'active'
      WHEN 'deferred'  THEN 'active'
      WHEN 'bounced'   THEN 'failed'
      WHEN 'delivered' THEN 'done'
      ELSE 'active'
    END,
    oq.attempt_count,
    oq.next_attempt_at,
    oq.last_error,
    oq.queued_at,
    oq.message_id
  FROM outbound_queue oq
  UNION ALL
  SELECT
    'scheduled'::TEXT,
    sa.id::TEXT,
    sa.status,
    CASE sa.status
      WHEN 'pending'    THEN 'active'
      WHEN 'processing' THEN 'active'
      WHEN 'failed'     THEN 'failed'
      WHEN 'done'       THEN 'done'
      ELSE 'active'
    END,
    sa.attempts,
    NULL::TIMESTAMPTZ,
    sa.last_error,
    sa.created_at,
    sa.action_kind
  FROM scheduled_actions sa
  UNION ALL
  SELECT
    'bulk_role'::TEXT,
    brj.id::TEXT,
    brj.status,
    CASE brj.status
      WHEN 'queued'  THEN 'active'
      WHEN 'running' THEN 'active'
      WHEN 'done'    THEN 'done'
      WHEN 'error'   THEN 'failed'
      ELSE 'active'
    END,
    0,                                                               -- attempt_count (n/a)
    NULL::TIMESTAMPTZ,                                               -- next_attempt_at (n/a)
    brj.error,                                                       -- last_error
    brj.created_at,                                                  -- queued_at
    brj.op || ' role #' || brj.role_id || ' ×' || brj.total        -- label
  FROM bulk_role_jobs brj;

-- get_queue_summary: counts per normalized state for one queue. p_queue is one of
-- 'journal' | 'outbound' | 'scheduled' | 'bulk_role'. An unknown queue raises BZ051.
CREATE OR REPLACE FUNCTION get_queue_summary(p_queue TEXT)
RETURNS TABLE(active INT, failed INT, dead INT, done INT, total INT) AS $$
BEGIN
  IF p_queue NOT IN ('journal', 'outbound', 'scheduled', 'bulk_role') THEN
    RAISE EXCEPTION 'get_queue_summary: unknown queue %', p_queue USING ERRCODE='BZ051';
  END IF;
  RETURN QUERY
    SELECT
      COUNT(*) FILTER (WHERE n.normalized = 'active')::INT,
      COUNT(*) FILTER (WHERE n.normalized = 'failed')::INT,
      COUNT(*) FILTER (WHERE n.normalized = 'dead')::INT,
      COUNT(*) FILTER (WHERE n.normalized = 'done')::INT,
      COUNT(*)::INT
    FROM queue_status_normalized n
    WHERE n.queue = p_queue;
END;
$$ LANGUAGE plpgsql STABLE;

-- list_queue: paginated normalized rows for one queue, optionally filtered to a
-- normalized state. p_status is one of 'active'|'failed'|'dead'|'done'|'all'|''
-- (empty/'all' = no filter) OR the synthetic 'attention' filter (D1) =
-- normalized IN ('failed','dead'), the console's failure-first default view.
-- For 'attention' (D6) rows sort dead-before-failed then oldest queued_at first
-- (most-stuck floats to top); every other view sorts newest queued_at first.
-- Returns one JSONB object per row (contract columns).
CREATE OR REPLACE FUNCTION list_queue(
  p_queue  TEXT,
  p_status TEXT,
  p_limit  INT DEFAULT 50,
  p_offset INT DEFAULT 0
) RETURNS TABLE(item JSONB) AS $$
BEGIN
  IF p_queue NOT IN ('journal', 'outbound', 'scheduled', 'bulk_role') THEN
    RAISE EXCEPTION 'list_queue: unknown queue %', p_queue USING ERRCODE='BZ051';
  END IF;
  RETURN QUERY
    SELECT jsonb_build_object(
        'id', n.id,
        'queue', n.queue,
        'status', n.status,
        'normalized', n.normalized,
        'label', n.label,
        'attemptCount', n.attempt_count,
        'nextAttemptAt', n.next_attempt_at,
        'lastError', n.last_error,
        'queuedAt', n.queued_at
      )
    FROM queue_status_normalized n
    WHERE n.queue = p_queue
      AND (
        p_status IS NULL OR p_status = '' OR p_status = 'all'
        OR (p_status = 'attention' AND n.normalized IN ('failed', 'dead'))
        OR n.normalized = p_status
      )
    ORDER BY
      -- attention view: dead (0) before failed (1), then oldest queued_at first.
      CASE WHEN p_status = 'attention' AND n.normalized = 'dead' THEN 0
           WHEN p_status = 'attention' AND n.normalized = 'failed' THEN 1
           ELSE 0 END ASC,
      CASE WHEN p_status = 'attention' THEN n.queued_at END ASC NULLS LAST,
      -- every other view: newest first.
      n.queued_at DESC NULLS LAST
    LIMIT LEAST(GREATEST(COALESCE(p_limit, 50), 1), 200)
    OFFSET GREATEST(COALESCE(p_offset, 0), 0);
END;
$$ LANGUAGE plpgsql STABLE;
