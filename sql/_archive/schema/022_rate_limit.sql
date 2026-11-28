-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Rate limiting & brute-force protection (Phase 7.10)
-- Sliding-window counters per source IP and per account.
CREATE UNLOGGED TABLE IF NOT EXISTS rate_limit_counters (
  key             TEXT        PRIMARY KEY,
  count           INT         NOT NULL DEFAULT 0,
  window_start    TIMESTAMPTZ NOT NULL DEFAULT now(),
  blocked_until   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS rate_limit_block_idx ON rate_limit_counters(blocked_until)
  WHERE blocked_until IS NOT NULL;

-- Check if a request should be allowed.
-- Returns TRUE if allowed, FALSE if blocked.
CREATE OR REPLACE FUNCTION rate_limit_check(
  p_key          TEXT,
  p_max_attempts INT DEFAULT 20,      -- per window
  p_window_min   INT DEFAULT 15,      -- window size in minutes
  p_block_min    INT DEFAULT 60       -- block duration in minutes
) RETURNS BOOL AS $$
DECLARE
  v_now       TIMESTAMPTZ := now();
  v_window    TIMESTAMPTZ := date_trunc('minute', v_now) - ((extract(minute FROM v_now)::INT % p_window_min) || ' minutes')::INTERVAL;
  v_count     INT;
  v_block     TIMESTAMPTZ;
BEGIN
  -- Check existing block
  SELECT blocked_until INTO v_block FROM rate_limit_counters
  WHERE key = p_key;

  IF v_block IS NOT NULL AND v_block > v_now THEN
    RETURN FALSE;
  END IF;

  -- Reset counter if window expired, otherwise increment
  INSERT INTO rate_limit_counters (key, window_start, count)
  VALUES (p_key, v_window, 1)
  ON CONFLICT (key)
  DO UPDATE SET
    count = CASE WHEN rate_limit_counters.window_start = v_window
                 THEN rate_limit_counters.count + 1 ELSE 1 END,
    window_start = v_window,
    blocked_until = CASE WHEN rate_limit_counters.window_start = v_window
                         THEN rate_limit_counters.blocked_until ELSE NULL END
  RETURNING count INTO v_count;

  -- Apply block if exceeded
  IF v_count > p_max_attempts THEN
    UPDATE rate_limit_counters
    SET blocked_until = v_now + (p_block_min || ' minutes')::INTERVAL
    WHERE key = p_key;
    RETURN FALSE;
  END IF;

  RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

-- Prune old rate limit windows (pg_cron every hour)
CREATE OR REPLACE FUNCTION rate_limit_prune()
RETURNS VOID AS $$
BEGIN
  DELETE FROM rate_limit_counters
  WHERE window_start < now() - interval '2 hours';
END;
$$ LANGUAGE plpgsql;
