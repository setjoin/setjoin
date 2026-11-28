-- settle_job: the shared queue failure-handling helper (F2). A SQL-resident drain
-- calls this after running one row's body, passing the outcome and the row's
-- already-incremented attempt_count. It applies capped exponential backoff and
-- returns the status the caller should write (the caller owns the UPDATE — this
-- reducer is queue-table-agnostic). Backoff math lifted verbatim from the proven
-- scheduled_actions_dispatch.sql dispatcher.
--
--   p_outcome:        'ok' | 'retry' | 'permanent_fail'
--   p_attempt_count:  attempts so far (the caller increments before calling).
--   p_last_error:     failure reason (recorded in the audit row's note).
--   p_max_attempts:   retries-exhausted threshold (default 5).
--   p_backoff_cap:    backoff ceiling (default 1 hour).
--   p_audit_id:       audit key (uuid); NULL skips the audit row.
--   p_*_status:       the caller queue's vocabulary for done/active/terminal.
--
-- Returns one row: (resolved_status, next_attempt_at, is_terminal).
CREATE OR REPLACE FUNCTION settle_job(
  p_outcome         TEXT,
  p_attempt_count   INT,
  p_last_error      TEXT     DEFAULT NULL,
  p_max_attempts    INT      DEFAULT 5,
  p_backoff_cap     INTERVAL DEFAULT interval '1 hour',
  p_audit_id        UUID     DEFAULT NULL,
  p_terminal_status TEXT     DEFAULT 'dead',
  p_active_status   TEXT     DEFAULT 'deferred',
  p_done_status     TEXT     DEFAULT 'delivered'
) RETURNS TABLE (resolved_status TEXT, next_attempt_at TIMESTAMPTZ, is_terminal BOOLEAN) AS $$
DECLARE
  v_status   TEXT;
  v_next     TIMESTAMPTZ;
  v_terminal BOOLEAN;
  v_outcome  TEXT;
BEGIN
  IF p_outcome NOT IN ('ok','retry','permanent_fail') THEN
    RAISE EXCEPTION 'settle_job: invalid outcome %', p_outcome
      USING ERRCODE = 'BZ081',
            HINT = jsonb_build_object('type','bad_outcome','outcome',p_outcome)::TEXT;
  END IF;

  IF p_outcome = 'ok' THEN
    v_status := p_done_status; v_next := NULL; v_terminal := FALSE; v_outcome := 'done';
  ELSIF p_outcome = 'permanent_fail' OR p_attempt_count >= p_max_attempts THEN
    v_status := p_terminal_status; v_next := NULL; v_terminal := TRUE; v_outcome := 'failed';
  ELSE
    -- Transient failure: exponential, capped backoff.
    v_status := p_active_status;
    v_next   := now() + LEAST(interval '1 minute' * power(2, p_attempt_count), p_backoff_cap);
    v_terminal := FALSE; v_outcome := 'retry';
  END IF;

  IF p_audit_id IS NOT NULL THEN
    INSERT INTO scheduled_action_log (action_id, from_status, to_status, worker, outcome, note)
    VALUES (p_audit_id, NULL, v_status, 'settle_job', v_outcome, p_last_error);
  END IF;

  RETURN QUERY SELECT v_status, v_next, v_terminal;
END;
$$ LANGUAGE plpgsql;
