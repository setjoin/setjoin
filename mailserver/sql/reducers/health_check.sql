-- health_check(): run by pg_cron every 5 minutes.
-- Writes results to health_history and logs crash_events on consecutive failures.
-- All thresholds are configurable via system_config.

-- Helper: read a health check config threshold, falling back to a default.
CREATE OR REPLACE FUNCTION get_hc_config(p_key TEXT, p_default REAL) RETURNS REAL AS $$
    SELECT COALESCE((value #>> '{}')::REAL, p_default) FROM system_config WHERE key = p_key;
$$ LANGUAGE sql STABLE;

CREATE OR REPLACE FUNCTION health_check() RETURNS VOID AS $$
DECLARE
  v_lag_seconds     NUMERIC;
  v_queue_depth     INT;
  v_queue_oldest_m  NUMERIC;
  v_db_size_gb      NUMERIC;
  v_auth_fails      BIGINT;
  v_journal_depth   INT;
  v_journal_dead    INT;
  v_sched_depth     INT;
  v_sched_failed    INT;
  v_secevents_failed INT;
  v_secevents_age    NUMERIC;
  v_esc_window_min   INT;
  v_esc_min          INT;
  v_esc_rec          RECORD;
BEGIN

  -- 1. Replication lag (only meaningful on primary with replicas)
  SELECT EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp()))
  INTO v_lag_seconds;
  v_lag_seconds := coalesce(v_lag_seconds, 0);

  INSERT INTO health_history (check_name, status, value, threshold, details) VALUES (
    'replication_lag_seconds',
    CASE WHEN v_lag_seconds > get_hc_config('hc_replication_lag_error_sec', 60) THEN 'error'
         WHEN v_lag_seconds > get_hc_config('hc_replication_lag_warn_sec',  30) THEN 'warn'
         ELSE 'ok' END,
    v_lag_seconds,
    get_hc_config('hc_replication_lag_error_sec', 60),
    'Streaming replication lag in seconds'
  );

  -- 2. Outbound queue depth
  SELECT COUNT(*) INTO v_queue_depth
  FROM outbound_queue WHERE status IN ('pending','deferred');

  INSERT INTO health_history (check_name, status, value, threshold, details) VALUES (
    'outbound_queue_depth',
    CASE WHEN v_queue_depth > get_hc_config('hc_outbound_queue_error', 500) THEN 'error'
         WHEN v_queue_depth > get_hc_config('hc_outbound_queue_warn',  100) THEN 'warn'
         ELSE 'ok' END,
    v_queue_depth,
    get_hc_config('hc_outbound_queue_error', 500),
    'Messages in outbound queue awaiting delivery'
  );

  -- 3. Oldest deferred outbound item (in minutes)
  SELECT EXTRACT(EPOCH FROM (now() - MIN(queued_at)))/60
  INTO v_queue_oldest_m
  FROM outbound_queue WHERE status IN ('pending','deferred');

  v_queue_oldest_m := coalesce(v_queue_oldest_m, 0);

  INSERT INTO health_history (check_name, status, value, threshold, details) VALUES (
    'outbound_queue_age_minutes',
    CASE WHEN v_queue_oldest_m > get_hc_config('hc_outbound_queue_age_error_min', 60) THEN 'error'
         WHEN v_queue_oldest_m > get_hc_config('hc_outbound_queue_age_warn_min', 15) THEN 'warn'
         ELSE 'ok' END,
    v_queue_oldest_m,
    get_hc_config('hc_outbound_queue_age_error_min', 60),
    'Age of oldest undelivered message in minutes'
  );

  -- 3b. Journal queue depth (pending + deferred awaiting materialisation)
  SELECT COUNT(*) INTO v_journal_depth
  FROM journal_queue WHERE status IN ('pending','deferred');

  INSERT INTO health_history (check_name, status, value, threshold, details) VALUES (
    'journal_queue_depth',
    CASE WHEN v_journal_depth > get_hc_config('hc_journal_queue_error', 10000) THEN 'error'
         WHEN v_journal_depth > get_hc_config('hc_journal_queue_warn',  1000) THEN 'warn'
         ELSE 'ok' END,
    v_journal_depth,
    get_hc_config('hc_journal_queue_error', 10000),
    'Journal queue rows awaiting materialisation'
  );

  -- 3c. Journal dead-letter count (terminal failures — HELD compliance mail)
  SELECT COUNT(*) INTO v_journal_dead
  FROM journal_queue WHERE status = 'dead';

  INSERT INTO health_history (check_name, status, value, threshold, details) VALUES (
    'journal_dead_letter',
    CASE WHEN v_journal_dead > get_hc_config('hc_journal_dead_error', 0) THEN 'error'
         ELSE 'ok' END,
    v_journal_dead,
    get_hc_config('hc_journal_dead_error', 0),
    'Journal rows dead-lettered (compliance mail held, never delivered — operator must re-pend)'
  );

  -- 3d. Scheduled-actions queue depth (pending due now or future)
  SELECT COUNT(*) INTO v_sched_depth
  FROM scheduled_actions WHERE status = 'pending';

  INSERT INTO health_history (check_name, status, value, threshold, details) VALUES (
    'scheduled_actions_depth',
    CASE WHEN v_sched_depth > get_hc_config('hc_scheduled_depth_error', 5000) THEN 'error'
         WHEN v_sched_depth > get_hc_config('hc_scheduled_depth_warn',  1000) THEN 'warn'
         ELSE 'ok' END,
    v_sched_depth,
    get_hc_config('hc_scheduled_depth_error', 5000),
    'Pending scheduled actions awaiting dispatch'
  );

  -- 3e. Scheduled-actions terminal failures (silent to user+operator before this)
  SELECT COUNT(*) INTO v_sched_failed
  FROM scheduled_actions WHERE status = 'failed';

  INSERT INTO health_history (check_name, status, value, threshold, details) VALUES (
    'scheduled_actions_failed',
    CASE WHEN v_sched_failed > get_hc_config('hc_scheduled_failed_error', 0) THEN 'error'
         ELSE 'ok' END,
    v_sched_failed,
    get_hc_config('hc_scheduled_failed_error', 0),
    'Scheduled actions that terminally failed (snooze/scheduled-send/reminder never fired)'
  );

  -- 3f. Security-event outbox terminal failures (L2-C4: durable alert signal —
  -- a status='failed' outbox row means a security event exhausted every
  -- delivery attempt; rows are retained, never deleted, so the count is the
  -- operator's work queue). Threshold call-site COALESCE: get_hc_config
  -- returns NULL for an ABSENT key, and NULL would silently compare healthy —
  -- any terminal failure must be alertable, so the default (0) engages
  -- regardless of config state.
  SELECT COUNT(*) INTO v_secevents_failed
  FROM security_event_outbox WHERE status = 'failed';

  INSERT INTO health_history (check_name, status, value, threshold, details) VALUES (
    'security_event_outbox_failed',
    CASE WHEN v_secevents_failed > COALESCE(get_hc_config('hc_secevents_failed_error', 0), 0) THEN 'error'
         ELSE 'ok' END,
    v_secevents_failed,
    COALESCE(get_hc_config('hc_secevents_failed_error', 0), 0),
    'Security-event outbox rows that terminally failed delivery (rows retained — operator must investigate the delivery sink)'
  );

  -- 3g. Security-event outbox stale-pending age (L2-C4). Age of the oldest
  -- pending row, evaluated against lease+backoff: only rows whose
  -- next_attempt_at has already passed are counted, so a row under an active
  -- claim lease or its scheduled backoff is NOT an incident — sustained age
  -- means the delivery drain is not keeping up. Warn/error defaults 15/60
  -- (matching hc_outbound_queue_age_*), COALESCE-wrapped so an absent config
  -- key cannot NULL the comparison into a silent 'ok'.
  SELECT COALESCE(EXTRACT(EPOCH FROM (now() - MIN(created_at)))/60, 0)
  INTO v_secevents_age
  FROM security_event_outbox
  WHERE status = 'pending' AND next_attempt_at <= now();

  INSERT INTO health_history (check_name, status, value, threshold, details) VALUES (
    'security_event_outbox_pending_age_minutes',
    CASE WHEN v_secevents_age > COALESCE(get_hc_config('hc_secevents_age_error_min', 60), 60) THEN 'error'
         WHEN v_secevents_age > COALESCE(get_hc_config('hc_secevents_age_warn_min',  15), 15) THEN 'warn'
         ELSE 'ok' END,
    v_secevents_age,
    COALESCE(get_hc_config('hc_secevents_age_error_min', 60), 60),
    'Age in minutes of the oldest due (lease-expired) pending security-event row — delivery drain not keeping up'
  );

  -- 4. Database size
  SELECT pg_database_size(current_database()) / 1073741824.0 INTO v_db_size_gb;

  INSERT INTO health_history (check_name, status, value, threshold, details) VALUES (
    'database_size_gb',
    CASE WHEN v_db_size_gb > get_hc_config('hc_db_size_error_gb', 100) THEN 'error'
         WHEN v_db_size_gb > get_hc_config('hc_db_size_warn_gb',   80) THEN 'warn'
         ELSE 'ok' END,
    round(v_db_size_gb, 2),
    get_hc_config('hc_db_size_error_gb', 100),
    'PostgreSQL database size in GB'
  );

  -- 5. Failed auth rate
  SELECT COALESCE(SUM(count), 0) INTO v_auth_fails
  FROM rate_limit_counters
  WHERE key LIKE 'auth:%'
    AND window_start > now() - interval '5 minutes';

  INSERT INTO health_history (check_name, status, value, threshold, details) VALUES (
    'auth_failure_rate',
    CASE WHEN v_auth_fails > get_hc_config('hc_auth_fail_error', 200) THEN 'error'
         WHEN v_auth_fails > get_hc_config('hc_auth_fail_warn',   50) THEN 'warn'
         ELSE 'ok' END,
    v_auth_fails,
    get_hc_config('hc_auth_fail_error', 200),
    'Failed authentication attempts in the last 5 minutes'
  );

  -- 6. DKIM key expiry
  INSERT INTO health_history (check_name, status, value, threshold, details)
  SELECT
    'dkim_key_expiry:' || name,
    CASE
      WHEN dkim_key_expires_at < now() + make_interval(days => get_hc_config('hc_dkim_expiry_error_days', 7)::INT)  THEN 'error'
      WHEN dkim_key_expires_at < now() + make_interval(days => get_hc_config('hc_dkim_expiry_warn_days', 30)::INT) THEN 'warn'
      ELSE 'ok'
    END,
    EXTRACT(DAY FROM (dkim_key_expires_at - now())),
    get_hc_config('hc_dkim_expiry_warn_days', 30),
    'Days until DKIM key expires for domain ' || name
  FROM domains
  WHERE dkim_key_expires_at IS NOT NULL AND is_local = TRUE;

  -- 7. Crash events
  IF EXISTS (
    SELECT 1 FROM crash_events
    WHERE severity = 'fatal'
      AND admin_notified = FALSE
      AND occurred_at > now() - make_interval(mins => get_hc_config('hc_crash_window_min', 10)::INT)
  ) THEN
    INSERT INTO health_history (check_name, status, details) VALUES (
      'crash_events', 'error', 'Unacknowledged fatal crash events detected'
    );
  END IF;

  -- 8. Partition existence: verify current + next month partitions exist for
  -- every month-partitioned table — catalog-derived with the same predicate as
  -- create_monthly_partitions() (RANGE parent, single timestamptz key), so new
  -- partitioned tables are monitored automatically and no hand list can drift.
  INSERT INTO health_history (check_name, status, details)
  SELECT
      'partition:' || tbl.table_name || '_' || to_char(target_month, 'YYYY_MM'),
      CASE WHEN EXISTS (
          SELECT 1 FROM pg_class
          WHERE relname = tbl.table_name || '_' || to_char(target_month, 'YYYY_MM')
      ) THEN 'ok'
      -- A parent WITH a default partition cannot hard-fail inserts on a missing
      -- month partition (rows land in the default; only pruning granularity
      -- degrades — and rows already in the default for that month legitimately
      -- BLOCK creating it, 23514). Only default-less parents (the audit trio)
      -- are insert-critical → 'error'; default-backed ones report 'warning'.
      WHEN tbl.has_default THEN 'warn'
      ELSE 'error' END,
      'Partition for ' || tbl.table_name || ' month ' || to_char(target_month, 'YYYY-MM')
  FROM generate_series(0, 1) AS s(month_offset),
       (SELECT c.relname::text AS table_name, (p.partdefid <> 0) AS has_default
          FROM pg_partitioned_table p
          JOIN pg_class     c ON c.oid = p.partrelid
          JOIN pg_namespace n ON n.oid = c.relnamespace
          JOIN pg_attribute a ON a.attrelid = p.partrelid AND a.attnum = p.partattrs[0]
         WHERE n.nspname = 'public' AND p.partstrat = 'r' AND p.partnatts = 1
           AND a.atttypid = 'timestamptz'::regtype) AS tbl(table_name, has_default),
       LATERAL (SELECT date_trunc('month', now() + (s.month_offset || ' months')::interval) AS target_month) AS m;

  -- 9. Consecutive failure escalation — PER-CHECK STREAKS (renumbered from 8;
  -- re-grounded by L2-C4 r3). The block this replaces counted every 'error'
  -- row for outbound_queue_depth inside the window — a windowed total: an
  -- error→ok→error flapping pattern counted BOTH errors and escalated with no
  -- streak, and extending it with a name-list would pool errors across
  -- independent checks. It now counts, per check_name INDEPENDENTLY, that
  -- check's current consecutive-error streak: the run of most-recent samples
  -- that are all 'error'; ANY non-error sample ('ok' or 'warn') resets that
  -- check's streak to zero. Checks never pool counts. The window is a
  -- freshness bound only: samples older than the window count toward nothing,
  -- and a check with no sample inside the window does not escalate (no fresh
  -- evidence). At the 5-minute pg_cron cadence the defaults cohere: 3 checks
  -- ≈ 15 minutes of failure fits inside the 20-minute window.
  --
  -- Both lookups are call-site COALESCE-wrapped: get_hc_config returns NULL
  -- for an absent key, and NULL here silently DISABLES escalation
  -- (make_interval(mins => NULL) filters every row; count >= NULL is NULL, so
  -- the IF never fires). Absent hc_consec_fail_window_min /
  -- alert_min_consecutive therefore engage the defaults 20 minutes / 3 checks
  -- — the same 3 notify_alerts falls back to below.
  v_esc_window_min := COALESCE(get_hc_config('hc_consec_fail_window_min', 20), 20)::INT;
  v_esc_min        := COALESCE(get_hc_config('alert_min_consecutive', 3), 3)::INT;

  FOR v_esc_rec IN
    WITH recent AS (
      SELECT check_name, status, checked_at,
             ROW_NUMBER() OVER (PARTITION BY check_name ORDER BY checked_at DESC, id DESC) AS rn
      FROM health_history
      WHERE checked_at > now() - make_interval(mins => v_esc_window_min)
        AND check_name IN (
          'outbound_queue_depth',
          'security_event_outbox_failed',
          'security_event_outbox_pending_age_minutes')
    ),
    streaks AS (
      -- Current consecutive-error streak per check: an error row counts only
      -- when NO newer in-window sample for the same check is non-error (any
      -- ok/warn resets the streak before it). Independent checks never pool.
      SELECT r.check_name, count(*)::INT AS errors
      FROM recent r
      WHERE r.status = 'error'
        AND NOT EXISTS (
          SELECT 1 FROM recent r2
           WHERE r2.check_name = r.check_name
             AND r2.rn < r.rn
             AND r2.status <> 'error')
      GROUP BY r.check_name
    )
    SELECT check_name, errors FROM streaks WHERE errors >= v_esc_min
  LOOP
    INSERT INTO crash_events (component, severity, description)
    VALUES ('health_check', 'error',
      v_esc_rec.check_name || ' has been in error state for ' ||
      v_esc_rec.errors::TEXT || ' consecutive checks');
  END LOOP;

  -- 10. Dispatch email alerts (renumbered from 9)
  -- Isolate alert dispatch: a send() failure (a quoted-address JSONB cast, a
  -- DLP/quota/validation error, any transient fault) must NOT roll back this
  -- tick's health_history snapshot — that would lose monitoring data precisely
  -- when the system is unhealthy. Log and continue.
  BEGIN
    PERFORM notify_alerts();
  EXCEPTION WHEN OTHERS THEN
    RAISE WARNING 'health_check: notify_alerts failed (snapshot preserved): %', SQLERRM;
  END;

END;
$$ LANGUAGE plpgsql;

-- notify_alerts: send email when health checks fail 3+ times consecutively,
-- and when they recover.
CREATE OR REPLACE FUNCTION notify_alerts() RETURNS VOID AS $$
DECLARE
    v_emails       TEXT;
    v_min_cons     INT;
    v_sender_mb    BIGINT;
    v_sender_uid   BIGINT;
    v_rec          RECORD;
    v_subject      TEXT;
    v_body         TEXT;
    v_duration     TEXT;
BEGIN
    -- Read config
    SELECT (value #>> '{}') INTO v_emails
    FROM system_config WHERE key = 'alert_email_addresses';
    SELECT (value #>> '{}')::INT INTO v_min_cons
    FROM system_config WHERE key = 'alert_min_consecutive';

    v_emails := NULLIF(TRIM(v_emails), '');
    IF v_emails IS NULL THEN RETURN; END IF;
    IF v_min_cons IS NULL THEN v_min_cons := 3; END IF;

    -- Find a sender mailbox (first admin with a primary mailbox)
    SELECT mb.id, mb.user_id INTO v_sender_mb, v_sender_uid
    FROM mailboxes mb
    JOIN users u ON u.id = mb.user_id
    WHERE u.is_local_admin = TRUE AND mb.is_primary = TRUE
    LIMIT 1;

    IF v_sender_mb IS NULL THEN RETURN; END IF;

    -- 1. Alert on checks with 3+ consecutive errors where alert hasn't been sent
    FOR v_rec IN
        WITH recent AS (
            SELECT check_name, status, checked_at,
                ROW_NUMBER() OVER (PARTITION BY check_name ORDER BY checked_at DESC) as rn
            FROM health_history
        ),
        streaks AS (
            SELECT check_name, COUNT(*) as errors, MAX(checked_at) as last_checked
            FROM recent
            WHERE status = 'error' AND rn <= v_min_cons
              AND rn = (SELECT COUNT(*) FROM recent r2
                        WHERE r2.check_name = recent.check_name
                          AND r2.rn <= recent.rn
                          AND r2.status = 'error')
            GROUP BY check_name
        )
        SELECT s.check_name, s.errors, s.last_checked, h.details, h.threshold, h.value
        FROM streaks s
        JOIN health_history h ON h.check_name = s.check_name
            AND h.checked_at = s.last_checked
        LEFT JOIN health_alerts a ON a.check_name = s.check_name
        WHERE s.errors >= v_min_cons
          AND COALESCE(a.alert_sent_at, '1970-01-01'::TIMESTAMPTZ) < h.checked_at
          AND COALESCE(a.suppressed, FALSE) = FALSE
    LOOP
        v_subject := format('[ALERT] mailserver: %s exceeded', v_rec.check_name);
        v_body := format('The %s health check has failed %s consecutive times.%s%s'
            || 'Check: %s%s'
            || 'Current value: %s%s'
            || 'Threshold: %s%s'
            || 'Last checked: %s',
            v_rec.check_name, v_rec.errors::TEXT, E'\n', E'\n',
            v_rec.check_name, E'\n',
            COALESCE(v_rec.value::TEXT, 'N/A'), E'\n',
            COALESCE(v_rec.threshold::TEXT, 'N/A'), E'\n',
            v_rec.last_checked::TEXT
        );

        PERFORM send(v_sender_uid, v_sender_mb,
            'internal://alert-' || v_rec.check_name,
            '<alert-' || v_rec.check_name || '@mailserver>',
            (SELECT email FROM mailboxes WHERE id = v_sender_mb),
            (SELECT jsonb_agg(jsonb_build_object('email', btrim(e)))
             FROM unnest(string_to_array(v_emails, ',')) AS e
             WHERE btrim(e) <> ''),
            '[]'::JSONB, '[]'::JSONB,
            v_subject, '', '',
            v_body, '', length(v_body)::BIGINT, FALSE, NULL
        );

        INSERT INTO health_alerts (check_name, alert_sent_at)
        VALUES (v_rec.check_name, now())
        ON CONFLICT (check_name) DO UPDATE SET alert_sent_at = now();
    END LOOP;

    -- 2. Recovery notification: checks that were error but are now ok
    FOR v_rec IN
        SELECT h.check_name, h.checked_at, a.alert_sent_at
        FROM health_alerts a
        JOIN health_history h ON h.check_name = a.check_name
            AND h.checked_at = (SELECT MAX(checked_at) FROM health_history WHERE check_name = a.check_name)
        WHERE h.status = 'ok'
          AND a.alert_sent_at IS NOT NULL
          AND COALESCE(a.suppressed, FALSE) = FALSE
    LOOP
        v_duration := ceil(EXTRACT(EPOCH FROM (v_rec.checked_at - v_rec.alert_sent_at))/60)::TEXT || ' minutes';

        v_subject := format('[RECOVERED] mailserver: %s back to normal', v_rec.check_name);
        v_body := format('%s is now OK.%s%s'
            || 'Total failure duration: %s%s',
            v_rec.check_name, E'\n', E'\n',
            v_duration, E'\n'
        );

        PERFORM send(v_sender_uid, v_sender_mb,
            'internal://alert-recovery-' || v_rec.check_name,
            '<alert-recovery-' || v_rec.check_name || '@mailserver>',
            (SELECT email FROM mailboxes WHERE id = v_sender_mb),
            (SELECT jsonb_agg(jsonb_build_object('email', btrim(e)))
             FROM unnest(string_to_array(v_emails, ',')) AS e
             WHERE btrim(e) <> ''),
            '[]'::JSONB, '[]'::JSONB,
            v_subject, '', '',
            v_body, '', length(v_body)::BIGINT, FALSE, NULL
        );

        UPDATE health_alerts SET alert_sent_at = NULL WHERE check_name = v_rec.check_name;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- Register pg_cron job for health_check
-- [pg_cron→Go cron worker] SELECT cron.schedule('health-check', '*/5 * * * *', $$ SELECT health_check(); $$);
