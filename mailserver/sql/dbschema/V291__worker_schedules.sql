-- V291__worker_schedules.sql — Wave 2.2 (#549): SKIP LOCKED distributed cron
-- schedule leases (public.worker_schedules), fenced work_release / work_cancel_pending /
-- work_expedite reducers, durable WORM DLQ health check, and guest digest WorkQueue
-- coalescing.
--
-- Isolation posture (V253/V281/V290 pattern):
--   * public.worker_schedules (named outside *_queue|*_jobs) is ENABLE + FORCE
--     ROW LEVEL SECURITY with ZERO permissive policies (deny-all to setjoin_app).
--   * Ownership sits with setjoin_owner; PUBLIC and setjoin_app have zero table
--     privileges; setjoin_worker holds SELECT/INSERT/UPDATE/DELETE (reasserted in
--     scripts/provision-roles.sql).
--   * ZERO public.feature_toggles rows (preserves V275 toggle registry goldens).

CREATE TABLE public.worker_schedules (
    task_name            TEXT PRIMARY KEY
        CHECK (task_name ~ '^[a-z][a-z0-9_-]{0,127}$'),
    schedule_spec        TEXT NOT NULL,
    timeout_secs         INT NOT NULL
        CHECK (timeout_secs BETWEEN 1 AND 600),
    schedule_tz          TEXT NOT NULL DEFAULT 'UTC',
    credential           TEXT NOT NULL DEFAULT 'worker'
        CHECK (credential IN ('worker', 'owner')),
    enabled              BOOLEAN NOT NULL DEFAULT TRUE,
    next_due_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    lease_owner          TEXT,
    lease_expires_at     TIMESTAMPTZ,
    fencing_token        BIGINT NOT NULL DEFAULT 0
        CHECK (fencing_token >= 0),
    last_started_at      TIMESTAMPTZ,
    last_completed_at    TIMESTAMPTZ,
    last_duration_ms     INT,
    last_outcome         TEXT
        CHECK (last_outcome IS NULL OR last_outcome IN ('ok', 'error', 'timeout', 'cancelled')),
    last_error           TEXT
        CHECK (last_error IS NULL OR octet_length(last_error) <= 4096),
    consecutive_failures INT NOT NULL DEFAULT 0,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT worker_schedules_lease_shape CHECK (
        (lease_owner IS NULL) = (lease_expires_at IS NULL)
    )
);

CREATE INDEX worker_schedules_due_idx
    ON public.worker_schedules (next_due_at ASC, task_name ASC)
    WHERE enabled;

CREATE INDEX worker_schedules_leased_expiry_idx
    ON public.worker_schedules (lease_expires_at ASC, task_name ASC)
    WHERE lease_owner IS NOT NULL;

COMMENT ON TABLE public.worker_schedules IS
  'Distributed SKIP LOCKED cron schedule leases (V291, #549) with monotonic '
  'fencing_token, HA schedule_tz drift check, and bounded error storage. '
  'FORCE RLS deny-all to setjoin_app; worker/operator only.';

ALTER TABLE public.worker_schedules ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.worker_schedules FORCE ROW LEVEL SECURITY;

REVOKE ALL ON public.worker_schedules FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_owner') THEN
        ALTER TABLE public.worker_schedules OWNER TO setjoin_owner;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
        REVOKE ALL ON public.worker_schedules FROM setjoin_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
        REVOKE ALL ON public.worker_schedules FROM setjoin_worker;
        GRANT SELECT, INSERT, UPDATE, DELETE ON public.worker_schedules TO setjoin_worker;
    END IF;
END $$;

-- ── Upgrade-safe reducer definitions (canonical sources under mailserver/sql/reducers/)
--    so `upgrade.sh` -> `mailctl schema apply --yes` updates every Wave 2.2 reducer
--    atomically alongside V291 DDL while fresh installs stay byte-identical under
--    scripts/reload-reducers.sh and scripts/check-schema-determinism.sh.

-- [embedded verbatim from reducers/worker_schedules.sql]
CREATE OR REPLACE FUNCTION worker_schedule_register(
    p_name         TEXT,
    p_spec         TEXT,
    p_timeout_secs INT,
    p_tz           TEXT DEFAULT 'UTC',
    p_credential   TEXT DEFAULT 'worker'
) RETURNS public.worker_schedules
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_tz   TEXT := COALESCE(NULLIF(btrim(p_tz), ''), 'UTC');
    v_cred TEXT := COALESCE(NULLIF(btrim(p_credential), ''), 'worker');
    v_row  public.worker_schedules;
BEGIN
    PERFORM public.work_queue_require_worker();

    IF p_name IS NULL OR p_name !~ '^[a-z][a-z0-9_-]{0,127}$' THEN
        RAISE EXCEPTION 'worker_schedule_register: invalid task_name %', p_name
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalid_schedule_name"}';
    END IF;
    IF p_spec IS NULL OR btrim(p_spec) = '' THEN
        RAISE EXCEPTION 'worker_schedule_register: schedule_spec is required'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalid_schedule_spec"}';
    END IF;
    IF p_timeout_secs IS NULL OR p_timeout_secs < 1 OR p_timeout_secs > 600 THEN
        RAISE EXCEPTION 'worker_schedule_register: timeout_secs must be between 1 and 600'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalid_schedule_timeout"}';
    END IF;
    IF v_cred NOT IN ('worker', 'owner') THEN
        RAISE EXCEPTION 'worker_schedule_register: invalid credential %', v_cred
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalid_schedule_credential"}';
    END IF;

    INSERT INTO public.worker_schedules (
        task_name, schedule_spec, timeout_secs, schedule_tz, credential,
        next_due_at, updated_at
    )
    VALUES (
        p_name, btrim(p_spec), p_timeout_secs, v_tz, v_cred,
        clock_timestamp(), clock_timestamp()
    )
    ON CONFLICT (task_name) DO NOTHING
    RETURNING * INTO v_row;

    IF FOUND THEN
        RETURN v_row;
    END IF;

    SELECT * INTO v_row
      FROM public.worker_schedules
     WHERE task_name = p_name
     FOR UPDATE;

    IF v_row.schedule_tz <> v_tz THEN
        RAISE EXCEPTION 'worker_schedule_register: schedule_tz mismatch for % (existing=%, requested=%)',
            p_name, v_row.schedule_tz, v_tz
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"schedule_tz_mismatch"}';
    END IF;

    UPDATE public.worker_schedules
       SET schedule_spec = btrim(p_spec),
           timeout_secs  = p_timeout_secs,
           credential    = v_cred,
           updated_at    = clock_timestamp()
     WHERE task_name = p_name
    RETURNING * INTO v_row;

    RETURN v_row;
END;
$$;

-- Claim up to p_limit due enabled schedules via FOR UPDATE SKIP LOCKED.
-- Uses clock_timestamp() for post-lock eligibility/expiry and probes the legacy
-- Release N per_task advisory lock ('cron-task:' || task_name) so a legacy node
-- holding a session lock never double-runs.
CREATE OR REPLACE FUNCTION worker_schedule_claim(
    p_names      TEXT[],
    p_owner      TEXT,
    p_lease_secs INT DEFAULT 30,
    p_limit      INT DEFAULT 4
) RETURNS SETOF public.worker_schedules
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_lease   INTERVAL := make_interval(secs => GREATEST(COALESCE(p_lease_secs, 30), 1));
    v_limit   INT := GREATEST(COALESCE(p_limit, 4), 1);
    v_claimed INT := 0;
    v_row     public.worker_schedules;
BEGIN
    PERFORM public.work_queue_require_worker();

    IF p_owner IS NULL OR btrim(p_owner) = '' THEN
        RAISE EXCEPTION 'worker_schedule_claim: owner is required'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalid_schedule_owner"}';
    END IF;

    IF p_names IS NULL OR cardinality(p_names) = 0 THEN
        RETURN;
    END IF;

    FOR v_row IN
        SELECT *
          FROM public.worker_schedules cand
         WHERE cand.enabled
           AND cand.task_name = ANY(p_names)
           AND cand.next_due_at <= clock_timestamp()
           AND (cand.lease_expires_at IS NULL OR cand.lease_expires_at <= clock_timestamp())
         ORDER BY cand.next_due_at ASC, cand.task_name ASC
         FOR UPDATE SKIP LOCKED
    LOOP
        EXIT WHEN v_claimed >= v_limit;

        IF v_row.next_due_at > clock_timestamp()
           OR (v_row.lease_expires_at IS NOT NULL AND v_row.lease_expires_at > clock_timestamp()) THEN
            CONTINUE;
        END IF;

        -- Rolling-upgrade compatibility: never claim a task whose legacy per_task
        -- session advisory lock is still held by an unstopped Release N-1 node.
        IF NOT pg_catalog.pg_try_advisory_xact_lock(
            pg_catalog.hashtextextended('cron-task:' || v_row.task_name, 0)
        ) THEN
            CONTINUE;
        END IF;

        UPDATE public.worker_schedules ws
           SET fencing_token    = ws.fencing_token + 1,
               lease_owner      = p_owner,
               lease_expires_at = clock_timestamp() + v_lease,
               last_started_at  = clock_timestamp(),
               updated_at       = clock_timestamp()
         WHERE ws.task_name = v_row.task_name
        RETURNING ws.* INTO v_row;

        v_claimed := v_claimed + 1;
        RETURN NEXT v_row;
    END LOOP;
END;
$$;

-- Fenced lease extension: succeeds ONLY while (task_name, fencing_token, lease_owner)
-- match AND lease_expires_at > clock_timestamp(). Returning FALSE cancels local work.
CREATE OR REPLACE FUNCTION worker_schedule_heartbeat(
    p_name       TEXT,
    p_token      BIGINT,
    p_owner      TEXT,
    p_lease_secs INT DEFAULT 30
) RETURNS BOOLEAN
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_lease INTERVAL := make_interval(secs => GREATEST(COALESCE(p_lease_secs, 30), 1));
BEGIN
    PERFORM public.work_queue_require_worker();

    UPDATE public.worker_schedules
       SET lease_expires_at = clock_timestamp() + v_lease,
           updated_at       = clock_timestamp()
     WHERE task_name = p_name
       AND fencing_token = p_token
       AND lease_owner = p_owner
       AND lease_expires_at > clock_timestamp();

    RETURN FOUND;
END;
$$;

-- Fenced completion: clears lease, records bounded error via work_truncate_utf8,
-- and coalesces missed slots via GREATEST(p_next_due_at, clock_timestamp()).
CREATE OR REPLACE FUNCTION worker_schedule_complete(
    p_name        TEXT,
    p_token       BIGINT,
    p_owner       TEXT,
    p_outcome     TEXT,
    p_duration_ms INT,
    p_error       TEXT,
    p_next_due_at TIMESTAMPTZ
) RETURNS BOOLEAN
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_err TEXT;
BEGIN
    PERFORM public.work_queue_require_worker();

    IF p_outcome IS NULL OR p_outcome NOT IN ('ok', 'error', 'timeout', 'cancelled') THEN
        RAISE EXCEPTION 'worker_schedule_complete: invalid outcome %', p_outcome
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalid_schedule_outcome"}';
    END IF;

    v_err := CASE
        WHEN p_error IS NULL OR p_error = '' THEN NULL
        ELSE public.work_truncate_utf8(p_error, 4096)
    END;

    UPDATE public.worker_schedules
       SET lease_owner          = NULL,
           lease_expires_at     = NULL,
           last_completed_at    = clock_timestamp(),
           last_duration_ms     = p_duration_ms,
           last_outcome         = p_outcome,
           last_error           = v_err,
           consecutive_failures = CASE WHEN p_outcome = 'ok' THEN 0 ELSE consecutive_failures + 1 END,
           next_due_at          = GREATEST(COALESCE(p_next_due_at, clock_timestamp()), clock_timestamp()),
           updated_at           = clock_timestamp()
     WHERE task_name = p_name
       AND fencing_token = p_token
       AND lease_owner = p_owner;

    RETURN FOUND;
END;
$$;

-- Fenced graceful shutdown handoff: clears lease and pulls next_due_at to
-- LEAST(next_due_at, clock_timestamp()) for <1s peer pickup.
CREATE OR REPLACE FUNCTION worker_schedule_release(
    p_name  TEXT,
    p_token BIGINT,
    p_owner TEXT
) RETURNS BOOLEAN
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    PERFORM public.work_queue_require_worker();

    UPDATE public.worker_schedules
       SET lease_owner      = NULL,
           lease_expires_at = NULL,
           next_due_at      = LEAST(next_due_at, clock_timestamp()),
           updated_at       = clock_timestamp()
     WHERE task_name = p_name
       AND fencing_token = p_token
       AND lease_owner = p_owner;

    RETURN FOUND;
END;
$$;

-- Strictly worker-only ACLs (also restated in scripts/provision-roles.sql exact_worker).
DO $$
DECLARE
    v_sig TEXT;
BEGIN
    FOREACH v_sig IN ARRAY ARRAY[
        'public.worker_schedule_register(text,text,integer,text,text)',
        'public.worker_schedule_claim(text[],text,integer,integer)',
        'public.worker_schedule_heartbeat(text,bigint,text,integer)',
        'public.worker_schedule_complete(text,bigint,text,text,integer,text,timestamptz)',
        'public.worker_schedule_release(text,bigint,text)'
    ] LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', v_sig);
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
            EXECUTE format('REVOKE ALL ON FUNCTION %s FROM setjoin_app', v_sig);
        END IF;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
            EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO setjoin_worker', v_sig);
        END IF;
    END LOOP;
END $$;

-- [embedded verbatim from reducers/work_queue.sql]
CREATE OR REPLACE FUNCTION work_release(
    p_id         BIGINT,
    p_generation INT,
    p_worker_id  TEXT
) RETURNS BOOLEAN
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_kind TEXT;
BEGIN
    PERFORM public.work_queue_require_worker();

    UPDATE public.work_items
       SET status           = 'pending',
           lease_expires_at = NULL,
           locked_by        = NULL,
           run_at           = LEAST(run_at, clock_timestamp()),
           attempts         = GREATEST(attempts - 1, 0),
           updated_at       = clock_timestamp()
     WHERE id = p_id
       AND status = 'leased'
       AND claim_generation = p_generation
       AND locked_by = p_worker_id
       AND lease_expires_at > clock_timestamp()
    RETURNING kind INTO v_kind;

    IF FOUND THEN
        PERFORM public.emit_wakeup_bell('work', v_kind);
        RETURN TRUE;
    END IF;
    RETURN FALSE;
END;
$$;

CREATE OR REPLACE FUNCTION work_cancel_pending(
    p_id BIGINT
) RETURNS BOOLEAN
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    PERFORM public.work_queue_require_worker();

    DELETE FROM public.work_items
     WHERE id = p_id
       AND status = 'pending';

    RETURN FOUND;
END;
$$;

CREATE OR REPLACE FUNCTION work_expedite(
    p_id BIGINT
) RETURNS BOOLEAN
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_kind TEXT;
BEGIN
    PERFORM public.work_queue_require_worker();

    UPDATE public.work_items
       SET run_at     = LEAST(run_at, clock_timestamp()),
           updated_at = clock_timestamp()
     WHERE id = p_id
       AND status = 'pending'
    RETURNING kind INTO v_kind;

    IF FOUND THEN
        PERFORM public.emit_wakeup_bell('work', v_kind);
        RETURN TRUE;
    END IF;
    RETURN FALSE;
END;
$$;

REVOKE ALL ON FUNCTION public.work_release(BIGINT, INT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.work_cancel_pending(BIGINT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.work_expedite(BIGINT) FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
        REVOKE ALL ON FUNCTION public.work_release(BIGINT, INT, TEXT) FROM setjoin_app;
        REVOKE ALL ON FUNCTION public.work_cancel_pending(BIGINT) FROM setjoin_app;
        REVOKE ALL ON FUNCTION public.work_expedite(BIGINT) FROM setjoin_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
        GRANT EXECUTE ON FUNCTION public.work_release(BIGINT, INT, TEXT) TO setjoin_worker;
        GRANT EXECUTE ON FUNCTION public.work_cancel_pending(BIGINT) TO setjoin_worker;
        GRANT EXECUTE ON FUNCTION public.work_expedite(BIGINT) TO setjoin_worker;
    END IF;
END $$;

-- [embedded verbatim from reducers/guest_notification_intent.sql]
CREATE OR REPLACE FUNCTION guest_notification_intent_enqueue(
    p_user_id bigint,
    p_kind    text,
    p_ref     text
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    IF NOT COALESCE((SELECT enabled FROM feature_toggles
                      WHERE key = 'feature.guest_accounts'), false)
       OR NOT is_guest_account(p_user_id) THEN
        RETURN;
    END IF;
    -- Serialize per-guest intent insert + WorkQueue coalescing against the
    -- consumer's post-drain check/complete transaction so a coalesced wakeup
    -- can never be lost between drain and complete (#549).
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended('guest-digest:' || p_user_id::text, 0)
    );
    INSERT INTO guest_notification_intents (user_id, kind, ref)
    VALUES (p_user_id, p_kind, p_ref);
    -- Wave 2.2 (#549): coalesce per-guest digest wakeup onto durable WorkQueue
    -- while keeping guest_notification_intents populated during drain-then-retire.
    PERFORM public.work_enqueue(
        'guest.digest_notify',
        jsonb_build_object('user_id', p_user_id),
        'guest.digest:' || p_user_id::text,
        now(),
        0::smallint,
        5
    );
END;
$$;

-- [embedded verbatim from reducers/health_check.sql]
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
  v_wq_dlq           BIGINT;
  v_worm_dlq         BIGINT;
  v_wq_due_age_m     NUMERIC;
  v_notify_backlog   BIGINT;
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

  -- 3d. Scheduled-actions queue depth (pending or enqueued awaiting execution)
  SELECT COUNT(*) INTO v_sched_depth
  FROM scheduled_actions WHERE status IN ('pending', 'enqueued');

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

  -- 3h. Durable WorkQueue dead-letter count (Wave 2.1, #548)
  SELECT COUNT(*) INTO v_wq_dlq
  FROM work_dead_letters WHERE replayed_at IS NULL;

  INSERT INTO health_history (check_name, status, value, threshold, details) VALUES (
    'work_queue_dead_letters',
    CASE WHEN v_wq_dlq > COALESCE(get_hc_config('hc_work_queue_dlq_error', 0), 0) THEN 'error'
         ELSE 'ok' END,
    v_wq_dlq,
    COALESCE(get_hc_config('hc_work_queue_dlq_error', 0), 0),
    'Un-replayed dead-lettered work items (inspect/replay via mailctl work dlq)'
  );

  -- 3h2. Durable S3 WORM arming dead-letter count (Wave 2.2, #549)
  SELECT COUNT(*) INTO v_worm_dlq
  FROM work_dead_letters WHERE kind = 'blob.worm_arm' AND replayed_at IS NULL;

  INSERT INTO health_history (check_name, status, value, threshold, details) VALUES (
    'worm_arm_dead_letters',
    CASE WHEN v_worm_dlq > COALESCE(get_hc_config('hc_worm_arm_dlq_error', 0), 0) THEN 'error'
         ELSE 'ok' END,
    v_worm_dlq,
    COALESCE(get_hc_config('hc_worm_arm_dlq_error', 0), 0),
    'Un-replayed dead-lettered S3 WORM retention arming jobs (inspect/replay via mailctl work dlq --kind blob.worm_arm)'
  );

  -- 3i. Durable WorkQueue oldest due item age in minutes (Wave 2.1, #548)
  SELECT COALESCE(EXTRACT(EPOCH FROM (now() - MIN(run_at)))/60, 0)
  INTO v_wq_due_age_m
  FROM work_items
  WHERE status = 'pending' AND run_at <= now();

  INSERT INTO health_history (check_name, status, value, threshold, details) VALUES (
    'work_queue_due_age_minutes',
    CASE WHEN v_wq_due_age_m > COALESCE(get_hc_config('hc_work_queue_due_age_error_min', 60), 60) THEN 'error'
         WHEN v_wq_due_age_m > COALESCE(get_hc_config('hc_work_queue_due_age_warn_min',  15), 15) THEN 'warn'
         ELSE 'ok' END,
    v_wq_due_age_m,
    COALESCE(get_hc_config('hc_work_queue_due_age_error_min', 60), 60),
    'Age in minutes of the oldest due pending work item'
  );

  -- 3j. notify_intents backlog depth (Wave 2.1, #548)
  SELECT COUNT(*) INTO v_notify_backlog
  FROM notify_intents;

  INSERT INTO health_history (check_name, status, value, threshold, details) VALUES (
    'notify_intents_backlog',
    CASE WHEN v_notify_backlog > COALESCE(get_hc_config('hc_notify_intents_backlog_error', 50000), 50000) THEN 'error'
         WHEN v_notify_backlog > COALESCE(get_hc_config('hc_notify_intents_backlog_warn',  5000), 5000) THEN 'warn'
         ELSE 'ok' END,
    v_notify_backlog,
    COALESCE(get_hc_config('hc_notify_intents_backlog_error', 50000), 50000),
    'Undrained notify_intents wakeup/notification rows awaiting NotifyIntentDrain'
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
          'security_event_outbox_pending_age_minutes',
          'work_queue_dead_letters',
          'worm_arm_dead_letters')
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

INSERT INTO public.schema_migrations (version, applied_at)
VALUES (291, now())
ON CONFLICT (version) DO NOTHING;
