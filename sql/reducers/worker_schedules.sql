-- worker_schedules.sql — Wave 2.2 (#549): SKIP LOCKED distributed cron schedule
-- leases with monotonic fencing_token, clock_timestamp() eligibility/expiry,
-- HA schedule_tz drift rejection, and Release N rolling-upgrade advisory-lock probe.
--
-- Security & RLS model:
--   * public.worker_schedules is ENABLE + FORCE ROW LEVEL SECURITY with ZERO
--     permissive policies (deny-all to setjoin_app).
--   * All worker_schedule_* reducers are SECURITY INVOKER SET search_path =
--     pg_catalog, public, checking rolbypassrls OR rolsuper (BZ003), with
--     REVOKE ALL FROM PUBLIC, setjoin_app and GRANT EXECUTE TO setjoin_worker
--     (reasserted in scripts/provision-roles.sql exact_worker).

-- Register or update a periodic schedule row; rejects mismatched schedule_tz across
-- HA nodes so wall-clock cron schedules cannot drift.
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
