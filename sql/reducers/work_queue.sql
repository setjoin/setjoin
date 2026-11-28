-- work_queue.sql — Wave 2.1 (#548): durable WorkQueue (FOR UPDATE SKIP LOCKED),
-- DLQ inspection/replay/purge, content-free wakeup bells, and scheduled_actions
-- handoff reducers.
--
-- Security & RLS model:
--   * work_items and work_dead_letters are ENABLE+FORCE RLS with zero policies
--     (deny-all to setjoin_app).
--   * All worker/operator reducers are SECURITY INVOKER SET search_path = pg_catalog, public,
--     explicitly checking rolbypassrls OR rolsuper (raising BZ003 otherwise), with
--     REVOKE ALL FROM PUBLIC, setjoin_app and GRANT EXECUTE TO setjoin_worker
--     (reasserted in scripts/provision-roles.sql exact_worker carve-out).
--   * work_enqueue_app(...) and work_queue_stats() are narrow SECURITY DEFINER
--     seams owned by setjoin_worker with SET search_path = pg_catalog, public and
--     REVOKE ALL FROM PUBLIC (never PUBLIC EXECUTE).

-- UTF-8 byte-safe truncation helper: returns the longest character-boundary
-- prefix of p_text whose UTF-8 octet_length <= p_max_bytes.
CREATE OR REPLACE FUNCTION work_truncate_utf8(
    p_text      TEXT,
    p_max_bytes INT DEFAULT 4096
) RETURNS TEXT
LANGUAGE plpgsql IMMUTABLE STRICT SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_lo  INT := 0;
    v_hi  INT;
    v_mid INT;
BEGIN
    IF p_max_bytes <= 0 THEN
        RETURN '';
    END IF;
    IF octet_length(p_text) <= p_max_bytes THEN
        RETURN p_text;
    END IF;
    v_hi := LEAST(char_length(p_text), p_max_bytes);
    WHILE v_lo < v_hi LOOP
        v_mid := (v_lo + v_hi + 1) / 2;
        IF octet_length(left(p_text, v_mid)) <= p_max_bytes THEN
            v_lo := v_mid;
        ELSE
            v_hi := v_mid - 1;
        END IF;
    END LOOP;
    RETURN left(p_text, v_lo);
END;
$$;

-- Guard helper for SECURITY INVOKER worker reducers: requires BYPASSRLS or superuser.
CREATE OR REPLACE FUNCTION work_queue_require_worker()
RETURNS VOID
LANGUAGE plpgsql STABLE SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_roles
         WHERE rolname = current_user
           AND (rolbypassrls OR rolsuper)
    ) THEN
        RAISE EXCEPTION 'work_queue: worker privilege (BYPASSRLS or superuser) required'
            USING ERRCODE = 'BZ003',
                  HINT = '{"type":"worker_privilege_required"}';
    END IF;
END;
$$;

-- Content-free batched wakeup bell: unconditionally writes (p_bus, p_hint) into
-- public.notify_intents (and mirrors _test_notify_log under app.capture_notify='on').
-- Zero feature.notify_decouple lookup and zero direct pg_notify on user write commits.
CREATE OR REPLACE FUNCTION emit_wakeup_bell(
    p_bus  TEXT,
    p_hint TEXT DEFAULT ''
) RETURNS VOID
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_hint TEXT := COALESCE(p_hint, '');
BEGIN
    IF p_bus IS NULL OR p_bus NOT IN ('sync', 'work') THEN
        RAISE EXCEPTION 'emit_wakeup_bell: invalid bus % (must be sync or work)', p_bus
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalid_wakeup_bus"}';
    END IF;
    IF octet_length(v_hint) > 128
       OR (v_hint <> '' AND v_hint !~ '^[a-zA-Z0-9_.:/-]{1,128}$') THEN
        RAISE EXCEPTION 'emit_wakeup_bell: hint must be an empty string or content-free token <= 128 bytes'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalid_wakeup_hint"}';
    END IF;

    IF COALESCE(current_setting('app.capture_notify', TRUE), '') = 'on' THEN
        INSERT INTO public._test_notify_log (channel, payload, seq)
        VALUES (p_bus, v_hint, nextval('public._test_notify_log_seq'));
    END IF;

    PERFORM public.app_notify_enqueue_intent(p_bus, v_hint);
END;
$$;

-- Worker-only enqueue with optional per-kind idempotency_key coalescing.
CREATE OR REPLACE FUNCTION work_enqueue(
    p_kind            TEXT,
    p_payload         JSONB DEFAULT '{}'::jsonb,
    p_idempotency_key TEXT DEFAULT NULL,
    p_run_at          TIMESTAMPTZ DEFAULT now(),
    p_priority        SMALLINT DEFAULT 0,
    p_max_attempts    INT DEFAULT 5
) RETURNS TABLE(work_item_id BIGINT, coalesced BOOLEAN)
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_payload      JSONB := COALESCE(p_payload, '{}'::jsonb);
    v_run_at       TIMESTAMPTZ := COALESCE(p_run_at, now());
    v_priority     SMALLINT := COALESCE(p_priority, 0);
    v_max_attempts INT := COALESCE(p_max_attempts, 5);
    v_id           BIGINT;
    v_attempt      INT := 0;
BEGIN
    PERFORM public.work_queue_require_worker();

    IF p_kind IS NULL OR p_kind !~ '^[a-z][a-z0-9_.:-]{0,127}$' THEN
        RAISE EXCEPTION 'work_enqueue: invalid kind %', p_kind
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalid_work_kind"}';
    END IF;
    IF jsonb_typeof(v_payload) <> 'object' OR octet_length(v_payload::text) > 65536 THEN
        RAISE EXCEPTION 'work_enqueue: payload must be a JSON object <= 65536 bytes'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalid_work_payload"}';
    END IF;
    IF v_max_attempts < 1 OR v_max_attempts > 100 THEN
        RAISE EXCEPTION 'work_enqueue: max_attempts must be between 1 and 100'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalid_work_max_attempts"}';
    END IF;

    IF p_idempotency_key IS NULL THEN
        INSERT INTO public.work_items (
            kind, payload, idempotency_key, priority, run_at, max_attempts
        )
        VALUES (
            p_kind, v_payload, NULL, v_priority, v_run_at, v_max_attempts
        )
        RETURNING id INTO v_id;

        IF v_run_at <= now() THEN
            PERFORM public.emit_wakeup_bell('work', p_kind);
        END IF;

        RETURN QUERY SELECT v_id, FALSE;
        RETURN;
    END IF;

    LOOP
        v_attempt := v_attempt + 1;
        INSERT INTO public.work_items (
            kind, payload, idempotency_key, priority, run_at, max_attempts
        )
        VALUES (
            p_kind, v_payload, p_idempotency_key, v_priority, v_run_at, v_max_attempts
        )
        ON CONFLICT (kind, idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING
        RETURNING id INTO v_id;

        IF v_id IS NOT NULL THEN
            IF v_run_at <= now() THEN
                PERFORM public.emit_wakeup_bell('work', p_kind);
            END IF;
            RETURN QUERY SELECT v_id, FALSE;
            RETURN;
        END IF;

        SELECT wi.id INTO v_id
          FROM public.work_items wi
         WHERE wi.kind = p_kind
           AND wi.idempotency_key = p_idempotency_key;

        IF v_id IS NOT NULL THEN
            RETURN QUERY SELECT v_id, TRUE;
            RETURN;
        END IF;

        IF v_attempt >= 3 THEN
            RAISE EXCEPTION 'work_enqueue: concurrent idempotency race for kind %', p_kind
                USING ERRCODE = 'BZ040',
                      HINT = '{"type":"work_enqueue_race"}';
        END IF;
    END LOOP;
END;
$$;

-- Narrow domain-safe app enqueue seam (SECURITY DEFINER, owned by setjoin_worker).
-- Enforces:
--   * explicit SQL allowlist of non-privileged app kinds (NEVER scheduled_action.* / admin.* / system.*),
--   * R2 actor stamping from app.current_user_id / app.current_mailbox_id (refuses if both empty),
--   * tenant-prefixed idempotency_key ('app:' || actor_scope || ':'),
--   * clamped priority = 0, max_attempts = 5, run_at in [now(), now() + 24h].
CREATE OR REPLACE FUNCTION work_enqueue_app(
    p_kind            TEXT,
    p_payload         JSONB DEFAULT '{}'::jsonb,
    p_idempotency_key TEXT DEFAULT NULL,
    p_run_at          TIMESTAMPTZ DEFAULT now()
) RETURNS TABLE(work_item_id BIGINT, coalesced BOOLEAN)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_user_id    TEXT := NULLIF(current_setting('app.current_user_id', TRUE), '');
    v_mailbox_id TEXT := NULLIF(current_setting('app.current_mailbox_id', TRUE), '');
    v_scope      TEXT;
    v_payload    JSONB;
    v_idem       TEXT;
    v_run_at     TIMESTAMPTZ;
BEGIN
    IF p_kind IS NULL OR p_kind NOT IN (
        'app.domain_event',
        'mail.index_refresh',
        'calendar.sync_hint',
        'drive.preview_hint',
        'chat.unfurl_hint'
    ) THEN
        RAISE EXCEPTION 'work_enqueue_app: kind % is not allowlisted for app enqueue', p_kind
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"work_kind_not_allowed"}';
    END IF;

    IF v_user_id IS NULL AND v_mailbox_id IS NULL THEN
        RAISE EXCEPTION 'work_enqueue_app: authenticated actor context required'
            USING ERRCODE = 'BZ003',
                  HINT = '{"type":"missing_actor_context"}';
    END IF;

    v_payload := COALESCE(p_payload, '{}'::jsonb);
    IF jsonb_typeof(v_payload) <> 'object' THEN
        RAISE EXCEPTION 'work_enqueue_app: payload must be a JSON object'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalid_work_payload"}';
    END IF;

    -- Stamp R2 actor identity from session GUCs, overwriting any caller-supplied fields.
    IF v_user_id IS NOT NULL THEN
        v_payload := jsonb_set(v_payload, '{actor_user_id}', to_jsonb(v_user_id), TRUE);
    ELSE
        v_payload := v_payload - 'actor_user_id';
    END IF;
    IF v_mailbox_id IS NOT NULL THEN
        v_payload := jsonb_set(v_payload, '{actor_mailbox_id}', to_jsonb(v_mailbox_id), TRUE);
    ELSE
        v_payload := v_payload - 'actor_mailbox_id';
    END IF;

    IF octet_length(v_payload::text) > 65536 THEN
        RAISE EXCEPTION 'work_enqueue_app: payload exceeds 65536 bytes'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalid_work_payload"}';
    END IF;

    v_scope := CASE
        WHEN v_mailbox_id IS NOT NULL AND v_user_id IS NOT NULL THEN 'usr:' || v_user_id || ':mbx:' || v_mailbox_id
        WHEN v_mailbox_id IS NOT NULL THEN 'mbx:' || v_mailbox_id
        ELSE 'usr:' || v_user_id
    END;

    v_idem := CASE
        WHEN p_idempotency_key IS NOT NULL AND p_idempotency_key <> ''
            THEN 'app:' || v_scope || ':' || p_idempotency_key
        ELSE NULL
    END;

    v_run_at := LEAST(GREATEST(COALESCE(p_run_at, now()), now()), now() + interval '24 hours');

    RETURN QUERY
    SELECT r.work_item_id, r.coalesced
      FROM public.work_enqueue(p_kind, v_payload, v_idem, v_run_at, 0::SMALLINT, 5) AS r;
END;
$$;

-- Scalar queue depth & due-age stats (SECURITY DEFINER owned by setjoin_worker;
-- exposes zero payload or tenant data).
CREATE OR REPLACE FUNCTION work_queue_stats()
RETURNS TABLE(
    pending             BIGINT,
    leased              BIGINT,
    dead_letters        BIGINT,
    oldest_due_age_secs DOUBLE PRECISION
)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    RETURN QUERY
    SELECT
        (SELECT count(*)::BIGINT FROM public.work_items WHERE status = 'pending'),
        (SELECT count(*)::BIGINT FROM public.work_items WHERE status = 'leased'),
        (SELECT count(*)::BIGINT FROM public.work_dead_letters WHERE replayed_at IS NULL),
        COALESCE(
            (SELECT EXTRACT(EPOCH FROM (now() - MIN(run_at)))::DOUBLE PRECISION
               FROM public.work_items
              WHERE status = 'pending' AND run_at <= now()),
            0.0::DOUBLE PRECISION
        );
END;
$$;

-- Worker claim with FOR UPDATE SKIP LOCKED, monotonic claim_generation fencing,
-- and optional per-kind max_concurrency enforced via ordered 64-bit advisory locks.
CREATE OR REPLACE FUNCTION work_queue_claim(
    p_worker_id       TEXT,
    p_kinds           TEXT[] DEFAULT NULL,
    p_batch           INT DEFAULT 10,
    p_lease_secs      INT DEFAULT 60,
    p_max_concurrency INT DEFAULT NULL
) RETURNS SETOF public.work_items
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_batch      INT := GREATEST(COALESCE(p_batch, 10), 1);
    v_lease      INTERVAL := make_interval(secs => GREATEST(COALESCE(p_lease_secs, 60), 1));
    v_remaining  INT := v_batch;
    v_kind       TEXT;
    v_active     INT;
    v_headroom   INT;
    v_take       INT;
    v_claimed    INT;
    v_row        public.work_items;
BEGIN
    PERFORM public.work_queue_require_worker();

    IF p_worker_id IS NULL OR btrim(p_worker_id) = '' THEN
        RAISE EXCEPTION 'work_queue_claim: worker_id is required'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalid_worker_id"}';
    END IF;

    IF p_max_concurrency IS NULL THEN
        RETURN QUERY
        UPDATE public.work_items wi
           SET status           = 'leased',
               locked_by        = p_worker_id,
               lease_expires_at = now() + v_lease,
               attempts         = wi.attempts + 1,
               claim_generation = wi.claim_generation + 1,
               updated_at       = now()
         WHERE wi.id IN (
             SELECT cand.id
               FROM public.work_items cand
              WHERE cand.status = 'pending'
                AND cand.run_at <= now()
                AND (p_kinds IS NULL OR cand.kind = ANY(p_kinds))
              ORDER BY cand.priority DESC, cand.run_at ASC, cand.id ASC
              FOR UPDATE SKIP LOCKED
              LIMIT v_batch
         )
        RETURNING wi.*;
        RETURN;
    END IF;

    IF p_kinds IS NULL OR cardinality(p_kinds) = 0 THEN
        RAISE EXCEPTION 'work_queue_claim: p_kinds must be non-empty when p_max_concurrency is specified'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalid_claim_spec"}';
    END IF;

    -- Capped claim: acquire 64-bit collision-free advisory locks in strict
    -- ascending C-collation (bytewise) order to prevent lock-order deadlocks
    -- across locales and match Rust's bytewise sort in claim_with_caps.
    FOR v_kind IN
        SELECT d.k
          FROM (SELECT DISTINCT k FROM unnest(p_kinds) AS k) d
         ORDER BY d.k COLLATE "C" ASC
    LOOP
        PERFORM pg_catalog.pg_advisory_xact_lock(
            pg_catalog.hashtextextended('workqueue:cap:' || v_kind, 0)
        );
    END LOOP;

    FOR v_kind IN
        SELECT d.k
          FROM (SELECT DISTINCT k FROM unnest(p_kinds) AS k) d
         ORDER BY d.k COLLATE "C" ASC
    LOOP
        EXIT WHEN v_remaining <= 0;

        SELECT count(*)::INT INTO v_active
          FROM public.work_items wi
         WHERE wi.kind = v_kind
           AND wi.status = 'leased'
           AND wi.lease_expires_at > clock_timestamp();

        v_headroom := GREATEST(p_max_concurrency - COALESCE(v_active, 0), 0);
        IF v_headroom <= 0 THEN
            CONTINUE;
        END IF;

        v_take := LEAST(v_headroom, v_remaining);
        v_claimed := 0;

        FOR v_row IN
            UPDATE public.work_items wi
               SET status           = 'leased',
                   locked_by        = p_worker_id,
                   lease_expires_at = clock_timestamp() + v_lease,
                   attempts         = wi.attempts + 1,
                   claim_generation = wi.claim_generation + 1,
                   updated_at       = clock_timestamp()
             WHERE wi.id IN (
                 SELECT cand.id
                   FROM public.work_items cand
                  WHERE cand.kind = v_kind
                    AND cand.status = 'pending'
                    AND cand.run_at <= clock_timestamp()
                  ORDER BY cand.priority DESC, cand.run_at ASC, cand.id ASC
                  FOR UPDATE SKIP LOCKED
                  LIMIT v_take
             )
            RETURNING wi.*
        LOOP
            v_claimed := v_claimed + 1;
            RETURN NEXT v_row;
        END LOOP;

        v_remaining := v_remaining - v_claimed;
    END LOOP;
END;
$$;

-- Lease-valid heartbeat: extends lease ONLY while lease_expires_at > now() and
-- (id, claim_generation, locked_by) match. Returns FALSE if lease lapsed or fenced.
CREATE OR REPLACE FUNCTION work_queue_heartbeat(
    p_id               BIGINT,
    p_claim_generation INT,
    p_worker_id        TEXT,
    p_lease_secs       INT DEFAULT 60
) RETURNS BOOLEAN
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_kind TEXT;
BEGIN
    PERFORM public.work_queue_require_worker();

    SELECT kind INTO v_kind
      FROM public.work_items
     WHERE id = p_id;

    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    -- Serialize with capped work_queue_claim on the same kind so a racing
    -- heartbeat cannot extend an about-to-expire lease after a concurrent claim
    -- already counted it as expired and granted headroom.
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended('workqueue:cap:' || v_kind, 0)
    );

    UPDATE public.work_items
       SET lease_expires_at = clock_timestamp() + make_interval(secs => GREATEST(COALESCE(p_lease_secs, 60), 1)),
           updated_at       = clock_timestamp()
     WHERE id = p_id
       AND status = 'leased'
       AND claim_generation = p_claim_generation
       AND locked_by = p_worker_id
       AND lease_expires_at > clock_timestamp();

    RETURN FOUND;
END;
$$;

-- Fenced completion: deletes the leased row only if (id, claim_generation, locked_by) match.
CREATE OR REPLACE FUNCTION work_queue_complete(
    p_id               BIGINT,
    p_claim_generation INT,
    p_worker_id        TEXT
) RETURNS BOOLEAN
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    PERFORM public.work_queue_require_worker();

    DELETE FROM public.work_items
     WHERE id = p_id
       AND status = 'leased'
       AND claim_generation = p_claim_generation
       AND locked_by = p_worker_id;

    RETURN FOUND;
END;
$$;

-- Fenced graceful lease release on SIGTERM/shutdown for safe-to-retry items:
-- resets status to 'pending', decrements attempts = GREATEST(attempts - 1, 0)
-- so routine deploys never exhaust max_attempts into DLQ, and emits a 'work' bell.
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

-- Cancel a deferred pending work item (e.g. inline WORM retention succeeded
-- before the deferred durable-first item became due).
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

-- Expedite a deferred pending work item to run immediately and ring the 'work' bell
-- (e.g. inline WORM retention failed after promote).
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

-- Fenced failure settlement: retries with backoff or moves to work_dead_letters
-- when permanent or attempts >= max_attempts. Truncates last_error <= 4096 UTF-8 bytes.
CREATE OR REPLACE FUNCTION work_queue_fail(
    p_id               BIGINT,
    p_claim_generation INT,
    p_worker_id        TEXT,
    p_error            TEXT,
    p_retry_after_secs DOUBLE PRECISION DEFAULT NULL,
    p_permanent        BOOLEAN DEFAULT FALSE
) RETURNS TABLE(outcome TEXT, dead_letter_id BIGINT)
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_row    public.work_items;
    v_err    TEXT;
    v_delay  DOUBLE PRECISION;
    v_dlq_id BIGINT;
BEGIN
    PERFORM public.work_queue_require_worker();

    SELECT * INTO v_row
      FROM public.work_items
     WHERE id = p_id
       AND status = 'leased'
       AND claim_generation = p_claim_generation
       AND locked_by = p_worker_id
     FOR UPDATE;

    IF NOT FOUND THEN
        RETURN QUERY SELECT 'lease_lost'::TEXT, NULL::BIGINT;
        RETURN;
    END IF;

    v_err := public.work_truncate_utf8(COALESCE(NULLIF(p_error, ''), 'unknown error'), 4096);

    IF COALESCE(p_permanent, FALSE) OR v_row.attempts >= v_row.max_attempts THEN
        INSERT INTO public.work_dead_letters (
            work_item_id, kind, payload, idempotency_key, priority,
            attempts, max_attempts, last_error, failed_by, enqueued_at
        )
        VALUES (
            v_row.id, v_row.kind, v_row.payload, v_row.idempotency_key, v_row.priority,
            v_row.attempts, v_row.max_attempts, v_err, p_worker_id, v_row.created_at
        )
        RETURNING id INTO v_dlq_id;

        DELETE FROM public.work_items WHERE id = v_row.id;
        RETURN QUERY SELECT 'dead_lettered'::TEXT, v_dlq_id;
        RETURN;
    END IF;

    v_delay := GREATEST(
        COALESCE(
            p_retry_after_secs,
            LEAST(30.0 * power(2.0, GREATEST(v_row.attempts - 1, 0)), 3600.0)
        ),
        0.0
    );

    UPDATE public.work_items
       SET status           = 'pending',
           run_at           = now() + make_interval(secs => v_delay),
           lease_expires_at = NULL,
           locked_by        = NULL,
           last_error       = v_err,
           updated_at       = now()
     WHERE id = v_row.id;

    RETURN QUERY SELECT 'retried'::TEXT, NULL::BIGINT;
END;
$$;

-- Reclaim expired leases: poison-pill items with attempts >= max_attempts move
-- atomically to work_dead_letters; remaining expired leases return to pending.
CREATE OR REPLACE FUNCTION work_queue_reclaim_expired(
    p_batch INT DEFAULT 100
) RETURNS TABLE(reclaimed INT, dead_lettered INT)
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_batch        INT := GREATEST(COALESCE(p_batch, 100), 1);
    v_reclaimed    INT := 0;
    v_dead         INT := 0;
    v_row          public.work_items;
    v_err          TEXT;
    v_action_id    UUID;
BEGIN
    PERFORM public.work_queue_require_worker();

    FOR v_row IN
        SELECT *
          FROM public.work_items
         WHERE status = 'leased'
           AND lease_expires_at <= now()
         ORDER BY lease_expires_at ASC, id ASC
         FOR UPDATE SKIP LOCKED
         LIMIT v_batch
    LOOP
        IF v_row.attempts >= v_row.max_attempts THEN
            v_err := public.work_truncate_utf8(
                COALESCE(NULLIF(v_row.last_error, ''), 'lease expired after max attempts'),
                4096
            );
            INSERT INTO public.work_dead_letters (
                work_item_id, kind, payload, idempotency_key, priority,
                attempts, max_attempts, last_error, failed_by, enqueued_at
            )
            VALUES (
                v_row.id, v_row.kind, v_row.payload, v_row.idempotency_key, v_row.priority,
                v_row.attempts, v_row.max_attempts, v_err, v_row.locked_by, v_row.created_at
            );
            DELETE FROM public.work_items WHERE id = v_row.id;

            IF starts_with(v_row.kind, 'scheduled_action.') THEN
                BEGIN
                    v_action_id := (v_row.payload->>'scheduled_action_id')::UUID;
                EXCEPTION WHEN OTHERS THEN
                    v_action_id := NULL;
                END;
                IF v_action_id IS NOT NULL THEN
                    UPDATE public.scheduled_actions
                       SET status       = 'failed',
                           last_error   = v_err,
                           locked_until = NULL,
                           locked_by    = NULL,
                           updated_at   = now()
                     WHERE id = v_action_id
                       AND status = 'enqueued';
                    IF FOUND THEN
                        INSERT INTO public.scheduled_action_log (
                            action_id, from_status, to_status, worker, outcome, note
                        )
                        VALUES (
                            v_action_id, 'enqueued', 'failed',
                            COALESCE(v_row.locked_by, 'workqueue-reclaim'), 'failed', v_err
                        );
                    END IF;
                END IF;
            END IF;

            v_dead := v_dead + 1;
        ELSE
            UPDATE public.work_items
               SET status           = 'pending',
                   run_at           = now(),
                   lease_expires_at = NULL,
                   locked_by        = NULL,
                   updated_at       = now()
             WHERE id = v_row.id;
            v_reclaimed := v_reclaimed + 1;
        END IF;
    END LOOP;

    IF v_reclaimed > 0 THEN
        PERFORM public.emit_wakeup_bell('work', 'reclaimed');
    END IF;

    RETURN QUERY SELECT v_reclaimed, v_dead;
END;
$$;

-- DLQ list (worker/operator only).
CREATE OR REPLACE FUNCTION work_queue_dlq_list(
    p_kind             TEXT DEFAULT NULL,
    p_include_replayed BOOLEAN DEFAULT FALSE,
    p_limit            INT DEFAULT 50,
    p_offset           INT DEFAULT 0
) RETURNS SETOF public.work_dead_letters
LANGUAGE plpgsql STABLE SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_limit  INT := LEAST(GREATEST(COALESCE(p_limit, 50), 1), 500);
    v_offset INT := GREATEST(COALESCE(p_offset, 0), 0);
BEGIN
    PERFORM public.work_queue_require_worker();

    RETURN QUERY
    SELECT *
      FROM public.work_dead_letters d
     WHERE (p_kind IS NULL OR p_kind = '' OR d.kind = p_kind)
       AND (COALESCE(p_include_replayed, FALSE) OR d.replayed_at IS NULL)
     ORDER BY d.dead_lettered_at DESC, d.id DESC
     LIMIT v_limit
    OFFSET v_offset;
END;
$$;

-- DLQ inspect single row (worker/operator only).
CREATE OR REPLACE FUNCTION work_queue_dlq_inspect(
    p_id BIGINT
) RETURNS SETOF public.work_dead_letters
LANGUAGE plpgsql STABLE SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    PERFORM public.work_queue_require_worker();

    RETURN QUERY
    SELECT *
      FROM public.work_dead_letters
     WHERE id = p_id;
END;
$$;

-- Concurrency-safe DLQ replay:
--   1. Locks target work_dead_letters row FOR UPDATE before checking replayed_at.
--   2. For scheduled_action.* items, locks scheduled_actions FOR UPDATE and
--      refuses replay unless status = 'failed' (even with p_force=TRUE, so an
--      already 'done' email can NEVER be re-sent).
--   3. Enqueues via work_enqueue; if coalesced=TRUE (active work_items row has
--      same (kind, idempotency_key)), aborts with BZ040 advising --reset-idempotency.
--   4. Transitions scheduled_actions 'failed' -> 'enqueued' + logs 'replayed'
--      and marks work_dead_letters.replayed_at / replayed_work_item_id.
CREATE OR REPLACE FUNCTION work_queue_dlq_replay(
    p_id                BIGINT,
    p_reset_idempotency BOOLEAN DEFAULT FALSE,
    p_force             BOOLEAN DEFAULT FALSE
) RETURNS TABLE(dlq_id BIGINT, work_item_id BIGINT)
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_dlq       public.work_dead_letters;
    v_action_id UUID;
    v_sa_status TEXT;
    v_idem      TEXT;
    v_new_id    BIGINT;
    v_coalesced BOOLEAN;
BEGIN
    PERFORM public.work_queue_require_worker();

    SELECT * INTO v_dlq
      FROM public.work_dead_letters
     WHERE id = p_id
     FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'work_queue_dlq_replay: dead letter % not found', p_id
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"dlq_not_found"}';
    END IF;

    IF v_dlq.replayed_at IS NOT NULL AND NOT COALESCE(p_force, FALSE) THEN
        RAISE EXCEPTION 'work_queue_dlq_replay: dead letter % was already replayed at % (pass --force to replay again)',
            p_id, v_dlq.replayed_at
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"dlq_already_replayed"}';
    END IF;

    -- Prevent concurrent --force --reset-idempotency replays from creating duplicate
    -- active jobs while the previous replay's work item is still live in work_items.
    IF v_dlq.replayed_work_item_id IS NOT NULL
       AND EXISTS (SELECT 1 FROM public.work_items WHERE id = v_dlq.replayed_work_item_id) THEN
        RAISE EXCEPTION 'work_queue_dlq_replay: previous replay work item % for dead letter % is still active',
            v_dlq.replayed_work_item_id, p_id
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"dlq_replay_still_active"}';
    END IF;

    IF starts_with(v_dlq.kind, 'scheduled_action.') THEN
        BEGIN
            v_action_id := (v_dlq.payload->>'scheduled_action_id')::UUID;
        EXCEPTION WHEN OTHERS THEN
            v_action_id := NULL;
        END;
        IF v_action_id IS NULL THEN
            RAISE EXCEPTION 'work_queue_dlq_replay: missing scheduled_action_id in DLQ % payload', p_id
                USING ERRCODE = 'BZ040',
                      HINT = '{"type":"invalid_scheduled_action_payload"}';
        END IF;

        SELECT status INTO v_sa_status
          FROM public.scheduled_actions
         WHERE id = v_action_id
         FOR UPDATE;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'work_queue_dlq_replay: scheduled_action % not found', v_action_id
                USING ERRCODE = 'BZ040',
                      HINT = '{"type":"scheduled_action_not_found"}';
        END IF;

        IF v_sa_status <> 'failed' THEN
            RAISE EXCEPTION 'work_queue_dlq_replay: refusing to replay scheduled_action % in status % (only failed actions may be replayed)',
                v_action_id, v_sa_status
                USING ERRCODE = 'BZ040',
                      HINT = '{"type":"scheduled_action_not_failed"}';
        END IF;
    END IF;

    v_idem := CASE
        WHEN COALESCE(p_reset_idempotency, FALSE) THEN NULL
        ELSE v_dlq.idempotency_key
    END;

    SELECT r.work_item_id, r.coalesced
      INTO v_new_id, v_coalesced
      FROM public.work_enqueue(
          v_dlq.kind,
          v_dlq.payload,
          v_idem,
          now(),
          v_dlq.priority,
          v_dlq.max_attempts
      ) AS r;

    IF v_coalesced THEN
        RAISE EXCEPTION 'work_queue_dlq_replay: active work item % already holds (kind=%, idempotency_key=%); re-run with --reset-idempotency to enqueue a fresh copy',
            v_new_id, v_dlq.kind, v_dlq.idempotency_key
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"idempotency_conflict"}';
    END IF;

    IF v_action_id IS NOT NULL THEN
        UPDATE public.scheduled_actions
           SET status       = 'enqueued',
               locked_until = NULL,
               locked_by    = NULL,
               updated_at   = now()
         WHERE id = v_action_id;

        INSERT INTO public.scheduled_action_log (
            action_id, from_status, to_status, worker, outcome, note
        )
        VALUES (
            v_action_id, 'failed', 'enqueued', 'mailctl', 'replayed',
            'replayed from DLQ #' || p_id::TEXT
        );
    END IF;

    UPDATE public.work_dead_letters
       SET replayed_at           = now(),
           replayed_work_item_id = v_new_id
     WHERE id = p_id;

    RETURN QUERY SELECT p_id, v_new_id;
END;
$$;

-- Operator DLQ purge (by id, kind, and/or age).
CREATE OR REPLACE FUNCTION work_queue_dlq_purge(
    p_id              BIGINT DEFAULT NULL,
    p_kind            TEXT DEFAULT NULL,
    p_older_than_days INT DEFAULT NULL,
    p_replayed_only   BOOLEAN DEFAULT TRUE
) RETURNS INT
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_deleted INT;
BEGIN
    PERFORM public.work_queue_require_worker();

    DELETE FROM public.work_dead_letters
     WHERE (p_id IS NULL OR id = p_id)
       AND (p_kind IS NULL OR p_kind = '' OR kind = p_kind)
       AND (NOT COALESCE(p_replayed_only, TRUE) OR replayed_at IS NOT NULL)
       AND (p_older_than_days IS NULL
            OR dead_lettered_at < now() - make_interval(days => GREATEST(p_older_than_days, 0)));
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted;
END;
$$;

-- Bounded retention pruning for replayed dead-letter rows (un-replayed rows are
-- kept until operator acts).
CREATE OR REPLACE FUNCTION prune_work_dead_letters(
    p_retention_days INT DEFAULT 30,
    p_batch          INT DEFAULT 1000
) RETURNS INT
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_days    INT := GREATEST(COALESCE(p_retention_days, 30), 1);
    v_batch   INT := GREATEST(COALESCE(p_batch, 1000), 1);
    v_deleted INT;
BEGIN
    PERFORM public.work_queue_require_worker();

    WITH doomed AS (
        SELECT id
          FROM public.work_dead_letters
         WHERE replayed_at IS NOT NULL
           AND replayed_at < now() - make_interval(days => v_days)
         ORDER BY replayed_at ASC, id ASC
         LIMIT v_batch
    )
    DELETE FROM public.work_dead_letters d
     USING doomed
     WHERE d.id = doomed.id;

    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted;
END;
$$;

-- Promote due pending scheduled_actions into work_items ('pending' -> 'enqueued').
-- Zero work_item_id column on scheduled_actions: linked via payload->>'scheduled_action_id'
-- and idempotency_key = 'scheduled_action:' || id.
CREATE OR REPLACE FUNCTION promote_due_scheduled_actions(
    p_batch INT DEFAULT 100
) RETURNS INT
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_batch    INT := GREATEST(COALESCE(p_batch, 100), 1);
    v_action   public.scheduled_actions;
    v_promoted INT := 0;
BEGIN
    PERFORM public.work_queue_require_worker();

    FOR v_action IN
        UPDATE public.scheduled_actions sa
           SET status     = 'enqueued',
               updated_at = now()
         WHERE sa.id IN (
             SELECT cand.id
               FROM public.scheduled_actions cand
              WHERE cand.status = 'pending'
                AND cand.fire_at <= now()
              ORDER BY cand.fire_at ASC, cand.id ASC
              FOR UPDATE SKIP LOCKED
              LIMIT v_batch
         )
        RETURNING sa.*
    LOOP
        INSERT INTO public.scheduled_action_log (
            action_id, from_status, to_status, worker, outcome
        )
        VALUES (
            v_action.id, 'pending', 'enqueued', 'workqueue-promoter', 'enqueued'
        );

        PERFORM public.work_enqueue(
            'scheduled_action.' || v_action.action_kind,
            jsonb_build_object(
                'scheduled_action_id', v_action.id::TEXT,
                'action_kind', v_action.action_kind
            ),
            'scheduled_action:' || v_action.id::TEXT,
            now(),
            0::SMALLINT,
            5
        );
        v_promoted := v_promoted + 1;
    END LOOP;

    RETURN v_promoted;
END;
$$;

-- Single-tx WorkQueue consumer entrypoint for scheduled_action.* work items.
-- Runs inside the same WorkerTx as WorkQueue::complete_tx() so a crash after
-- handler commit cannot double-execute.
-- Uses p_attempt >= p_max_attempts (NOT v_action.attempts, which may already be
-- >= 5 after a DLQ replay!).
CREATE OR REPLACE FUNCTION execute_scheduled_action_work(
    p_action_id    UUID,
    p_worker_id    TEXT,
    p_attempt      INT,
    p_max_attempts INT,
    p_allow_replay BOOLEAN DEFAULT FALSE
) RETURNS TABLE(outcome TEXT, note TEXT)
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_action      public.scheduled_actions;
    v_from_status TEXT;
    v_result      JSONB;
    v_status      TEXT;
    v_note        TEXT;
BEGIN
    PERFORM public.work_queue_require_worker();

    SELECT * INTO v_action
      FROM public.scheduled_actions
     WHERE id = p_action_id
     FOR UPDATE;

    IF NOT FOUND THEN
        RETURN QUERY SELECT 'complete'::TEXT, 'action not found'::TEXT;
        RETURN;
    END IF;

    IF v_action.status = 'done' THEN
        RETURN QUERY SELECT 'complete'::TEXT, 'already done'::TEXT;
        RETURN;
    END IF;

    IF v_action.status = 'failed' AND NOT COALESCE(p_allow_replay, FALSE) THEN
        RETURN QUERY SELECT 'complete'::TEXT, 'already failed'::TEXT;
        RETURN;
    END IF;

    IF NOT (
        v_action.status = 'enqueued'
        OR (v_action.status = 'failed' AND COALESCE(p_allow_replay, FALSE))
    ) THEN
        RAISE EXCEPTION 'execute_scheduled_action_work: refusing scheduled_action % in status % (must be enqueued)',
            p_action_id, v_action.status
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"scheduled_action_not_enqueued"}';
    END IF;

    v_from_status := v_action.status;

    UPDATE public.scheduled_actions
       SET status     = 'processing',
           locked_by  = p_worker_id,
           attempts   = attempts + 1,
           updated_at = now()
     WHERE id = v_action.id
    RETURNING * INTO v_action;

    INSERT INTO public.scheduled_action_log (
        action_id, from_status, to_status, worker, outcome
    )
    VALUES (
        v_action.id, v_from_status, 'processing', p_worker_id, 'claimed'
    );

    BEGIN
        v_result := public.run_scheduled_action(v_action);
    EXCEPTION WHEN OTHERS THEN
        v_result := jsonb_build_object('status', 'retry', 'note', SQLERRM);
    END;

    v_status := v_result->>'status';
    v_note := v_result->>'note';

    IF v_status = 'ok' THEN
        UPDATE public.scheduled_actions
           SET status       = 'done',
               locked_until = NULL,
               locked_by    = NULL,
               updated_at   = now()
         WHERE id = v_action.id;

        INSERT INTO public.scheduled_action_log (
            action_id, from_status, to_status, worker, outcome, note
        )
        VALUES (
            v_action.id, 'processing', 'done', p_worker_id, 'done', v_note
        );

        RETURN QUERY SELECT 'complete'::TEXT, COALESCE(v_note, 'ok');
        RETURN;
    END IF;

    IF v_status = 'permanent_fail' OR COALESCE(p_attempt, 1) >= COALESCE(p_max_attempts, 5) THEN
        v_note := public.work_truncate_utf8(
            COALESCE(
                NULLIF(v_note, ''),
                CASE WHEN v_status = 'permanent_fail' THEN 'permanent failure'
                     ELSE 'max attempts exhausted' END
            ),
            4096
        );

        UPDATE public.scheduled_actions
           SET status       = 'failed',
               last_error   = v_note,
               locked_until = NULL,
               locked_by    = NULL,
               updated_at   = now()
         WHERE id = v_action.id;

        INSERT INTO public.scheduled_action_log (
            action_id, from_status, to_status, worker, outcome, note
        )
        VALUES (
            v_action.id, 'processing', 'failed', p_worker_id, 'failed', v_note
        );

        RETURN QUERY SELECT 'permanent_fail'::TEXT, v_note;
        RETURN;
    END IF;

    v_note := public.work_truncate_utf8(COALESCE(NULLIF(v_note, ''), 'transient failure'), 4096);

    UPDATE public.scheduled_actions
       SET status       = 'enqueued',
           last_error   = v_note,
           locked_until = NULL,
           locked_by    = NULL,
           updated_at   = now()
     WHERE id = v_action.id;

    INSERT INTO public.scheduled_action_log (
        action_id, from_status, to_status, worker, outcome, note
    )
    VALUES (
        v_action.id, 'processing', 'enqueued', p_worker_id, 'retry', v_note
    );

    RETURN QUERY SELECT 'retry'::TEXT, v_note;
END;
$$;

-- ── Function ownership & least-privilege ACLs ────────────────────────────────
-- PG 15+ owner-safe transient GRANT/REVOKE CREATE ON SCHEMA public around
-- ALTER FUNCTION ... OWNER TO setjoin_worker so both superuser and non-superuser
-- setjoin_owner load cleanly with zero other_secdef_drifted rows.
DO $$
DECLARE
    v_granted_create BOOLEAN := FALSE;
    v_sig            TEXT;
BEGIN
    -- Narrow SECURITY DEFINER seams owned by setjoin_worker, callable by app + worker.
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
        IF NOT has_schema_privilege('setjoin_worker', 'public', 'CREATE') THEN
            GRANT CREATE ON SCHEMA public TO setjoin_worker;
            v_granted_create := TRUE;
        END IF;

        ALTER FUNCTION public.work_enqueue_app(text, jsonb, text, timestamptz) OWNER TO setjoin_worker;
        ALTER FUNCTION public.work_queue_stats() OWNER TO setjoin_worker;

        IF v_granted_create THEN
            REVOKE CREATE ON SCHEMA public FROM setjoin_worker;
        END IF;
    END IF;

    REVOKE ALL ON FUNCTION public.work_enqueue_app(text, jsonb, text, timestamptz) FROM PUBLIC;
    REVOKE ALL ON FUNCTION public.work_queue_stats() FROM PUBLIC;
    REVOKE ALL ON FUNCTION public.emit_wakeup_bell(text, text) FROM PUBLIC;
    REVOKE ALL ON FUNCTION public.work_truncate_utf8(text, int) FROM PUBLIC;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
        GRANT EXECUTE ON FUNCTION public.work_enqueue_app(text, jsonb, text, timestamptz) TO setjoin_app;
        GRANT EXECUTE ON FUNCTION public.work_queue_stats() TO setjoin_app;
        GRANT EXECUTE ON FUNCTION public.emit_wakeup_bell(text, text) TO setjoin_app;
        GRANT EXECUTE ON FUNCTION public.work_truncate_utf8(text, int) TO setjoin_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
        GRANT EXECUTE ON FUNCTION public.work_enqueue_app(text, jsonb, text, timestamptz) TO setjoin_worker;
        GRANT EXECUTE ON FUNCTION public.work_queue_stats() TO setjoin_worker;
        GRANT EXECUTE ON FUNCTION public.emit_wakeup_bell(text, text) TO setjoin_worker;
        GRANT EXECUTE ON FUNCTION public.work_truncate_utf8(text, int) TO setjoin_worker;
    END IF;

    -- Strictly worker-only SECURITY INVOKER functions (also restated in provision-roles.sql).
    FOREACH v_sig IN ARRAY ARRAY[
        'public.work_queue_require_worker()',
        'public.work_enqueue(text,jsonb,text,timestamptz,smallint,integer)',
        'public.work_queue_claim(text,text[],integer,integer,integer)',
        'public.work_queue_heartbeat(bigint,integer,text,integer)',
        'public.work_queue_complete(bigint,integer,text)',
        'public.work_release(bigint,integer,text)',
        'public.work_cancel_pending(bigint)',
        'public.work_expedite(bigint)',
        'public.work_queue_fail(bigint,integer,text,text,double precision,boolean)',
        'public.work_queue_reclaim_expired(integer)',
        'public.work_queue_dlq_list(text,boolean,integer,integer)',
        'public.work_queue_dlq_inspect(bigint)',
        'public.work_queue_dlq_replay(bigint,boolean,boolean)',
        'public.work_queue_dlq_purge(bigint,text,integer,boolean)',
        'public.prune_work_dead_letters(integer,integer)',
        'public.promote_due_scheduled_actions(integer)',
        'public.execute_scheduled_action_work(uuid,text,integer,integer,boolean)'
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
