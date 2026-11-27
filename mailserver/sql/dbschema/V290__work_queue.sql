-- V290__work_queue.sql — Wave 2.1 (#548): durable WorkQueue (FOR UPDATE SKIP LOCKED),
-- dead-letter queue (work_dead_letters), scheduled_actions 'enqueued' handoff state,
-- and notify_intents retention index.
--
-- Isolation posture (V253/V281 pattern):
--   * work_items and work_dead_letters are cross-tenant worker/operator substrates
--     with ENABLE + FORCE ROW LEVEL SECURITY and ZERO permissive policies
--     (deny-all to setjoin_app).
--   * Ownership sits with setjoin_owner; PUBLIC and setjoin_app have zero table
--     privileges; setjoin_worker holds SELECT/INSERT/UPDATE/DELETE (reasserted in
--     scripts/provision-roles.sql).
--   * scheduled_actions gains ONLY the 'enqueued' status value (ZERO new columns
--     so to_jsonb(scheduled_actions) parity goldens remain byte-identical).
--   * Do NOT seed public.feature_toggles (preserves V275 toggle registry goldens).

CREATE TABLE public.work_items (
    id               BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind             TEXT NOT NULL
        CHECK (kind ~ '^[a-z][a-z0-9_.:-]{0,127}$'),
    payload          JSONB NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(payload) = 'object'
               AND octet_length(payload::text) <= 65536),
    idempotency_key  TEXT,
    status           TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'leased')),
    priority         SMALLINT NOT NULL DEFAULT 0,
    run_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    attempts         INTEGER NOT NULL DEFAULT 0
        CHECK (attempts >= 0),
    max_attempts     INTEGER NOT NULL DEFAULT 5
        CHECK (max_attempts BETWEEN 1 AND 100),
    lease_expires_at TIMESTAMPTZ,
    locked_by        TEXT,
    claim_generation INTEGER NOT NULL DEFAULT 0
        CHECK (claim_generation >= 0),
    last_error       TEXT
        CHECK (last_error IS NULL OR octet_length(last_error) <= 4096),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT work_items_lease_shape CHECK (
        (status = 'leased') = (lease_expires_at IS NOT NULL AND locked_by IS NOT NULL)
    )
);

CREATE UNIQUE INDEX work_items_kind_idempotency_uidx
    ON public.work_items (kind, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

CREATE INDEX work_items_pending_kind_idx
    ON public.work_items (kind, priority DESC, run_at ASC, id ASC)
    WHERE status = 'pending';

CREATE INDEX work_items_pending_due_idx
    ON public.work_items (run_at ASC, id ASC)
    WHERE status = 'pending';

CREATE INDEX work_items_leased_expiry_idx
    ON public.work_items (kind, lease_expires_at ASC)
    WHERE status = 'leased';

COMMENT ON TABLE public.work_items IS
  'Durable background work queue (V290, #548): SKIP LOCKED claimable jobs with '
  'monotonic claim_generation fencing, optional per-kind idempotency_key coalescing, '
  'and bounded error storage. FORCE RLS deny-all to setjoin_app; worker/operator only.';

CREATE TABLE public.work_dead_letters (
    id                    BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    work_item_id          BIGINT NOT NULL,
    kind                  TEXT NOT NULL
        CHECK (kind ~ '^[a-z][a-z0-9_.:-]{0,127}$'),
    payload               JSONB NOT NULL
        CHECK (jsonb_typeof(payload) = 'object'
               AND octet_length(payload::text) <= 65536),
    idempotency_key       TEXT,
    priority              SMALLINT NOT NULL DEFAULT 0,
    attempts              INTEGER NOT NULL
        CHECK (attempts >= 0),
    max_attempts          INTEGER NOT NULL
        CHECK (max_attempts BETWEEN 1 AND 100),
    last_error            TEXT NOT NULL
        CHECK (octet_length(last_error) <= 4096),
    failed_by             TEXT,
    enqueued_at           TIMESTAMPTZ NOT NULL,
    dead_lettered_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    replayed_at           TIMESTAMPTZ,
    replayed_work_item_id BIGINT
);

CREATE INDEX work_dead_letters_unreplayed_idx
    ON public.work_dead_letters (dead_lettered_at DESC, id DESC)
    WHERE replayed_at IS NULL;

CREATE INDEX work_dead_letters_kind_unreplayed_idx
    ON public.work_dead_letters (kind, dead_lettered_at DESC)
    WHERE replayed_at IS NULL;

CREATE INDEX work_dead_letters_replayed_idx
    ON public.work_dead_letters (replayed_at)
    WHERE replayed_at IS NOT NULL;

COMMENT ON TABLE public.work_dead_letters IS
  'Dead-letter queue for permanently failed or attempt-exhausted work_items (V290, #548). '
  'FORCE RLS deny-all to setjoin_app; inspected/replayed/purged via mailctl work dlq.';

-- Extend scheduled_actions status vocabulary with 'enqueued' (ZERO new columns so
-- to_jsonb(scheduled_actions) parity goldens remain byte-identical).
ALTER TABLE public.scheduled_actions
    DROP CONSTRAINT IF EXISTS scheduled_actions_status_check;
ALTER TABLE public.scheduled_actions
    ADD CONSTRAINT scheduled_actions_status_check
    CHECK (status IN ('pending', 'enqueued', 'processing', 'done', 'failed'));

-- Retention pruning index & poison-row CHECK constraints for notify_intents.
CREATE INDEX IF NOT EXISTS notify_intents_created_at_idx
    ON public.notify_intents (created_at);

DELETE FROM public.notify_intents
 WHERE channel IS NULL
    OR octet_length(channel) = 0
    OR octet_length(channel) > 63
    OR channel !~ '^[a-zA-Z0-9_.:-]+$'
    OR octet_length(payload) > 7900;

ALTER TABLE public.notify_intents
    DROP CONSTRAINT IF EXISTS notify_intents_channel_check;
ALTER TABLE public.notify_intents
    ADD CONSTRAINT notify_intents_channel_check
    CHECK (octet_length(channel) BETWEEN 1 AND 63 AND channel ~ '^[a-zA-Z0-9_.:-]+$');

ALTER TABLE public.notify_intents
    DROP CONSTRAINT IF EXISTS notify_intents_payload_check;
ALTER TABLE public.notify_intents
    ADD CONSTRAINT notify_intents_payload_check
    CHECK (octet_length(payload) <= 7900);

-- Deny-all FORCE RLS on work_items, work_dead_letters, and notify_intents
-- (zero permissive policies; app writes flow through narrow worker-owned
-- SECURITY DEFINER seams work_enqueue_app / app_notify_enqueue_intent).
ALTER TABLE public.work_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.work_items FORCE ROW LEVEL SECURITY;
ALTER TABLE public.work_dead_letters ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.work_dead_letters FORCE ROW LEVEL SECURITY;
ALTER TABLE public.notify_intents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.notify_intents FORCE ROW LEVEL SECURITY;

REVOKE ALL ON public.work_items FROM PUBLIC;
REVOKE ALL ON public.work_dead_letters FROM PUBLIC;
REVOKE ALL ON public.notify_intents FROM PUBLIC;

DO $$
DECLARE
    v_tbl text;
    v_seq text;
BEGIN
    FOREACH v_tbl IN ARRAY ARRAY['work_items', 'work_dead_letters', 'notify_intents'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_owner') THEN
            EXECUTE format('ALTER TABLE public.%I OWNER TO setjoin_owner', v_tbl);
        END IF;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
            EXECUTE format('REVOKE ALL ON public.%I FROM setjoin_app', v_tbl);
        END IF;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
            EXECUTE format('REVOKE ALL ON public.%I FROM setjoin_worker', v_tbl);
            EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON public.%I TO setjoin_worker', v_tbl);
        END IF;
        v_seq := pg_get_serial_sequence('public.' || v_tbl, 'id');
        IF v_seq IS NOT NULL THEN
            EXECUTE format('REVOKE ALL ON SEQUENCE %s FROM PUBLIC', v_seq);
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
                EXECUTE format('REVOKE ALL ON SEQUENCE %s FROM setjoin_app', v_seq);
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
                EXECUTE format('REVOKE ALL ON SEQUENCE %s FROM setjoin_worker', v_seq);
                EXECUTE format('GRANT USAGE, SELECT ON SEQUENCE %s TO setjoin_worker', v_seq);
            END IF;
        END IF;
    END LOOP;
END $$;

-- ── Upgrade-safe reducer definitions (canonical sources under mailserver/sql/reducers/)
--    so `upgrade.sh` -> `mailctl schema apply --yes` updates every Wave 2.1 reducer
--    atomically alongside V290 DDL while fresh installs stay byte-identical under
--    scripts/reload-reducers.sh and scripts/check-schema-determinism.sh.

-- [embedded from reducers/app_notify.sql]
CREATE OR REPLACE FUNCTION app_notify_enqueue_intent(
  p_channel TEXT,
  p_payload TEXT
) RETURNS VOID
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_payload TEXT := COALESCE(p_payload, '');
BEGIN
  IF p_channel IS NULL OR octet_length(p_channel) = 0 OR octet_length(p_channel) > 63
     OR p_channel !~ '^[a-zA-Z0-9_.:-]+$' THEN
    RAISE EXCEPTION 'app_notify_enqueue_intent: invalid channel %', p_channel
      USING ERRCODE = 'BZ040',
            HINT = '{"type":"invalid_notify_channel"}';
  END IF;
  IF octet_length(v_payload) > 7900 THEN
    RAISE EXCEPTION 'app_notify_enqueue_intent: payload exceeds 7900 bytes'
      USING ERRCODE = 'BZ040',
            HINT = '{"type":"notify_payload_too_large"}';
  END IF;

  INSERT INTO public.notify_intents (channel, payload)
  VALUES (p_channel, v_payload);
END;
$$;

DO $$
DECLARE
  v_granted_create BOOLEAN := FALSE;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
    IF NOT has_schema_privilege('setjoin_worker', 'public', 'CREATE') THEN
      GRANT CREATE ON SCHEMA public TO setjoin_worker;
      v_granted_create := TRUE;
    END IF;
    ALTER FUNCTION public.app_notify_enqueue_intent(text, text) OWNER TO setjoin_worker;
    IF v_granted_create THEN
      REVOKE CREATE ON SCHEMA public FROM setjoin_worker;
    END IF;
  END IF;
  REVOKE ALL ON FUNCTION public.app_notify_enqueue_intent(text, text) FROM PUBLIC;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
    GRANT EXECUTE ON FUNCTION public.app_notify_enqueue_intent(text, text) TO setjoin_app;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
    GRANT EXECUTE ON FUNCTION public.app_notify_enqueue_intent(text, text) TO setjoin_worker;
  END IF;
END $$;

-- p_channel — the pg_notify channel (e.g. 'tag:'||mailbox_id, 'calendar:'||…).
-- p_payload — the JSON payload text.
CREATE OR REPLACE FUNCTION app_notify(
  p_channel TEXT,
  p_payload TEXT
) RETURNS VOID AS $$
BEGIN
  IF coalesce(current_setting('app.capture_notify', TRUE), '') = 'on' THEN
    INSERT INTO _test_notify_log(channel, payload, seq)
      VALUES (p_channel, p_payload, nextval('_test_notify_log_seq'));
  END IF;

  PERFORM public.app_notify_enqueue_intent(p_channel, p_payload);
END;
$$ LANGUAGE plpgsql;

-- [embedded from reducers/work_queue.sql]
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

-- [embedded from reducers/scheduled_action_enqueue.sql]
CREATE OR REPLACE FUNCTION enqueue_scheduled_action(
    p_kind       TEXT,
    p_fire_at    TIMESTAMPTZ,
    p_payload    JSONB,
    p_mailbox_id BIGINT,
    p_dedup_key  TEXT DEFAULT NULL
) RETURNS UUID AS $$
DECLARE
    v_id UUID;
BEGIN
    IF p_kind IS NULL OR p_kind NOT IN ('send','snooze','remind','dsn','chat_send') THEN
        RAISE EXCEPTION 'Unknown action_kind %', p_kind
            USING ERRCODE = 'BZ036',
                  HINT = jsonb_build_object('type','bad_action_kind','kind',p_kind)::TEXT;
    END IF;

    IF p_fire_at IS NULL THEN
        RAISE EXCEPTION 'fire_at is required'
            USING ERRCODE = 'BZ037',
                  HINT = jsonb_build_object('type','fire_at_required')::TEXT;
    END IF;

    INSERT INTO scheduled_actions (action_kind, fire_at, payload, mailbox_id, dedup_key)
    VALUES (p_kind, p_fire_at, COALESCE(p_payload, '{}'::JSONB), p_mailbox_id, p_dedup_key)
    RETURNING id INTO v_id;

    -- Default the send-style kinds' dedup_key to the action id (egress
    -- idempotency / reclaim correlation). chat_send joins send here — see
    -- the header note above.
    IF p_kind IN ('send', 'chat_send') AND p_dedup_key IS NULL THEN
        UPDATE scheduled_actions SET dedup_key = v_id::TEXT WHERE id = v_id;
    END IF;

    RETURN v_id;
END;
$$ LANGUAGE plpgsql;

-- cancel_scheduled_action: delete the matching pending/enqueued action for this owner.
-- Matches on action_kind + a payload subset (e.g. {message_id}); ownership via
-- p_mailbox_id in the same DELETE (R3). Pending and promoted-but-unstarted
-- ('enqueued') rows are cancellable (if a work_items row was already enqueued,
-- execute_scheduled_action_work observes the missing scheduled_action and
-- completes harmlessly); processing/done/failed actions have already fired or
-- are mid-flight. Returns the number of cancelled rows.
CREATE OR REPLACE FUNCTION cancel_scheduled_action(
    p_mailbox_id    BIGINT,
    p_kind          TEXT,
    p_payload_match JSONB DEFAULT '{}'::JSONB
) RETURNS INT AS $$
DECLARE
    v_count INT;
BEGIN
    WITH del AS (
        DELETE FROM scheduled_actions
        WHERE mailbox_id = p_mailbox_id
          AND action_kind = p_kind
          AND status IN ('pending', 'enqueued')
          AND payload @> COALESCE(p_payload_match, '{}'::JSONB)
        RETURNING 1
    )
    SELECT count(*) INTO v_count FROM del;
    RETURN v_count;
END;
$$ LANGUAGE plpgsql;

-- [embedded from reducers/scheduled_actions_dispatch.sql]
CREATE OR REPLACE FUNCTION claim_scheduled_actions(p_worker_id TEXT, p_batch INT DEFAULT 100)
RETURNS SETOF scheduled_actions AS $$
BEGIN
    RETURN QUERY
    UPDATE scheduled_actions
    SET status = 'processing',
        locked_until = now() + interval '2 minutes',
        locked_by = p_worker_id,
        attempts = attempts + 1,
        updated_at = now()
    WHERE id IN (
        SELECT sa.id FROM scheduled_actions sa
        WHERE (
            (sa.status = 'pending' AND sa.fire_at <= now())
            OR (
                sa.status = 'enqueued'
                AND sa.fire_at <= now()
                AND NOT EXISTS (
                    SELECT 1
                      FROM public.work_items wi
                     WHERE wi.kind = 'scheduled_action.' || sa.action_kind
                       AND wi.idempotency_key = 'scheduled_action:' || sa.id::TEXT
                )
            )
        )
        ORDER BY sa.fire_at
        FOR UPDATE SKIP LOCKED
        LIMIT GREATEST(p_batch, 1)
    )
    RETURNING *;
END;
$$ LANGUAGE plpgsql;

-- Crash recovery: a processing row whose lease expired → back to pending (logged).
-- Safe to re-run because the egress handler (send) is idempotent via dedup_key.
CREATE OR REPLACE FUNCTION reclaim_expired_scheduled_actions()
RETURNS SETOF UUID AS $$
DECLARE
    v_row scheduled_actions;
BEGIN
    FOR v_row IN
        UPDATE scheduled_actions
        SET status = 'pending', locked_until = NULL, locked_by = NULL, updated_at = now()
        WHERE status = 'processing' AND locked_until < now()
        RETURNING *
    LOOP
        INSERT INTO scheduled_action_log (action_id, from_status, to_status, worker, outcome, note)
        VALUES (v_row.id, 'processing', 'pending', v_row.locked_by, 'expired',
                'lease expired; reclaimed');
        RETURN NEXT v_row.id;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- Thin router: the ONLY place that knows kind→handler. Adding a kind edits this
-- switch + adds a handler reducer. Returns the handler's status JSON ({status,note}).
--
-- Test hook: a payload carrying `_test_outcome` short-circuits to that outcome
-- ('retry' | 'permanent_fail') WITHOUT invoking a handler. This lets the retry /
-- terminal-failure policy be exercised deterministically (scheduled_actions_retry.pg)
-- without coupling the test to any one handler's failure modes. Production payloads
-- never set `_test_outcome`.
CREATE OR REPLACE FUNCTION run_scheduled_action(p_action scheduled_actions)
RETURNS JSONB AS $$
BEGIN
    IF p_action.payload ? '_test_outcome' THEN
        RETURN jsonb_build_object('status', p_action.payload->>'_test_outcome',
                                  'note', 'test hook');
    END IF;

    CASE p_action.action_kind
        WHEN 'send'        THEN RETURN scheduled_action_send(p_action);
        WHEN 'snooze'      THEN RETURN scheduled_action_snooze(p_action);
        WHEN 'remind'      THEN RETURN scheduled_action_remind(p_action);
        WHEN 'dsn'         THEN RETURN scheduled_action_dsn(p_action);
        WHEN 'rules_retro' THEN RETURN scheduled_action_rules_retro(p_action);
        WHEN 'chat_send'   THEN RETURN scheduled_action_chat_send(p_action);
        ELSE RAISE EXCEPTION 'Unknown action_kind %', p_action.action_kind
            USING ERRCODE = 'BZ036',
                  HINT = jsonb_build_object('type','bad_action_kind',
                                            'kind', p_action.action_kind)::TEXT;
    END CASE;
END;
$$ LANGUAGE plpgsql;

-- The cron entry-point: reclaim, claim a batch, run each, apply the §5 status
-- machine. Returns the count of actions that completed (status='done') this tick.
--
-- Retry / terminal-failure policy (spec §5):
--   * handler 'ok'             → terminal done.
--   * handler 'permanent_fail' → terminal failed immediately (no re-queue).
--   * handler 'retry' / raised exception:
--       - attempts >= MAX_ATTEMPTS (5) → terminal failed (exhausted).
--       - else re-pending with fire_at = now() + backoff(attempts), where
--         backoff = LEAST(interval '1 minute' * 2^attempts, interval '1 hour')
--         (exponential, capped). attempts was already incremented by the claim.
CREATE OR REPLACE FUNCTION dispatch_scheduled_actions(p_worker_id TEXT DEFAULT 'cron', p_batch INT DEFAULT 100)
RETURNS INT AS $$
DECLARE
    v_action     scheduled_actions;
    v_result     JSONB;
    v_status     TEXT;
    v_done       INT := 0;
    v_backoff    INTERVAL;
    c_max_attempts CONSTANT INT := 5;
BEGIN
    PERFORM reclaim_expired_scheduled_actions();

    FOR v_action IN SELECT * FROM claim_scheduled_actions(p_worker_id, p_batch) LOOP
        INSERT INTO scheduled_action_log (action_id, from_status, to_status, worker, outcome)
        VALUES (v_action.id, 'pending', 'processing', p_worker_id, 'claimed');

        BEGIN
            v_result := run_scheduled_action(v_action);
        EXCEPTION WHEN OTHERS THEN
            v_result := jsonb_build_object('status', 'retry', 'note', SQLERRM);
        END;

        v_status := v_result->>'status';

        IF v_status = 'ok' THEN
            UPDATE scheduled_actions
               SET status='done', locked_until=NULL, locked_by=NULL, updated_at=now()
             WHERE id = v_action.id;
            INSERT INTO scheduled_action_log (action_id, from_status, to_status, worker, outcome, note)
            VALUES (v_action.id, 'processing', 'done', p_worker_id, 'done', v_result->>'note');
            v_done := v_done + 1;

        ELSIF v_status = 'permanent_fail' OR v_action.attempts >= c_max_attempts THEN
            -- Terminal failure: a permanent error, or retries exhausted.
            UPDATE scheduled_actions
               SET status='failed', last_error = v_result->>'note',
                   locked_until=NULL, locked_by=NULL, updated_at=now()
             WHERE id = v_action.id;
            INSERT INTO scheduled_action_log (action_id, from_status, to_status, worker, outcome, note)
            VALUES (v_action.id, 'processing', 'failed', p_worker_id, 'failed',
                    COALESCE(v_result->>'note',
                             CASE WHEN v_status='permanent_fail' THEN 'permanent failure'
                                  ELSE 'max attempts exhausted' END));

        ELSE
            -- Transient failure: re-queue with exponential, capped backoff.
            v_backoff := LEAST(interval '1 minute' * power(2, v_action.attempts), interval '1 hour');
            UPDATE scheduled_actions
               SET status='pending', fire_at = now() + v_backoff,
                   last_error = v_result->>'note',
                   locked_until=NULL, locked_by=NULL, updated_at=now()
             WHERE id = v_action.id;
            INSERT INTO scheduled_action_log (action_id, from_status, to_status, worker, outcome, note)
            VALUES (v_action.id, 'processing', 'pending', p_worker_id, 'retry', v_result->>'note');
        END IF;
    END LOOP;
    RETURN v_done;
END;
$$ LANGUAGE plpgsql;

-- [embedded from reducers/chat_schedule.sql]
CREATE OR REPLACE FUNCTION chat_schedule_message(
    p_user_id bigint, p_channel_id bigint, p_body text,
    p_parent_id bigint DEFAULT NULL, p_mentions bigint[] DEFAULT '{}',
    p_broadcast text DEFAULT NULL, p_fire_at timestamptz DEFAULT NULL
) RETURNS uuid AS $$
DECLARE
    v_payload jsonb;
    v_id      uuid;
BEGIN
    -- membership checked at ENQUEUE time (BZ163); the handler re-checks at
    -- FIRE time via chat_message_send itself (TOCTOU — a member kicked
    -- between now and fire_at must not silently post).
    PERFORM chat_require_role(p_channel_id, p_user_id);
    IF coalesce(btrim(p_body), '') = '' OR octet_length(p_body) > 65536 THEN
        RAISE EXCEPTION 'message body empty or over 64KiB'
            USING ERRCODE='BZ168', HINT='{"type":"invalidArguments"}';
    END IF;
    IF p_fire_at IS NULL OR p_fire_at <= now() THEN
        RAISE EXCEPTION 'fireAt must be a future timestamp'
            USING ERRCODE='BZ179', HINT='{"type":"invalidArguments","detail":"fireAt must be in the future"}';
    END IF;
    -- payload built server-side from p_user_id/p_channel_id/etc — never from
    -- a raw request-body pass-through (R2). mentions defaults to '{}' so a
    -- NULL array never round-trips as JSON null.
    v_payload := jsonb_build_object(
      'userId', p_user_id, 'channelId', p_channel_id, 'body', p_body,
      'parentId', p_parent_id, 'mentions', to_jsonb(COALESCE(p_mentions, '{}'::bigint[])),
      'broadcast', p_broadcast
    );
    v_id := enqueue_scheduled_action('chat_send', p_fire_at, v_payload, NULL);
    RETURN v_id;
END;
$$ LANGUAGE plpgsql;

-- chat_scheduled_list: the caller's own pending + enqueued + FAILED chat_send rows.
-- Failed rows stay visible (grill-decided, plan Task 2): silent content loss
-- is the wrong brand for a compliance product — the failure reason (the
-- handler's caught BZ, in payload->>'failureCode') and the still-readable
-- body let the user copy it out and re-send; Dismiss is chat_scheduled_cancel
-- on a failed row.
CREATE OR REPLACE FUNCTION chat_scheduled_list(p_user_id bigint) RETURNS jsonb AS $$
    SELECT COALESCE(jsonb_agg(jsonb_build_object(
             'actionId', id, 'channelId', (payload->>'channelId')::bigint,
             'body', payload->>'body', 'fireAt', fire_at, 'status', status,
             'failureCode', payload->>'failureCode', 'lastError', last_error
           ) ORDER BY fire_at ASC), '[]'::jsonb)
      FROM scheduled_actions
     WHERE action_kind = 'chat_send'
       AND status IN ('pending', 'enqueued', 'failed')
       AND payload->>'userId' = p_user_id::text;
$$ LANGUAGE sql STABLE;

-- chat_scheduled_cancel: works on pending, enqueued, AND failed (dismiss); ownership +
-- id + status all folded into ONE DELETE (R1/R3, no check-then-act window).
-- Anti-oracle (BZ179): doesn't exist, belongs to another user, or already
-- fired/processing all fail identically — a client can't probe which.
CREATE OR REPLACE FUNCTION chat_scheduled_cancel(
    p_user_id bigint, p_action_id uuid
) RETURNS void AS $$
DECLARE
    v_count int;
BEGIN
    WITH del AS (
        DELETE FROM scheduled_actions
         WHERE id = p_action_id
           AND action_kind = 'chat_send'
           AND status IN ('pending', 'enqueued', 'failed')
           AND payload->>'userId' = p_user_id::text
        RETURNING 1
    )
    SELECT count(*) INTO v_count FROM del;
    IF v_count = 0 THEN
        RAISE EXCEPTION 'scheduled action not found or not cancellable'
            USING ERRCODE='BZ179', HINT='{"type":"invalidArguments","detail":"not pending/failed, not yours, or does not exist"}';
    END IF;
END;
$$ LANGUAGE plpgsql;

-- [embedded from reducers/chat_purge_expired.sql]
CREATE OR REPLACE FUNCTION chat_purge_expired(
  p_batch_size INT DEFAULT 1000,
  p_dry_run    BOOLEAN DEFAULT FALSE
) RETURNS TABLE(channel_id BIGINT, purged_count INT, id_from BIGINT, id_to BIGINT,
                retention_days INT)
LANGUAGE plpgsql AS $$
DECLARE
  v_ch RECORD; v_total INT := 0; v_ret INT;
  v_n INT; v_from BIGINT; v_to BIGINT; v_seq_max BIGINT; v_elems JSONB;
  v_nodes BIGINT[];
  -- F4 (pipeline review fix): the scheduled_actions DELETE below had no
  -- RETURNING and no digest — a failed scheduled send is an A4b export class
  -- while retained, so its destruction was an unrecorded records event.
  -- scheduled_actions.id is a uuid (no MIN/MAX aggregate in this PG
  -- version, and no meaningful ordering over random uuids anyway, unlike
  -- chat_messages' sequential bigint identity) — array_agg is the honest
  -- "which rows" signal, not a fabricated range.
  v_sched_n INT; v_sched_ids uuid[];
  -- C2 Task 8 Step 4: origin-qualified {origin,key} pairs captured from the
  -- doomed chat_messages rows BEFORE they die — the federation_outbox purge
  -- scrub's match key (see federation_outbox_redact_purged.sql).
  v_fed_origin_keys jsonb;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles
                   WHERE key='feature.chat_compliance'), FALSE) THEN
    RETURN;
  END IF;
  FOR v_ch IN
    SELECT c.id, chat_effective_retention(c.id) AS ret
      FROM chat_channels c
     WHERE c.classification = 'regular'        -- 1: gxp is never destroyed by a cron
       AND NOT chat_hold_active(c.id)          -- 2: hold, single-homed predicate
       AND chat_effective_retention(c.id) IS NOT NULL
  LOOP
    v_ret := v_ch.ret;
    BEGIN
      IF p_dry_run THEN
        SELECT count(*)::int, MIN(m.id), MAX(m.id) INTO v_n, v_from, v_to
          FROM chat_messages m
         WHERE m.channel_id = v_ch.id
           AND m.created_at + make_interval(days => v_ret) <= now();
        IF v_n > 0 THEN
          channel_id := v_ch.id; purged_count := v_n; id_from := v_from;
          id_to := v_to; retention_days := v_ret; RETURN NEXT;
        END IF;
        CONTINUE;
      END IF;

      -- Attachment-node collection BEFORE the message DELETE (Task 7): the
      -- CASCADE (chat_message_attachments.message_id ON DELETE CASCADE,
      -- V120:45) clears the link rows the moment the messages die, so this
      -- must run first or there is nothing left to join against.
      SELECT array_agg(DISTINCT a.file_node_id) INTO v_nodes
        FROM chat_message_attachments a
        JOIN chat_messages m ON m.id = a.message_id
       WHERE m.channel_id = v_ch.id
         AND m.created_at + make_interval(days => v_ret) <= now();

      -- risk 5 (verify N5 — BLOCKER in v2): message content OUTSIDE chat_messages.
      -- THIS DELETE RUNS BEFORE THE `CONTINUE WHEN v_n = 0` BELOW, DELIBERATELY.
      -- v2 had it after, so a channel with ZERO expired MESSAGES but expired
      -- failed/done chat_send rows — a scheduled send that failed and never became
      -- a message; or a channel whose messages were all purged on an earlier run —
      -- kept its verbatim body in a no-RLS `payload` FOREVER. Nothing else in the
      -- repo reaps these rows. Do not "tidy" this back below the CONTINUE.
      -- status NOT IN ('pending', 'enqueued'): never destroy an UNFIRED scheduled
      -- message (that is silent content loss, not retention).
      --
      -- F4 (pipeline review fix): RETURNING id captures a count + id range so
      -- this destruction folds into the SAME purge.execute act below
      -- (alongside the message stats) instead of leaving it unrecorded — a
      -- failed/done scheduled-send body is A4b export content while
      -- retained. Originally scoped to when this destruction co-occurred
      -- with a message purge in the same channel/run — a channel with ONLY
      -- expired scheduled rows and zero expired messages still had its rows
      -- destroyed here, but the CONTINUE below used to short-circuit BEFORE
      -- the act, leaving that scheduled-only destruction unrecorded (the F4
      -- residual, closed by the confirmation-review fix: the CONTINUE below
      -- now only skips a channel with NOTHING destroyed on either leg — see
      -- chat_purge.pg's p_sched0 case).
      WITH sched_gone AS (
        DELETE FROM scheduled_actions
         WHERE action_kind = 'chat_send'
           AND (payload->>'channelId')::bigint = v_ch.id
           AND status NOT IN ('pending', 'enqueued')
           AND created_at + make_interval(days => v_ret) <= now()
        RETURNING id
      )
      SELECT count(*)::int, array_agg(id) INTO v_sched_n, v_sched_ids FROM sched_gone;

      -- The DELETE is BOUNDED (eng review #6). p_batch_size checked only BETWEEN
      -- channels would let ONE channel with millions of expired messages run a
      -- single unbounded DELETE + cascades in one transaction, blow the cron
      -- Timeout, roll back, and never make progress on ANY later tick. This is
      -- exactly what enforce_retention's LIMIT p_batch_size driving scan avoids
      -- (retention.sql:68). All of purgedCount/idFrom/idTo/destroyedElems derive
      -- from the `gone` CTE — never from a pre-scan, which would over-report.
      --
      -- LEAF HASH IS sha256, NEVER md5 (verify N3): this is evidentiary material
      -- in a 防篡改 feature; md5 has practical chosen-prefix collisions. Same
      -- one-liner, same cost.
      -- RETURNING builds the EXACT digest element Task 9's anchor concatenated:
      --   id ':' author_id ':' epoch(created_at) ':' sha256(original_body)
      -- author_id and created_at die with the row, so the act must record the
      -- whole element, not just the leaf — that is what lets the verifier
      -- reconcile an anchor over a purged range to a HARD boolean instead of
      -- shrugging with a purge_overlap flag (verify N1). epoch, not ::text: a
      -- timestamptz's rendering is DateStyle/TimeZone-dependent and would produce
      -- false tamper verdicts across sessions.
      WITH gone AS (
        DELETE FROM chat_messages
         WHERE id IN (SELECT id FROM chat_messages
                       -- table-qualified: chat_purge_expired's own OUT
                       -- parameter is also named channel_id, and PL/pgSQL's
                       -- default #variable_conflict=error rejects the bare
                       -- reference here as ambiguous (a real compile bug,
                       -- caught red-first, not a design point of the plan).
                       WHERE chat_messages.channel_id = v_ch.id
                         AND created_at + make_interval(days => v_ret) <= now()
                       ORDER BY id
                       LIMIT GREATEST(p_batch_size - v_total, 0))
        RETURNING id, seq, federated_origin_domain, federated_stanza_id,
                  id::text||':'||author_id::text||':'||
                  extract(epoch from created_at)::text||':'||
                  encode(sha256(convert_to(COALESCE(
                    (SELECT rv.prior_body FROM chat_message_revisions rv
                      WHERE rv.message_id = chat_messages.id
                      ORDER BY rv.id LIMIT 1), body), 'UTF8')), 'hex') AS elem
      )
      SELECT count(*)::int, MIN(id), MAX(id), MAX(seq),
             jsonb_object_agg(id::text, elem),
             jsonb_agg(jsonb_build_object('origin', federated_origin_domain,
                                           'key', COALESCE(federated_stanza_id, id::text)))
        INTO v_n, v_from, v_to, v_seq_max, v_elems, v_fed_origin_keys
        FROM gone;

      -- C2 Task 8 Step 4: scrub the transport-residue outbox copy of every
      -- doomed row's body — the ONE new call site at this choke point (see
      -- federation_outbox_redact_purged.sql for the origin-qualified match
      -- rules; a no-op on a non-federated channel or an empty batch).
      -- v_fed_origin_keys is jsonb_agg over ZERO rows (v_n = 0) -> NULL,
      -- which federation_outbox_redact_purged already treats as a no-op.
      PERFORM federation_outbox_redact_purged(v_ch.id, v_fed_origin_keys);
      -- FIX (pipeline-review confirmation, F4 residual): only skip the
      -- whole channel when NEITHER messages NOR scheduled rows were
      -- destroyed. Before this, `CONTINUE WHEN v_n = 0` also skipped the
      -- act below on a scheduled-only channel (v_sched_n > 0, v_n = 0) —
      -- leaving that destruction completely unrecorded, the exact
      -- "unrecorded destruction" gap F4 was meant to close, just on the
      -- zero-message path.
      CONTINUE WHEN v_n = 0 AND v_sched_n = 0;

      -- Node destroy loop AFTER the message DELETE (Task 7 — the A2 storage-
      -- reclamation deferral). drive_node_destroy_hard is the tier-2 trash
      -- sweeper: it returns false (never raises) unless purged_at IS NOT NULL
      -- (drive_node_destroy_hard.sql:45-47). A chat-attached node is
      -- permanently LIVE (BZ175 blocks trashing it through Drive — the very
      -- immutability guard A2 built), so calling it on a live node destroys
      -- nothing. This is a deliberate, purge-only lift of the never-trash
      -- posture: BZ175 lives in the drive *reducers* (drive_node_trash etc.),
      -- not in a trigger on drive_nodes, so a direct UPDATE here is not
      -- blocked (spec-delta 1). The NOT EXISTS guard on both statements
      -- excludes any node still referenced by another chat_message_attachments
      -- row (e.g. a shared-chunk sibling attached to a message that survives
      -- this run) — its OWN version/chunk-link stays alive even though the
      -- underlying chunk's ref_count still drops when a to-be-destroyed
      -- sibling version releases its own drive_version_chunks row.
      -- drive_node_destroy_hard already deletes chat_message_attachments rows
      -- itself (:71) — defense in depth, since the CASCADE above already
      -- cleared them — so no ordering dance around the link rows is needed.
      IF v_nodes IS NOT NULL THEN
        UPDATE drive_nodes
           SET deleted_at = COALESCE(deleted_at, now()),
               purged_at  = COALESCE(purged_at, now())
         WHERE id = ANY(v_nodes)
           AND NOT EXISTS (SELECT 1 FROM chat_message_attachments a
                            WHERE a.file_node_id = drive_nodes.id);
        PERFORM drive_node_destroy_hard(n)
           FROM unnest(v_nodes) AS n
          WHERE NOT EXISTS (SELECT 1 FROM chat_message_attachments a
                             WHERE a.file_node_id = n);
        v_nodes := NULL;
      END IF;

      -- last_purged_seq only ever advances on an actual message purge
      -- (v_seq_max is NULL for a scheduled-only channel; GREATEST ignores a
      -- NULL argument so the UPDATE would be a harmless no-op regardless,
      -- but skip it outright rather than write a no-op row).
      IF v_n > 0 THEN
        UPDATE chat_channels
           SET last_purged_seq = GREATEST(last_purged_seq, v_seq_max)
         WHERE id = v_ch.id;
      END IF;

      -- Proof of disposition, not just a count (gate 3, rewritten per verify N1/N2).
      -- `destroyedElems` is a PER-ID map {messageId -> the exact digest element
      -- the anchor concatenated: id:author_id:epoch(created_at):sha256(original_body)},
      -- naturally bounded by p_batch_size. It is what lets chat_chain_anchor_verify
      -- return a HARD boolean over a purged range: the verifier recomputes the
      -- anchor digest over (surviving leaves ∪ these recovered leaves) and gets an
      -- exact match or a genuine tamper verdict. There is NO `purge_overlap` excuse
      -- field anywhere in this design — v2 had one, and it made a lawful purge and a
      -- body rewrite inside a purged range produce the IDENTICAL verdict, i.e. the
      -- cron laundered tampering. Both this act and the anchor act ride the same
      -- HMAC chain, so these leaves cannot be forged.
      --
      -- A scalar "digest over the destroyed rows" (v2) is NOT retained: nobody can
      -- recompute a pre-image over rows that no longer exist, so it proved nothing.
      -- Do not re-add it.
      --
      -- FIX 4 — destroyedElems is KEPT despite the anchor-before-purge ordering.
      -- The anchor (02:40) always runs before the purge (02:50) and retention_days
      -- > 0 forbids same-day create-and-purge, so every purged row IS anchored
      -- before it dies — but that only guarantees a GOVERNING anchor exists to
      -- reconcile against; it does NOT make the destroyed elements recoverable. The
      -- anchor commits a SCALAR digest H(elem1|...|elemN), and a one-way hash cannot
      -- yield elem_k back, so H(surviving ∪ destroyed) is uncomputable after a purge
      -- without these retained elements. Dropping destroyedElems would break FIX 1's
      -- hard-boolean reconciliation, not simplify it.
      -- ponytail: ~120 B/destroyed message, permanent (chat_audit_log is never
      -- purged, A4a↔A4b contract #3): a 2M-message purge = ~240 MB of durable
      -- digest — the deliberate price of hard-boolean reconciliation. Upgrade path
      -- if it ever bites: a per-message body-hash column would let the anchor store
      -- recoverable-enough per-leaf commitments and shrink the purge act to bare ids
      -- (the §Goal-named tamper-evidence gap); not before a regulator or a disk asks.
      -- destroyedElems is COALESCEd to '{}' for a scheduled-only purge
      -- (v_n=0 -> jsonb_object_agg over zero rows is NULL, not '{}') — the
      -- anchor verifier's destroyedElems join is keyed on message id ranges
      -- (chat_chain_anchor.sql), so an empty map here reconciles nothing and
      -- is inert, never a gap.
      PERFORM chat_access_audit(NULL, v_ch.id, 'purge.execute', 'channel', v_ch.id,
        NULL, jsonb_build_object('purgedCount', v_n, 'idFrom', v_from, 'idTo', v_to,
                                 'seqMax', v_seq_max, 'retentionDays', v_ret,
                                 'source', 'retention', 'destroyedElems', COALESCE(v_elems, '{}'::jsonb),
                                 'scheduledDestroyedCount', v_sched_n,
                                 'scheduledDestroyedIds', COALESCE(to_jsonb(v_sched_ids), '[]'::jsonb)),
        NULL, NULL);

      -- The TABLE-returning summary row (purged_count/id_from/id_to) and the
      -- batch-size bookkeeping stay scoped to an ACTUAL message purge — a
      -- scheduled-only channel gets its act (above) but never a summary row
      -- of purged_count=0 (unchanged caller contract: chat_purge_run's
      -- SUM(purged_count)/batch-exit logic and chat_purge.pg's "no run row"
      -- assertions for a message-free channel both stay correct).
      IF v_n > 0 THEN
        channel_id := v_ch.id; purged_count := v_n; id_from := v_from;
        id_to := v_to; retention_days := v_ret; RETURN NEXT;
        v_total := v_total + v_n;
        EXIT WHEN v_total >= p_batch_size;
      END IF;
    EXCEPTION WHEN SQLSTATE 'BZ194' THEN
      -- ONLY the legal-hold trigger is a "skip this channel" outcome (belt for a
      -- hold flipped mid-run). Everything else propagates loudly — catching WHEN
      -- OTHERS here would miscount real failures as holds (retention.sql:96
      -- lesson, verbatim).
      NULL;
    END;
  END LOOP;
END $$;

-- chat_purge_run() DRAINS — it does not nibble (verify N7, decided: drain, not
-- state-the-rate). Loops until the backlog is drained or a time budget is
-- spent, so a huge backlog degrades into "several nights", never into a
-- timeout that rolls back and makes ZERO progress forever.
-- ponytail: flat batch + wall-clock budget. If a deployment ever needs faster
-- drain, raise the batch — do not build a scheduler.
CREATE OR REPLACE FUNCTION chat_purge_run() RETURNS INT
LANGUAGE plpgsql AS $$
DECLARE
  v_deadline timestamptz := clock_timestamp() + interval '90 seconds';
  v_pass_ch INT; v_pass_msg INT; v_channels INT := 0; v_messages INT := 0;
BEGIN
  LOOP
    SELECT count(*)::int, COALESCE(sum(purged_count), 0)::int
      INTO v_pass_ch, v_pass_msg
      FROM chat_purge_expired(5000, FALSE);
    v_channels := v_channels + v_pass_ch;
    v_messages := v_messages + v_pass_msg;
    EXIT WHEN v_pass_msg = 0 OR clock_timestamp() >= v_deadline;
  END LOOP;
  -- audit_write(p_actor, p_action, p_target_type, p_target_id, p_before, p_after,
  --             p_ip, p_notes, p_tier) — verified audit_write.sql:4-7; p_tier is
  --             'core'|'routine' and is NOT optional.
  PERFORM audit_write(NULL, 'chat.purge_run', 'chat', NULL, NULL,
    jsonb_build_object('channels', v_channels, 'messages', v_messages, 'source', 'cron',
                       'drained', v_pass_msg = 0),
    NULL, NULL, 'core');
  RETURN v_messages;
END $$;

-- [embedded from reducers/jmap_email_submission.sql]
CREATE OR REPLACE FUNCTION jmap_email_submission_get(
  p_mailbox_id BIGINT,
  p_ids        BIGINT[] DEFAULT NULL
) RETURNS JSONB AS $$
DECLARE
  v_list JSONB;
  v_state BIGINT;
BEGIN
  SELECT jmap_email_state INTO v_state FROM mailboxes WHERE id = p_mailbox_id;

  SELECT COALESCE(jsonb_agg(row), '[]'::JSONB) INTO v_list
  FROM (
    SELECT jsonb_build_object(
      'id', (sa.payload->>'message_id'),
      'emailId', (sa.payload->>'message_id'),
      'undoStatus', 'pending',
      'sendAt', sa.fire_at,
      'undoSendBefore', CASE WHEN sa.payload->>'undo' = 'true' THEN sa.fire_at ELSE NULL END
    ) AS row
    FROM scheduled_actions sa
    WHERE sa.mailbox_id = p_mailbox_id          -- R1: ownership
      AND sa.action_kind = 'send'
      AND sa.status IN ('pending', 'enqueued')
      AND (p_ids IS NULL OR (sa.payload->>'message_id')::BIGINT = ANY(p_ids))
    ORDER BY sa.fire_at ASC
  ) sub;

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'state', COALESCE(v_state, 0)::TEXT,
    'list', v_list,
    'notFound', '[]'::JSONB
  );
END;
$$ LANGUAGE plpgsql;

-- jmap_email_submission_query: return ids of pending/deferred submissions.
-- Ordered by sendAt ascending. Filters strictly by p_mailbox_id (R1).
-- p_filter is reserved (accepted for JMAP shape compatibility, unused in wave-1).
CREATE OR REPLACE FUNCTION jmap_email_submission_query(
  p_mailbox_id BIGINT,
  p_filter     JSONB DEFAULT NULL,
  p_position   INT   DEFAULT 0,
  p_limit      INT   DEFAULT 50
) RETURNS JSONB AS $$
DECLARE
  v_ids   JSONB;
  v_total BIGINT;
  v_state BIGINT;
BEGIN
  SELECT jmap_email_state INTO v_state FROM mailboxes WHERE id = p_mailbox_id;

  SELECT COALESCE(jsonb_agg(mid ORDER BY fire_at ASC), '[]'::JSONB), count(*)
  INTO v_ids, v_total
  FROM (
    SELECT (sa.payload->>'message_id') AS mid, sa.fire_at
    FROM scheduled_actions sa
    WHERE sa.mailbox_id = p_mailbox_id           -- R1: ownership
      AND sa.action_kind = 'send'
      AND sa.status IN ('pending', 'enqueued')
    ORDER BY sa.fire_at ASC
    OFFSET GREATEST(p_position, 0)
    LIMIT LEAST(GREATEST(p_limit, 1), 256)
  ) sub;

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'queryState', COALESCE(v_state, 0)::TEXT,
    'canCalculateChanges', FALSE,
    'position', GREATEST(p_position, 0),
    'total', v_total,
    'ids', v_ids
  );
END;
$$ LANGUAGE plpgsql;

-- [embedded from reducers/reminders_scan.sql]
CREATE OR REPLACE FUNCTION scan_due_reminders()
RETURNS SETOF UUID AS $$
DECLARE
    v_rec      RECORD;
    v_fire     TIMESTAMPTZ;
    v_payload  JSONB;
    v_id       UUID;
    v_has_flag BOOLEAN;
BEGIN
    -- ── Event VALARM (absolute triggers only) ──
    FOR v_rec IN
        SELECT e.id AS source_id, e.title, c.mailbox_id, alarm.value AS alarm
        FROM calendar_events e
        JOIN calendars c ON c.id = e.calendar_id
        CROSS JOIN LATERAL jsonb_array_elements(COALESCE(e.valarm, '[]'::JSONB)) AS alarm(value)
        WHERE e.valarm IS NOT NULL
    LOOP
        -- Parse the trigger as an absolute timestamp; skip relative/unparseable.
        BEGIN
            v_fire := (v_rec.alarm->>'trigger')::TIMESTAMPTZ;
        EXCEPTION WHEN OTHERS THEN
            CONTINUE;
        END;

        IF v_fire IS NULL OR v_fire > now() THEN
            CONTINUE;
        END IF;

        v_payload := jsonb_build_object(
            'source_type', 'event', 'source_id', v_rec.source_id,
            'mailbox_id', v_rec.mailbox_id, 'fire_at', v_fire, 'title', v_rec.title);

        IF NOT EXISTS (
            SELECT 1 FROM scheduled_actions
            WHERE action_kind = 'remind'
              AND mailbox_id = v_rec.mailbox_id
              AND status IN ('pending','enqueued','processing')
              AND payload @> jsonb_build_object('source_type','event','source_id',v_rec.source_id,'fire_at',v_fire)
        ) AND NOT EXISTS (
            -- Already fired (ledger row exists): never re-enqueue. The ledger UNIQUE
            -- is (mailbox_id, source_type, source_id, fire_at); without this guard a
            -- done action no longer blocks and the queue grows one dead row/minute.
            SELECT 1 FROM reminders
            WHERE mailbox_id = v_rec.mailbox_id
              AND source_type = 'event'
              AND source_id = v_rec.source_id
              AND fire_at = v_fire
        ) THEN
            v_id := enqueue_scheduled_action('remind', v_fire, v_payload, v_rec.mailbox_id);
            RETURN NEXT v_id;
        END IF;
    END LOOP;

    -- ── Task reminder_at ──
    FOR v_rec IN
        SELECT t.id AS source_id, t.title, t.mailbox_id, t.reminder_at AS fire_at
        FROM tasks t
        WHERE t.reminder_at IS NOT NULL
          AND t.reminder_at <= now()
          AND t.status <> 'completed'
    LOOP
        v_payload := jsonb_build_object(
            'source_type', 'task', 'source_id', v_rec.source_id,
            'mailbox_id', v_rec.mailbox_id, 'fire_at', v_rec.fire_at, 'title', v_rec.title);

        IF NOT EXISTS (
            SELECT 1 FROM scheduled_actions
            WHERE action_kind = 'remind'
              AND mailbox_id = v_rec.mailbox_id
              AND status IN ('pending','enqueued','processing')
              AND payload @> jsonb_build_object('source_type','task','source_id',v_rec.source_id,'fire_at',v_rec.fire_at)
        ) AND NOT EXISTS (
            -- Already fired (ledger row exists): never re-enqueue. tasks.reminder_at
            -- keeps matching until cleared, so the ledger is the fire-once gate here.
            SELECT 1 FROM reminders
            WHERE mailbox_id = v_rec.mailbox_id
              AND source_type = 'task'
              AND source_id = v_rec.source_id
              AND fire_at = v_rec.fire_at
        ) THEN
            v_id := enqueue_scheduled_action('remind', v_rec.fire_at, v_payload, v_rec.mailbox_id);
            RETURN NEXT v_id;
        END IF;
    END LOOP;

    -- ── Flagged messages past due (A2) — GUARDED until messages.flag_due_at lands ──
    SELECT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'messages' AND column_name = 'flag_due_at'
    ) INTO v_has_flag;

    IF v_has_flag THEN
        -- A2-dependent branch. Enqueue a `remind` per flagged message past flag_due_at.
        -- Implemented with dynamic SQL so this file loads before A2 adds the column.
        FOR v_id IN
            EXECUTE $dyn$
                SELECT enqueue_scheduled_action('remind', m.flag_due_at,
                    jsonb_build_object('source_type','flag','source_id',m.id,
                        'mailbox_id',m.mailbox_id,'fire_at',m.flag_due_at,'title',m.subject),
                    m.mailbox_id)
                FROM messages m
                WHERE m.flag_due_at IS NOT NULL AND m.flag_due_at <= now()
                  AND NOT EXISTS (
                    SELECT 1 FROM scheduled_actions sa
                    WHERE sa.action_kind='remind' AND sa.mailbox_id = m.mailbox_id
                      AND sa.status IN ('pending','enqueued','processing')
                      AND sa.payload @> jsonb_build_object('source_type','flag','source_id',m.id,'fire_at',m.flag_due_at))
                  AND NOT EXISTS (
                    SELECT 1 FROM reminders r
                    WHERE r.mailbox_id = m.mailbox_id AND r.source_type='flag'
                      AND r.source_id = m.id AND r.fire_at = m.flag_due_at)
            $dyn$
        LOOP
            RETURN NEXT v_id;
        END LOOP;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- [embedded from reducers/continuity_recovery_receipt_context.sql]
CREATE OR REPLACE FUNCTION continuity_recovery_receipt_context(
    p_mailbox_id bigint,
    p_message_ids bigint[],
    p_boot_epoch uuid
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public
AS $$
DECLARE
    v_context jsonb;
    v_list jsonb;
BEGIN
    IF p_mailbox_id IS NULL OR p_boot_epoch IS NULL OR p_message_ids IS NULL OR
       cardinality(p_message_ids)=0 OR cardinality(p_message_ids)>64 OR
       NULLIF(current_setting('app.current_mailbox_id',true),'')::bigint IS DISTINCT FROM p_mailbox_id THEN
        RAISE EXCEPTION 'recovery receipt request is invalid'
            USING ERRCODE='BZ251',HINT='{"type":"continuity_receipt_invalid"}';
    END IF;
    v_context := continuity_context_issue(p_mailbox_id,p_boot_epoch);
    SELECT COALESCE(jsonb_agg(jsonb_build_object(
        'id',m.id::text,
        'rawRef',m.raw_ref,
        'receivedAt',m.received_at,
        'eligibility',CASE WHEN loc.name='Sent' THEN 'sent-terminal' ELSE 'received' END,
        'attachments',COALESCE((
            SELECT jsonb_agg(jsonb_build_object(
                'blobId',ma.blob_sha256,'sha256',ma.blob_sha256,
                'size',ma.size_bytes::text,'role',ma.disposition
            ) ORDER BY ma.id)
            FROM message_attachments ma
            WHERE ma.message_id=m.id AND ma.received_at=m.received_at
        ),'[]'::jsonb)
    ) ORDER BY requested.ordinality),'[]'::jsonb)
      INTO v_list
      FROM unnest(p_message_ids) WITH ORDINALITY AS requested(id,ordinality)
      JOIN messages m ON m.id=requested.id AND m.mailbox_id=p_mailbox_id
      LEFT JOIN LATERAL (
          SELECT t.name
          FROM message_tags mt JOIN tags t ON t.id=mt.tag_id
          WHERE mt.message_id=m.id AND mt.received_at=m.received_at
            AND t.mailbox_id=p_mailbox_id AND t.exclusive_group='location'
          LIMIT 1
      ) loc ON true
     WHERE COALESCE(loc.name,'') NOT IN ('Drafts','Scheduled')
       AND NOT EXISTS (
           SELECT 1 FROM scheduled_actions sa
           WHERE sa.mailbox_id=p_mailbox_id
             AND sa.status IN ('pending','enqueued','processing')
             AND sa.payload @> jsonb_build_object('message_id',m.id)
       )
       AND (loc.name IS DISTINCT FROM 'Sent' OR NOT EXISTS (
           SELECT 1 FROM outbound_queue q
           WHERE q.mailbox_id=p_mailbox_id AND q.raw_ref=m.raw_ref
             AND q.status IN ('pending','sending','deferred')
       ));
    RETURN jsonb_build_object('context',v_context,'list',v_list);
END;
$$;

REVOKE ALL ON FUNCTION continuity_recovery_receipt_context(bigint,bigint[],uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION continuity_recovery_receipt_context(bigint,bigint[],uuid) TO setjoin_app,setjoin_worker;
SELECT apply_worker_ownership('continuity_recovery_receipt_context(bigint,bigint[],uuid)'::regprocedure);

-- [embedded from reducers/chat_ediscovery_read.sql]
CREATE OR REPLACE FUNCTION chat_ediscovery_read(
    p_actor BIGINT, p_case_id BIGINT, p_channel_id BIGINT,
    p_before_id BIGINT DEFAULT NULL, p_limit INT DEFAULT 100
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_status          TEXT;
  v_lim             INT;
  v_messages        JSONB;
  v_sched           JSONB;
  v_purge_acts      JSONB;
  v_last_purged_seq BIGINT;
  v_count           INT;
  v_search_id       BIGINT;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key = 'feature.chat_compliance'), FALSE) THEN
    RAISE EXCEPTION 'chat compliance is disabled' USING ERRCODE='BZ197',
      HINT='{"type":"invalidArguments","detail":"compliance disabled"}';
  END IF;
  SELECT status INTO v_status FROM ediscovery_cases WHERE id = p_case_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'case % not found', p_case_id USING ERRCODE='BZ197',
      HINT='{"type":"invalidArguments","detail":"case not found"}';
  END IF;
  IF v_status <> 'active' THEN
    RAISE EXCEPTION 'case % is not open', p_case_id USING ERRCODE='BZ198',
      HINT='{"type":"stateMismatch","detail":"case is not open"}';
  END IF;
  SELECT last_purged_seq INTO v_last_purged_seq FROM chat_channels WHERE id = p_channel_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'channel % not found', p_channel_id USING ERRCODE='BZ197',
      HINT='{"type":"invalidArguments","detail":"channel not found"}';
  END IF;
  v_lim := LEAST(GREATEST(COALESCE(p_limit, 100), 1), 500);

  -- The window must be limited BEFORE aggregation — LIMIT on the outer
  -- aggregate query would apply to the single aggregated row, not the input
  -- rows, so the id-keyset window is a subquery.
  SELECT COALESCE(jsonb_agg(chat_ediscovery_message_json(sub.id) ORDER BY sub.id DESC), '[]'::jsonb)
    INTO v_messages
    FROM (
      SELECT m.id FROM chat_messages m
       WHERE m.channel_id = p_channel_id
         AND (p_before_id IS NULL OR m.id < p_before_id)
       ORDER BY m.id DESC
       LIMIT v_lim
    ) sub;
  v_count := jsonb_array_length(v_messages);

  v_sched := '[]'::jsonb;
  IF p_before_id IS NULL THEN
    -- review F9: clamped to v_lim, the SAME cap the message window uses
    -- (previously unbounded).
    SELECT COALESCE(jsonb_agg(jsonb_build_object(
             'scheduledActionId', sub.id, 'channelId', p_channel_id,
             'authorId', sub.author_id,
             'status', sub.status, 'fireAt', sub.fire_at,
             'body', sub.body) ORDER BY sub.id DESC), '[]'::jsonb)
      INTO v_sched
      FROM (
        SELECT sa.id, (sa.payload->>'userId')::bigint AS author_id,
               sa.status, sa.fire_at, sa.payload->>'body' AS body
          FROM scheduled_actions sa
         WHERE sa.action_kind = 'chat_send'
           AND sa.status IN ('pending', 'enqueued', 'failed')          -- contract #7
           AND (sa.payload->>'channelId')::bigint = p_channel_id
         ORDER BY sa.id DESC
         LIMIT v_lim
      ) sub;
  END IF;

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
           'actId', pa.id, 'idFrom', (pa.after_state->>'idFrom')::bigint,
           'idTo', (pa.after_state->>'idTo')::bigint,
           'purgedCount', (pa.after_state->>'purgedCount')::int) ORDER BY pa.id), '[]'::jsonb)
    INTO v_purge_acts
    FROM chat_audit_log pa
   WHERE pa.channel_id = p_channel_id AND pa.action = 'purge.execute';

  INSERT INTO chat_ediscovery_searches (case_id, kind, query, result_count, executed_by)
  VALUES (p_case_id, 'read',
          jsonb_build_object('channelId', p_channel_id, 'beforeId', p_before_id, 'limit', v_lim),
          v_count, p_actor)
  RETURNING id INTO v_search_id;

  PERFORM chat_access_audit(p_actor, p_channel_id, 'search.run', 'channel', p_channel_id, NULL,
    jsonb_build_object('caseId', p_case_id, 'searchId', v_search_id,
                       'range', jsonb_build_object('beforeId', p_before_id, 'limit', v_lim),
                       'resultCount', v_count),
    NULL, NULL);

  RETURN jsonb_build_object('channelId', p_channel_id, 'lastPurgedSeq', v_last_purged_seq,
                            'purgeActs', v_purge_acts, 'scheduledRows', v_sched,
                            'messages', v_messages);
END;
$$;

SELECT apply_worker_ownership('chat_ediscovery_read(BIGINT, BIGINT, BIGINT, BIGINT, INT)'::regprocedure);

-- [embedded from reducers/chat_ediscovery_search.sql]
CREATE OR REPLACE FUNCTION chat_ediscovery_search(
    p_actor BIGINT, p_case_id BIGINT, p_query JSONB,
    p_before_id BIGINT DEFAULT NULL,
    p_use_trgm BOOLEAN DEFAULT FALSE,
    p_limit INT DEFAULT 50
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_status TEXT; v_terms TEXT; v_lim INT;
  v_channel_ids BIGINT[]; v_author BIGINT; v_from TIMESTAMPTZ; v_to TIMESTAMPTZ;
  v_hits JSONB; v_sched JSONB; v_count INT := 0; v_search_id BIGINT; v_rec RECORD;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key = 'feature.chat_compliance'), FALSE) THEN
    RAISE EXCEPTION 'chat compliance is disabled' USING ERRCODE='BZ197',
      HINT='{"type":"invalidArguments","detail":"compliance disabled"}';
  END IF;
  SELECT status INTO v_status FROM ediscovery_cases WHERE id = p_case_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'case % not found', p_case_id USING ERRCODE='BZ197',
      HINT='{"type":"invalidArguments","detail":"case not found"}';
  END IF;
  IF v_status <> 'active' THEN
    RAISE EXCEPTION 'case % is not open', p_case_id USING ERRCODE='BZ198',
      HINT='{"type":"stateMismatch","detail":"case is not open"}';
  END IF;
  v_terms := btrim(coalesce(p_query->>'terms', ''));
  IF v_terms = '' THEN
    RAISE EXCEPTION 'query terms required' USING ERRCODE='BZ197',
      HINT='{"type":"invalidArguments","detail":"query terms required"}';
  END IF;
  IF p_query ? 'channelIds' THEN
    v_channel_ids := ARRAY(SELECT jsonb_array_elements_text(p_query->'channelIds')::bigint);
  END IF;
  v_author := (p_query->>'authorId')::bigint;
  v_from   := (p_query->>'dateFrom')::timestamptz;
  v_to     := (p_query->>'dateTo')::timestamptz;
  v_lim    := LEAST(GREATEST(COALESCE(p_limit, 50), 1), 200);

  -- Pillar C1 Task 4 (N1 eDiscovery-attribution fix): every leg now also
  -- carries federated_sender_addr — a federated inbound row (Task 4's
  -- federation_apply_chat) has author_id NULL, so without this the hit would
  -- silently attribute to nobody. authorId itself was ALREADY null-safe
  -- (jsonb_build_object projects a SQL NULL as JSON null with no CASE
  -- needed) — the actual gap was the missing federated identity, not a
  -- crash risk in this file.
  WITH matched AS (
    SELECT m.id, m.channel_id, m.author_id, m.federated_sender_addr, m.created_at,
           (m.deleted_at IS NOT NULL) AS is_deleted, m.body AS matched_text,
           'body' AS matched_in
      FROM chat_messages m
     WHERE (CASE WHEN p_use_trgm THEN m.body ILIKE '%' || v_terms || '%'
                 ELSE m.search_tsv @@ plainto_tsquery('simple', v_terms) END)
    UNION ALL
    SELECT m.id, m.channel_id, m.author_id, m.federated_sender_addr, m.created_at,
           (m.deleted_at IS NOT NULL), rv.prior_body, 'revision'
      FROM chat_message_revisions rv
      JOIN chat_messages m ON m.id = rv.message_id
     WHERE (CASE WHEN p_use_trgm THEN rv.prior_body ILIKE '%' || v_terms || '%'
                 ELSE to_tsvector('simple', rv.prior_body) @@ plainto_tsquery('simple', v_terms) END)
    UNION ALL
    SELECT m.id, m.channel_id, m.author_id, m.federated_sender_addr, m.created_at,
           (m.deleted_at IS NOT NULL), a.filename, 'filename'
      FROM chat_message_attachments a
      JOIN chat_messages m ON m.id = a.message_id
     WHERE a.filename ILIKE '%' || v_terms || '%'
  ), filtered AS (
    SELECT * FROM matched
     WHERE (v_channel_ids IS NULL OR channel_id = ANY(v_channel_ids))
       AND (v_author IS NULL OR author_id = v_author)
       AND (v_from IS NULL OR created_at >= v_from)
       AND (v_to   IS NULL OR created_at <= v_to)
       AND (p_before_id IS NULL OR id < p_before_id)
  ), grouped AS (
    -- review F6: array_agg(matched_text) had no ORDER BY — [1] picked
    -- whichever leg's row the planner happened to visit first, a
    -- nondeterministic excerpt for a message matched on multiple legs.
    -- ORDER BY matched_in makes it stable ('body' < 'filename' < 'revision').
    SELECT id, channel_id, author_id, federated_sender_addr, created_at, is_deleted,
           array_agg(DISTINCT matched_in) AS matched_in,
           (array_agg(matched_text ORDER BY matched_in))[1] AS excerpt
      FROM filtered
     GROUP BY id, channel_id, author_id, federated_sender_addr, created_at, is_deleted
     ORDER BY id DESC
     LIMIT v_lim
  )
  SELECT COALESCE(jsonb_agg(jsonb_build_object(
           'messageId', id, 'channelId', channel_id, 'authorId', author_id,
           'federatedSenderAddr', federated_sender_addr,
           'createdAt', created_at, 'deleted', is_deleted,
           'matchedIn', to_jsonb(matched_in), 'excerpt', left(excerpt, 300)
         ) ORDER BY id DESC), '[]'::jsonb),
         COALESCE(count(*), 0)
    INTO v_hits, v_count
    FROM grouped;

  v_sched := '[]'::jsonb;
  IF p_before_id IS NULL THEN
    -- review F9: clamped to v_lim, the SAME cap message hits use (previously
    -- unbounded — a busy scheduler could jsonb_agg an unbounded row set).
    SELECT COALESCE(jsonb_agg(jsonb_build_object(
             'scheduledActionId', sub.id,
             'channelId', sub.channel_id,
             'authorId',  sub.author_id,
             'status', sub.status, 'fireAt', sub.fire_at,
             'excerpt', left(sub.body, 300)) ORDER BY sub.id DESC), '[]'::jsonb)
      INTO v_sched
      FROM (
        SELECT sa.id, (sa.payload->>'channelId')::bigint AS channel_id,
               (sa.payload->>'userId')::bigint AS author_id,
               sa.status, sa.fire_at, sa.payload->>'body' AS body
          FROM scheduled_actions sa
         WHERE sa.action_kind = 'chat_send'
           AND sa.status IN ('pending', 'enqueued', 'failed')          -- contract #7
           AND (CASE WHEN p_use_trgm THEN sa.payload->>'body' ILIKE '%' || v_terms || '%'
                     ELSE to_tsvector('simple', sa.payload->>'body') @@ plainto_tsquery('simple', v_terms) END)
           AND (v_channel_ids IS NULL OR (sa.payload->>'channelId')::bigint = ANY(v_channel_ids))
           AND (v_author IS NULL OR (sa.payload->>'userId')::bigint = v_author)
         ORDER BY sa.id DESC
         LIMIT v_lim
      ) sub;
  END IF;

  v_count := v_count + jsonb_array_length(v_sched);
  INSERT INTO chat_ediscovery_searches (case_id, kind, query, result_count, executed_by)
  VALUES (p_case_id, 'search', p_query, v_count, p_actor)
  RETURNING id INTO v_search_id;

  FOR v_rec IN
    SELECT DISTINCT (e->>'channelId')::bigint AS channel_id
      FROM jsonb_array_elements(v_hits || v_sched) e
  LOOP
    PERFORM chat_access_audit(p_actor, v_rec.channel_id, 'search.run', 'channel',
      v_rec.channel_id, NULL,
      jsonb_build_object('caseId', p_case_id, 'searchId', v_search_id,
                         'query', p_query, 'resultCount', v_count),
      NULL, NULL);
  END LOOP;

  RETURN jsonb_build_object('searchId', v_search_id, 'hits', v_hits,
                            'scheduledHits', v_sched, 'resultCount', v_count);
END;
$$;

SELECT apply_worker_ownership('chat_ediscovery_search(BIGINT, BIGINT, JSONB, BIGINT, BOOLEAN, INT)'::regprocedure);

-- [embedded from reducers/rules_apply_retroactive.sql]
CREATE OR REPLACE FUNCTION rules_apply_retroactive(
    p_mailbox_id BIGINT,
    p_rule_id    BIGINT DEFAULT NULL,
    p_window     TEXT DEFAULT '90d'
) RETURNS UUID AS $$
DECLARE
    v_dedup    TEXT;
    v_existing UUID;
    v_id       UUID;
BEGIN
    IF p_mailbox_id IS NULL THEN
        RAISE EXCEPTION 'mailbox is required'
            USING ERRCODE = 'BZ120', HINT = jsonb_build_object('type','mailbox_required')::TEXT;
    END IF;

    IF p_window IS NULL OR p_window NOT IN ('90d','1y','all') THEN
        RAISE EXCEPTION 'invalid retro window %', p_window
            USING ERRCODE = 'BZ120',
                  HINT = jsonb_build_object('type','bad_window','window',p_window)::TEXT;
    END IF;

    -- Single-rule apply: the rule must be owned by this mailbox (R1) and be a
    -- per-mailbox (non-transport) rule — a user cannot retro-apply someone else's
    -- rule nor an org-wide transport rule through this self-service path.
    IF p_rule_id IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM rules
            WHERE id = p_rule_id
              AND mailbox_id = p_mailbox_id
              AND is_transport_rule = FALSE
        ) THEN
            RAISE EXCEPTION 'rule % not found for mailbox %', p_rule_id, p_mailbox_id
                USING ERRCODE = 'BZ121', HINT = jsonb_build_object('type','rule_not_found')::TEXT;
        END IF;
    END IF;

    v_dedup := 'rules_retro:' || p_mailbox_id || ':' || COALESCE(p_rule_id::TEXT, 'all');

    -- Already in flight for this (mailbox, rule) → hand back the existing action.
    SELECT id INTO v_existing
    FROM scheduled_actions
    WHERE dedup_key = v_dedup
      AND mailbox_id = p_mailbox_id
      AND status IN ('pending','enqueued','processing')
    LIMIT 1;
    IF v_existing IS NOT NULL THEN
        RETURN v_existing;
    END IF;

    -- Free the unique dedup_key from any prior terminal run so a fresh sweep can enqueue.
    DELETE FROM scheduled_actions
    WHERE dedup_key = v_dedup
      AND mailbox_id = p_mailbox_id
      AND status IN ('done','failed');

    INSERT INTO scheduled_actions (action_kind, fire_at, payload, mailbox_id, dedup_key)
    VALUES ('rules_retro', now(),
            jsonb_build_object('rule_id', p_rule_id, 'window', p_window),
            p_mailbox_id, v_dedup)
    RETURNING id INTO v_id;

    RETURN v_id;
END;
$$ LANGUAGE plpgsql;

-- [embedded from reducers/queue_read.sql]
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
      WHEN 'enqueued'   THEN 'active'
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

-- [embedded from reducers/health_check.sql]
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
  v_wq_dlq           BIGINT;
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
          'work_queue_dead_letters')
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

INSERT INTO public.schema_migrations (version, applied_at)
VALUES (290, now())
ON CONFLICT (version) DO NOTHING;
