-- V299__search_ediscovery_purge_and_ha_leader.sql — Wave 3.3 (#558):
-- Additive eDiscovery provenance column (`ediscovery_searches.search_provenance`),
-- SKIP LOCKED HA single-writer search leader lease table (`public.search_leader_leases`)
-- and worker-only reducers, atomic eDiscovery commit+audit reducers, plus gated
-- lawful-purge physical eviction trigger hooks (including child tables).
--
-- Non-negotiable invariants:
--   1. Zero `blobs` columns added; zero `feature_toggles` rows added.
--   2. `search_leader_leases` is a worker-only `system_only` table with
--      ENABLE + FORCE ROW LEVEL SECURITY, ZERO policies (deny-all to `setjoin_app`
--      and `PUBLIC`), owned by `setjoin_owner`, with table grants restricted to
--      `setjoin_worker` (restated in `scripts/provision-roles.sql`).
--   3. All worker-only functions enforce `(rolbypassrls OR rolsuper)` (`BZ003`),
--      use `SET search_path = pg_catalog, public, pg_temp`, revoke `PUBLIC`/`setjoin_app`,
--      and grant strictly to `setjoin_worker`.
--   4. `search_purge_evict_trg_fn()` is owned by `setjoin_worker` (`SECURITY DEFINER`)
--      using transient `GRANT/REVOKE CREATE ON SCHEMA public TO setjoin_worker` so
--      non-superuser `setjoin_owner` replay succeeds with zero drift on existing
--      `SECURITY DEFINER` functions, and is strictly inert while `search_index_watermarks`
--      is empty (Tier-2 search OFF).

BEGIN;

-- 1. Strictly additive eDiscovery provenance JSONB column on ediscovery_searches.
ALTER TABLE public.ediscovery_searches
    ADD COLUMN IF NOT EXISTS search_provenance jsonb;

-- 2. Worker-only HA single-writer search leader lease table.
CREATE TABLE IF NOT EXISTS public.search_leader_leases (
    lease_key      text        PRIMARY KEY,
    holder_node_id text        NOT NULL,
    rpc_url        text        NOT NULL,
    epoch          bigint      NOT NULL DEFAULT 0 CHECK (epoch >= 0),
    generation     bigint      NOT NULL DEFAULT 0 CHECK (generation >= 0),
    fencing_token  bigint      NOT NULL DEFAULT 1 CHECK (fencing_token >= 1),
    leased_until   timestamptz NOT NULL,
    updated_at     timestamptz NOT NULL DEFAULT now()
);

-- 3. Deny-all FORCE RLS + owner/worker privilege posture on search_leader_leases.
ALTER TABLE public.search_leader_leases ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.search_leader_leases FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_owner') THEN
        ALTER TABLE public.search_leader_leases OWNER TO setjoin_owner;
    END IF;
    REVOKE ALL ON TABLE public.search_leader_leases FROM PUBLIC;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
        REVOKE ALL ON TABLE public.search_leader_leases FROM setjoin_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
        REVOKE ALL ON TABLE public.search_leader_leases FROM setjoin_worker;
        GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.search_leader_leases TO setjoin_worker;
    END IF;
END
$$;

-- 4. Worker-only HA leader, eDiscovery atomic completion, & purge eviction reducers (verbatim copy of reducers/search_ha_leader.sql).
-- search_ha_leader.sql — Wave 3.3 (#558):
-- SKIP LOCKED HA single-writer search leader lease reducers, deterministic
-- chat revision doc ID helper, lawful purge eviction WorkQueue enqueue helper,
-- and gated lawful purge eviction trigger function.
--
-- Security posture:
--   - search_leader_try_acquire, search_leader_heartbeat, search_leader_release,
--     search_leader_current, and search_purge_enqueue are worker-only
--     SECURITY INVOKER with SET search_path = pg_catalog, public, pg_temp and
--     enforce (rolbypassrls OR rolsuper) raising BZ003.
--   - search_chat_revision_doc_id is pure IMMUTABLE SQL (SECURITY INVOKER)
--     using built-in pg_catalog.sha256 (matching Rust chat_revision_doc_id).
--   - search_purge_evict_trg_fn is a narrow worker-owned SECURITY DEFINER
--     trigger function (OWNER TO setjoin_worker, SET search_path = pg_catalog,
--     public, pg_temp) gated on EXISTS (SELECT 1 FROM search_index_watermarks
--     LIMIT 1) so Tier-2-OFF installations incur zero purge-eviction queue writes.
--   - EXECUTE is revoked from PUBLIC and setjoin_app and granted strictly to
--     setjoin_worker (restated in scripts/provision-roles.sql).

-- Deterministic strictly-negative bigint doc ID matching Rust
-- `setjoin_search::chat_revision_doc_id(i64)`.
CREATE OR REPLACE FUNCTION search_chat_revision_doc_id(p_message_id bigint)
RETURNS bigint
LANGUAGE sql
IMMUTABLE
STRICT
SECURITY INVOKER
SET search_path = pg_catalog, public, pg_temp
AS $$
    WITH d AS (
        SELECT pg_catalog.sha256(
            pg_catalog.convert_to('chat_message_revisions:' || p_message_id::text, 'UTF8')
        ) AS h
    ),
    u63 AS (
        SELECT (
            ((pg_catalog.get_byte(h, 0) & 127)::bigint << 56) |
            (pg_catalog.get_byte(h, 1)::bigint << 48) |
            (pg_catalog.get_byte(h, 2)::bigint << 40) |
            (pg_catalog.get_byte(h, 3)::bigint << 32) |
            (pg_catalog.get_byte(h, 4)::bigint << 24) |
            (pg_catalog.get_byte(h, 5)::bigint << 16) |
            (pg_catalog.get_byte(h, 6)::bigint << 8)  |
            pg_catalog.get_byte(h, 7)::bigint
        ) AS pos
        FROM d
    )
    SELECT -GREATEST(pos, 1::bigint) FROM u63;
$$;

-- Acquire or renew the singleton HA single-writer search leader lease
-- ('search_writer') using FOR UPDATE SKIP LOCKED.
-- Increments fencing_token strictly monotonically on every takeover.
CREATE OR REPLACE FUNCTION search_leader_try_acquire(
    p_node_id    text,
    p_rpc_url    text,
    p_lease_secs integer DEFAULT 30
)
RETURNS TABLE (
    acquired       boolean,
    holder_node_id text,
    rpc_url        text,
    fencing_token  bigint,
    leased_until   timestamptz
)
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    v_lease_secs integer;
    v_until      timestamptz;
    v_row        public.search_leader_leases%ROWTYPE;
    v_snap       public.search_leader_leases%ROWTYPE;
    v_inserted   boolean := false;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
         WHERE rolname = current_user
           AND (rolbypassrls OR rolsuper)
    ) THEN
        RAISE EXCEPTION 'search_leader_try_acquire: caller role % lacks BYPASSRLS privilege', current_user
            USING ERRCODE = 'BZ003',
                  HINT = '{"type":"forbidden","reason":"bypassrls_required"}'::text;
    END IF;

    IF p_node_id IS NULL OR btrim(p_node_id) = '' THEN
        RAISE EXCEPTION 'search_leader_try_acquire: p_node_id must be non-empty'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"node_id"}'::text;
    END IF;
    IF p_rpc_url IS NULL THEN
        RAISE EXCEPTION 'search_leader_try_acquire: p_rpc_url must not be null'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"rpc_url"}'::text;
    END IF;
    IF p_lease_secs IS NULL OR p_lease_secs < 1 OR p_lease_secs > 3600 THEN
        RAISE EXCEPTION 'search_leader_try_acquire: p_lease_secs must be between 1 and 3600'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"lease_secs"}'::text;
    END IF;

    v_lease_secs := p_lease_secs;
    v_until := now() + make_interval(secs => v_lease_secs);

    -- Ensure singleton row exists without blocking on concurrent first-boot racers.
    INSERT INTO public.search_leader_leases (
        lease_key,
        holder_node_id,
        rpc_url,
        epoch,
        generation,
        fencing_token,
        leased_until,
        updated_at
    )
    VALUES (
        'search_writer',
        p_node_id,
        p_rpc_url,
        0,
        0,
        1,
        v_until,
        now()
    )
    ON CONFLICT (lease_key) DO NOTHING;

    GET DIAGNOSTICS v_inserted = ROW_COUNT;
    IF v_inserted THEN
        RETURN QUERY
        SELECT true, p_node_id, p_rpc_url, 1::bigint, v_until;
        RETURN;
    END IF;

    -- Lock singleton row non-blockingly via SKIP LOCKED.
    SELECT * INTO v_row
      FROM public.search_leader_leases l
     WHERE l.lease_key = 'search_writer'
       FOR UPDATE SKIP LOCKED;

    IF NOT FOUND THEN
        -- Another transaction holds the row lock right now; report current visible holder.
        SELECT * INTO v_snap
          FROM public.search_leader_leases l
         WHERE l.lease_key = 'search_writer';
        RETURN QUERY
        SELECT false,
               COALESCE(v_snap.holder_node_id, ''),
               COALESCE(v_snap.rpc_url, ''),
               COALESCE(v_snap.fencing_token, 0::bigint),
               COALESCE(v_snap.leased_until, now());
        RETURN;
    END IF;

    IF v_row.leased_until <= now() THEN
        -- Expired or released lease: ALWAYS increment fencing_token monotonically,
        -- even when the same node re-acquires after a pause or partition.
        UPDATE public.search_leader_leases l
           SET holder_node_id = p_node_id,
               rpc_url = p_rpc_url,
               fencing_token = l.fencing_token + 1,
               leased_until = v_until,
               updated_at = now()
         WHERE l.lease_key = 'search_writer'
        RETURNING * INTO v_row;

        RETURN QUERY
        SELECT true, v_row.holder_node_id, v_row.rpc_url, v_row.fencing_token, v_row.leased_until;
        RETURN;
    END IF;

    IF v_row.holder_node_id = p_node_id THEN
        -- Active unexpired lease held by the same node: renew in place.
        UPDATE public.search_leader_leases l
           SET rpc_url = p_rpc_url,
               leased_until = v_until,
               updated_at = now()
         WHERE l.lease_key = 'search_writer'
        RETURNING * INTO v_row;

        RETURN QUERY
        SELECT true, v_row.holder_node_id, v_row.rpc_url, v_row.fencing_token, v_row.leased_until;
        RETURN;
    END IF;

    RETURN QUERY
    SELECT false, v_row.holder_node_id, v_row.rpc_url, v_row.fencing_token, v_row.leased_until;
END;
$$;

-- Renew an active HA search leader lease strictly when holder_node_id AND
-- fencing_token match AND the lease has not yet expired.
CREATE OR REPLACE FUNCTION search_leader_heartbeat(
    p_node_id       text,
    p_fencing_token bigint,
    p_epoch         bigint,
    p_generation    bigint,
    p_lease_secs    integer DEFAULT 30
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    v_lease_secs integer;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
         WHERE rolname = current_user
           AND (rolbypassrls OR rolsuper)
    ) THEN
        RAISE EXCEPTION 'search_leader_heartbeat: caller role % lacks BYPASSRLS privilege', current_user
            USING ERRCODE = 'BZ003',
                  HINT = '{"type":"forbidden","reason":"bypassrls_required"}'::text;
    END IF;

    IF p_node_id IS NULL OR btrim(p_node_id) = '' THEN
        RAISE EXCEPTION 'search_leader_heartbeat: p_node_id must be non-empty'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"node_id"}'::text;
    END IF;
    IF p_fencing_token IS NULL OR p_fencing_token < 1 THEN
        RAISE EXCEPTION 'search_leader_heartbeat: p_fencing_token must be positive'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"fencing_token"}'::text;
    END IF;
    IF p_epoch IS NULL OR p_epoch < 0 OR p_generation IS NULL OR p_generation < 0 THEN
        RAISE EXCEPTION 'search_leader_heartbeat: p_epoch and p_generation must be non-negative'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"epoch"}'::text;
    END IF;
    IF p_lease_secs IS NULL OR p_lease_secs < 1 OR p_lease_secs > 3600 THEN
        RAISE EXCEPTION 'search_leader_heartbeat: p_lease_secs must be between 1 and 3600'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"lease_secs"}'::text;
    END IF;

    v_lease_secs := p_lease_secs;

    UPDATE public.search_leader_leases l
       SET epoch = CASE
               WHEN p_epoch > l.epoch THEN p_epoch
               ELSE l.epoch
           END,
           generation = CASE
               WHEN p_epoch > l.epoch THEN p_generation
               WHEN p_epoch = l.epoch THEN GREATEST(l.generation, p_generation)
               ELSE l.generation
           END,
           leased_until = now() + make_interval(secs => v_lease_secs),
           updated_at = now()
     WHERE l.lease_key = 'search_writer'
       AND l.holder_node_id = p_node_id
       AND l.fencing_token = p_fencing_token
       AND l.leased_until > now();

    RETURN FOUND;
END;
$$;

-- Gracefully release the HA search leader lease so a standby node can acquire
-- immediately without waiting for TTL expiry while preserving fencing_token monotonicity.
CREATE OR REPLACE FUNCTION search_leader_release(
    p_node_id       text,
    p_fencing_token bigint
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
         WHERE rolname = current_user
           AND (rolbypassrls OR rolsuper)
    ) THEN
        RAISE EXCEPTION 'search_leader_release: caller role % lacks BYPASSRLS privilege', current_user
            USING ERRCODE = 'BZ003',
                  HINT = '{"type":"forbidden","reason":"bypassrls_required"}'::text;
    END IF;

    IF p_node_id IS NULL OR btrim(p_node_id) = '' THEN
        RAISE EXCEPTION 'search_leader_release: p_node_id must be non-empty'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"node_id"}'::text;
    END IF;
    IF p_fencing_token IS NULL OR p_fencing_token < 1 THEN
        RAISE EXCEPTION 'search_leader_release: p_fencing_token must be positive'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"fencing_token"}'::text;
    END IF;

    UPDATE public.search_leader_leases l
       SET leased_until = now() - interval '1 second',
           updated_at = now()
     WHERE l.lease_key = 'search_writer'
       AND l.holder_node_id = p_node_id
       AND l.fencing_token = p_fencing_token;

    RETURN FOUND;
END;
$$;

-- Return the currently active (non-expired) HA single-writer search leader.
CREATE OR REPLACE FUNCTION search_leader_current()
RETURNS TABLE (
    holder_node_id text,
    rpc_url        text,
    epoch          bigint,
    generation     bigint,
    fencing_token  bigint,
    leased_until   timestamptz
)
LANGUAGE plpgsql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
         WHERE rolname = current_user
           AND (rolbypassrls OR rolsuper)
    ) THEN
        RAISE EXCEPTION 'search_leader_current: caller role % lacks BYPASSRLS privilege', current_user
            USING ERRCODE = 'BZ003',
                  HINT = '{"type":"forbidden","reason":"bypassrls_required"}'::text;
    END IF;

    RETURN QUERY
    SELECT l.holder_node_id,
           l.rpc_url,
           l.epoch,
           l.generation,
           l.fencing_token,
           l.leased_until
      FROM public.search_leader_leases l
     WHERE l.lease_key = 'search_writer'
       AND l.leased_until > now();
END;
$$;

-- Atomically verify active HA single-writer search leadership (`FOR UPDATE` on
-- 'search_writer'), mark the batch's processed outbox rows, compute the gap-free
-- contiguous processed sequence, and advance `search_index_watermarks` in ONE
-- database transaction (eliminating any check-then-write split-brain race).
-- Returns `settled = false` with ZERO mutations if leadership or fencing_token was lost.
CREATE OR REPLACE FUNCTION search_fenced_settle_batch(
    p_node_id            text,
    p_fencing_token      bigint,
    p_seqs               bigint[],
    p_corpus             text,
    p_epoch              bigint,
    p_generation         bigint,
    p_indexed_outbox_seq bigint,
    p_schema_hash        text
)
RETURNS TABLE (
    settled              boolean,
    returned_epoch       bigint,
    committed_outbox_seq bigint
)
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    v_lease          public.search_leader_leases%ROWTYPE;
    v_contiguous_seq bigint;
    v_ret_epoch      bigint;
    v_ret_seq        bigint;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
         WHERE rolname = current_user
           AND (rolbypassrls OR rolsuper)
    ) THEN
        RAISE EXCEPTION 'search_fenced_settle_batch: caller role % lacks BYPASSRLS privilege', current_user
            USING ERRCODE = 'BZ003',
                  HINT = '{"type":"forbidden","reason":"bypassrls_required"}'::text;
    END IF;

    IF p_node_id IS NULL OR btrim(p_node_id) = '' THEN
        RAISE EXCEPTION 'search_fenced_settle_batch: p_node_id must be non-empty'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"node_id"}'::text;
    END IF;
    IF p_fencing_token IS NULL OR p_fencing_token < 1 THEN
        RAISE EXCEPTION 'search_fenced_settle_batch: p_fencing_token must be positive'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"fencing_token"}'::text;
    END IF;
    IF p_corpus IS NULL OR p_corpus NOT IN ('mail', 'mail_attachment', 'chat', 'drive', 'drive_file') THEN
        RAISE EXCEPTION 'search_fenced_settle_batch: invalid p_corpus %', p_corpus
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"corpus"}'::text;
    END IF;
    IF p_epoch IS NULL OR p_epoch < 0 OR p_generation IS NULL OR p_generation < 0 THEN
        RAISE EXCEPTION 'search_fenced_settle_batch: p_epoch and p_generation must be non-negative'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"epoch"}'::text;
    END IF;
    IF p_indexed_outbox_seq IS NULL OR p_indexed_outbox_seq < 0 THEN
        RAISE EXCEPTION 'search_fenced_settle_batch: p_indexed_outbox_seq must be non-negative'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"indexed_outbox_seq"}'::text;
    END IF;
    IF p_schema_hash IS NULL OR btrim(p_schema_hash) = '' THEN
        RAISE EXCEPTION 'search_fenced_settle_batch: p_schema_hash must be non-empty'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"schema_hash"}'::text;
    END IF;

    SELECT * INTO v_lease
      FROM public.search_leader_leases l
     WHERE l.lease_key = 'search_writer'
       FOR UPDATE;

    IF NOT FOUND
       OR v_lease.holder_node_id <> p_node_id
       OR v_lease.fencing_token <> p_fencing_token
       OR v_lease.leased_until <= now() THEN
        RETURN QUERY SELECT false, 0::bigint, 0::bigint;
        RETURN;
    END IF;

    IF p_seqs IS NOT NULL AND COALESCE(array_length(p_seqs, 1), 0) > 0 THEN
        UPDATE public.search_index_outbox
           SET processed_at = now()
         WHERE seq = ANY(p_seqs)
           AND processed_at IS NULL;
    END IF;

    SELECT COALESCE(
        (SELECT MIN(o.seq) - 1
           FROM public.search_index_outbox o
          WHERE o.corpus = p_corpus
            AND o.processed_at IS NULL
            AND o.seq <= p_indexed_outbox_seq),
        p_indexed_outbox_seq
    )::bigint INTO v_contiguous_seq;
    v_contiguous_seq := GREATEST(v_contiguous_seq, 0);

    SELECT w.epoch, w.indexed_outbox_seq
      INTO v_ret_epoch, v_ret_seq
      FROM public.search_watermark_advance(
          p_corpus,
          p_epoch,
          p_generation,
          v_contiguous_seq,
          p_schema_hash
      ) AS w;

    RETURN QUERY SELECT true, COALESCE(v_ret_epoch, 0::bigint), COALESCE(v_ret_seq, 0::bigint);
END;
$$;

-- Explicitly enqueue a physical lawful-purge eviction & segment compaction work item
-- ('search.purge_evict') when Tier-2 search watermarks are active (no-op returning 0 when OFF).
CREATE OR REPLACE FUNCTION search_purge_enqueue(
    p_corpus      text,
    p_scope_id    bigint,
    p_entity_id   bigint,
    p_received_at timestamptz DEFAULT NULL,
    p_sub_id      bigint      DEFAULT 0
)
RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    v_sub_id  bigint;
    v_work_id bigint;
    v_idem    text;
    v_payload jsonb;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
         WHERE rolname = current_user
           AND (rolbypassrls OR rolsuper)
    ) THEN
        RAISE EXCEPTION 'search_purge_enqueue: caller role % lacks BYPASSRLS privilege', current_user
            USING ERRCODE = 'BZ003',
                  HINT = '{"type":"forbidden","reason":"bypassrls_required"}'::text;
    END IF;

    IF p_corpus IS NULL OR p_corpus NOT IN ('mail', 'mail_attachment', 'chat', 'drive', 'drive_file') THEN
        RAISE EXCEPTION 'search_purge_enqueue: invalid p_corpus %', p_corpus
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"corpus"}'::text;
    END IF;
    IF p_scope_id IS NULL OR p_entity_id IS NULL THEN
        RAISE EXCEPTION 'search_purge_enqueue: p_scope_id and p_entity_id are required'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"entity_id"}'::text;
    END IF;

    -- Strictly inert while Tier-2 search is OFF (no seeded watermarks).
    IF NOT EXISTS (SELECT 1 FROM public.search_index_watermarks LIMIT 1) THEN
        RETURN 0;
    END IF;

    v_sub_id := COALESCE(p_sub_id, 0);
    v_idem := format('search.purge_evict:%s:%s:%s:%s', p_corpus, p_scope_id, p_entity_id, v_sub_id);
    v_payload := jsonb_build_object(
        'corpus', p_corpus,
        'scope_id', p_scope_id,
        'entity_id', p_entity_id,
        'sub_id', v_sub_id,
        'received_at', p_received_at
    );

    SELECT we.work_item_id INTO v_work_id
      FROM public.work_enqueue(
          'search.purge_evict',
          v_payload,
          v_idem,
          now(),
          10::smallint,
          10
      ) AS we;

    RETURN COALESCE(v_work_id, 0);
END;
$$;

-- Atomically commit eDiscovery search results, provenance JSON, status='complete',
-- and immutable core admin_audit_log entry in ONE transaction (ARCH-028).
-- Idempotent on WorkQueue retry: returns false without duplicating audit rows
-- when the search is already marked 'complete'.
CREATE OR REPLACE FUNCTION search_ediscovery_complete_atomic(
    p_actor       bigint,
    p_search_id   bigint,
    p_message_ids bigint[],
    p_total_count bigint,
    p_provenance  jsonb
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    v_status text;
    v_prov   jsonb;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
         WHERE rolname = current_user
           AND (rolbypassrls OR rolsuper)
    ) THEN
        RAISE EXCEPTION 'search_ediscovery_complete_atomic: caller role % lacks BYPASSRLS privilege', current_user
            USING ERRCODE = 'BZ003',
                  HINT = '{"type":"forbidden","reason":"bypassrls_required"}'::text;
    END IF;

    IF p_actor IS NULL OR p_actor <= 0 OR p_search_id IS NULL OR p_search_id <= 0 THEN
        RAISE EXCEPTION 'search_ediscovery_complete_atomic: p_actor and p_search_id must be positive'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"search_id"}'::text;
    END IF;
    IF p_total_count IS NULL OR p_total_count < 0 THEN
        RAISE EXCEPTION 'search_ediscovery_complete_atomic: p_total_count must be non-negative'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"total_count"}'::text;
    END IF;
    IF p_provenance IS NULL OR jsonb_typeof(p_provenance) <> 'object' THEN
        RAISE EXCEPTION 'search_ediscovery_complete_atomic: p_provenance must be a JSON object'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"provenance"}'::text;
    END IF;

    SELECT s.status INTO v_status
      FROM public.ediscovery_searches s
     WHERE s.id = p_search_id
       AND s.created_by = p_actor
       FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'search_ediscovery_complete_atomic: search % not found for actor %', p_search_id, p_actor
            USING ERRCODE = 'BZ006',
                  HINT = '{"type":"notFound"}'::text;
    END IF;

    IF v_status = 'complete' THEN
        RETURN false;
    END IF;

    v_prov := p_provenance || jsonb_build_object('result_count', p_total_count);

    DELETE FROM public.ediscovery_search_results r
     WHERE r.search_id = p_search_id;

    IF p_message_ids IS NOT NULL AND COALESCE(array_length(p_message_ids, 1), 0) > 0 THEN
        INSERT INTO public.ediscovery_search_results (search_id, message_id)
        SELECT p_search_id, mid
          FROM unnest(p_message_ids) AS mid
         ON CONFLICT DO NOTHING;
    END IF;

    UPDATE public.ediscovery_searches s
       SET status = 'complete',
           result_count = LEAST(p_total_count, 2147483647::bigint)::integer,
           search_provenance = v_prov,
           completed_at = now()
     WHERE s.id = p_search_id
       AND s.created_by = p_actor;

    PERFORM public.audit_write(
        p_actor,
        'ediscovery_search_complete',
        'ediscovery_search',
        p_search_id,
        NULL,
        v_prov,
        NULL::inet,
        format(
            'engine=%s result_count=%s tail_rows_scanned=%s',
            COALESCE(v_prov->>'engine_tier', 'unknown'),
            p_total_count,
            COALESCE(v_prov->>'tail_rows_scanned', '0')
        ),
        'core'
    );

    RETURN true;
END;
$$;

-- Atomically execute a validated KQL predicate via rust_compliance_search_complete,
-- persist search_provenance, and write the immutable core admin_audit_log entry
-- in ONE transaction (idempotent on WorkQueue retry).
CREATE OR REPLACE FUNCTION search_ediscovery_complete_kql_atomic(
    p_actor      bigint,
    p_search_id  bigint,
    p_predicate  text,
    p_values     text[],
    p_provenance jsonb
)
RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    v_status text;
    v_count  bigint;
    v_prov   jsonb;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
         WHERE rolname = current_user
           AND (rolbypassrls OR rolsuper)
    ) THEN
        RAISE EXCEPTION 'search_ediscovery_complete_kql_atomic: caller role % lacks BYPASSRLS privilege', current_user
            USING ERRCODE = 'BZ003',
                  HINT = '{"type":"forbidden","reason":"bypassrls_required"}'::text;
    END IF;

    IF p_actor IS NULL OR p_actor <= 0 OR p_search_id IS NULL OR p_search_id <= 0 THEN
        RAISE EXCEPTION 'search_ediscovery_complete_kql_atomic: p_actor and p_search_id must be positive'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"search_id"}'::text;
    END IF;
    IF p_predicate IS NULL OR btrim(p_predicate) = '' THEN
        RAISE EXCEPTION 'search_ediscovery_complete_kql_atomic: p_predicate must be non-empty'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"predicate"}'::text;
    END IF;
    IF p_provenance IS NULL OR jsonb_typeof(p_provenance) <> 'object' THEN
        RAISE EXCEPTION 'search_ediscovery_complete_kql_atomic: p_provenance must be a JSON object'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"provenance"}'::text;
    END IF;

    SELECT s.status, COALESCE(s.result_count, 0)::bigint
      INTO v_status, v_count
      FROM public.ediscovery_searches s
     WHERE s.id = p_search_id
       AND s.created_by = p_actor
       FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'search_ediscovery_complete_kql_atomic: search % not found for actor %', p_search_id, p_actor
            USING ERRCODE = 'BZ006',
                  HINT = '{"type":"notFound"}'::text;
    END IF;

    IF v_status = 'complete' THEN
        RETURN v_count;
    END IF;

    PERFORM public.rust_compliance_search_complete(p_actor, p_search_id, p_predicate, p_values);

    SELECT COALESCE(s.result_count, 0)::bigint
      INTO v_count
      FROM public.ediscovery_searches s
     WHERE s.id = p_search_id
       AND s.created_by = p_actor;

    v_prov := p_provenance || jsonb_build_object('result_count', v_count);

    UPDATE public.ediscovery_searches s
       SET search_provenance = v_prov
     WHERE s.id = p_search_id
       AND s.created_by = p_actor;

    PERFORM public.audit_write(
        p_actor,
        'ediscovery_search_complete',
        'ediscovery_search',
        p_search_id,
        NULL,
        v_prov,
        NULL::inet,
        format(
            'engine=%s result_count=%s tail_rows_scanned=%s',
            COALESCE(v_prov->>'engine_tier', 'tier1_pg_fallback'),
            v_count,
            COALESCE(v_prov->>'tail_rows_scanned', '0')
        ),
        'core'
    );

    RETURN v_count;
END;
$$;

-- Gated worker-owned SECURITY DEFINER trigger function for lawful hard-delete
-- physical eviction & segment compaction ('search.purge_evict').
-- Strictly inert while Tier-2 search is OFF (search_index_watermarks empty).
CREATE OR REPLACE FUNCTION search_purge_evict_trg_fn()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    v_src       text;
    v_att       record;
    v_ver       record;
    v_rev_id    bigint;
    v_scope_id  bigint;
    v_ts        timestamptz;
    v_is_chat   boolean;
    v_corpus    text;
    v_entity_id bigint;
    v_chan_text text;
    v_mb_text   text;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM public.search_index_watermarks LIMIT 1) THEN
        RETURN OLD;
    END IF;

    v_src := CASE WHEN TG_NARGS > 0 THEN TG_ARGV[0] ELSE TG_TABLE_NAME END;

    IF v_src = 'messages_before_delete' THEN
        FOR v_att IN
            SELECT ma.id
              FROM public.message_attachments ma
             WHERE ma.message_id = OLD.id
               AND ma.received_at = OLD.received_at
        LOOP
            PERFORM public.work_enqueue(
                'search.purge_evict',
                jsonb_build_object(
                    'corpus', 'mail_attachment',
                    'scope_id', OLD.mailbox_id,
                    'entity_id', OLD.id,
                    'sub_id', v_att.id,
                    'received_at', OLD.received_at
                ),
                format('search.purge_evict:mail_attachment:%s:%s:%s', OLD.mailbox_id, OLD.id, v_att.id),
                now(),
                10::smallint,
                10
            );
        END LOOP;
        RETURN OLD;
    ELSIF v_src = 'message_attachments' THEN
        SELECT m.mailbox_id INTO v_scope_id
          FROM public.messages m
         WHERE m.id = OLD.message_id
           AND m.received_at = OLD.received_at;
        IF v_scope_id IS NOT NULL THEN
            PERFORM public.work_enqueue(
                'search.purge_evict',
                jsonb_build_object(
                    'corpus', 'mail_attachment',
                    'scope_id', v_scope_id,
                    'entity_id', OLD.message_id,
                    'sub_id', OLD.id,
                    'received_at', OLD.received_at
                ),
                format('search.purge_evict:mail_attachment:%s:%s:%s', v_scope_id, OLD.message_id, OLD.id),
                now(),
                10::smallint,
                10
            );
            -- Also physically evict + compact the parent Mail document whose indexed text
            -- previously included this deleted attachment (V298's AFTER DELETE trigger enqueues
            -- a fresh Mail upsert to re-index the surviving parent Mail without this attachment).
            PERFORM public.work_enqueue(
                'search.purge_evict',
                jsonb_build_object(
                    'corpus', 'mail',
                    'scope_id', v_scope_id,
                    'entity_id', OLD.message_id,
                    'sub_id', 0,
                    'received_at', OLD.received_at
                ),
                format('search.purge_evict:mail:%s:%s:0', v_scope_id, OLD.message_id),
                now(),
                10::smallint,
                10
            );
        END IF;
        RETURN OLD;
    ELSIF v_src = 'messages' THEN
        PERFORM public.work_enqueue(
            'search.purge_evict',
            jsonb_build_object(
                'corpus', 'mail',
                'scope_id', OLD.mailbox_id,
                'entity_id', OLD.id,
                'sub_id', 0,
                'received_at', OLD.received_at
            ),
            format('search.purge_evict:mail:%s:%s:0', OLD.mailbox_id, OLD.id),
            now(),
            10::smallint,
            10
        );
    ELSIF v_src = 'chat_messages' THEN
        v_rev_id := public.search_chat_revision_doc_id(OLD.id);
        PERFORM public.work_enqueue(
            'search.purge_evict',
            jsonb_build_object(
                'corpus', 'chat',
                'scope_id', OLD.channel_id,
                'entity_id', OLD.id,
                'sub_id', 0,
                'received_at', OLD.created_at
            ),
            format('search.purge_evict:chat:%s:%s:0', OLD.channel_id, OLD.id),
            now(),
            10::smallint,
            10
        );
        PERFORM public.work_enqueue(
            'search.purge_evict',
            jsonb_build_object(
                'corpus', 'chat',
                'scope_id', OLD.channel_id,
                'entity_id', v_rev_id,
                'sub_id', 0,
                'received_at', OLD.created_at
            ),
            format('search.purge_evict:chat:%s:%s:0', OLD.channel_id, v_rev_id),
            now(),
            10::smallint,
            10
        );
    ELSIF v_src = 'drive_nodes_before_delete' THEN
        FOR v_ver IN
            SELECT dfv.id
              FROM public.drive_file_versions dfv
             WHERE dfv.file_node_id = OLD.id
        LOOP
            PERFORM public.work_enqueue(
                'search.purge_evict',
                jsonb_build_object(
                    'corpus', 'drive_file',
                    'scope_id', OLD.space_id,
                    'entity_id', OLD.id,
                    'sub_id', v_ver.id,
                    'received_at', OLD.created_at
                ),
                format('search.purge_evict:drive_file:%s:%s:%s', OLD.space_id, OLD.id, v_ver.id),
                now(),
                10::smallint,
                10
            );
        END LOOP;
        RETURN OLD;
    ELSIF v_src = 'drive_file_versions' THEN
        SELECT n.space_id, n.created_at INTO v_scope_id, v_ts
          FROM public.drive_nodes n
         WHERE n.id = OLD.file_node_id;
        IF v_scope_id IS NOT NULL THEN
            PERFORM public.work_enqueue(
                'search.purge_evict',
                jsonb_build_object(
                    'corpus', 'drive_file',
                    'scope_id', v_scope_id,
                    'entity_id', OLD.file_node_id,
                    'sub_id', OLD.id,
                    'received_at', v_ts
                ),
                format('search.purge_evict:drive_file:%s:%s:%s', v_scope_id, OLD.file_node_id, OLD.id),
                now(),
                10::smallint,
                10
            );
        END IF;
        RETURN OLD;
    ELSIF v_src = 'drive_nodes' THEN
        PERFORM public.work_enqueue(
            'search.purge_evict',
            jsonb_build_object(
                'corpus', 'drive',
                'scope_id', OLD.space_id,
                'entity_id', OLD.id,
                'sub_id', 0,
                'received_at', OLD.created_at
            ),
            format('search.purge_evict:drive:%s:%s:0', OLD.space_id, OLD.id),
            now(),
            10::smallint,
            10
        );
    ELSIF v_src = 'scheduled_actions' THEN
        v_is_chat := (
            lower(OLD.action_kind) LIKE '%chat%'
            OR (OLD.payload ? 'channelId')
            OR (OLD.payload ? 'channel_id')
        );
        IF NOT v_is_chat AND OLD.action_kind <> 'send' AND OLD.mailbox_id IS NULL THEN
            RETURN OLD;
        END IF;
        v_corpus := CASE WHEN v_is_chat THEN 'chat' ELSE 'mail' END;
        v_entity_id := public.search_scheduled_action_doc_id(OLD.id);
        IF v_is_chat THEN
            v_chan_text := COALESCE(
                NULLIF(OLD.payload->>'channelId', ''),
                NULLIF(OLD.payload->>'channel_id', '')
            );
            BEGIN
                v_scope_id := COALESCE(v_chan_text::bigint, 0);
            EXCEPTION WHEN OTHERS THEN
                v_scope_id := 0;
            END;
        ELSE
            v_mb_text := NULLIF(OLD.payload->>'mailbox_id', '');
            BEGIN
                v_scope_id := COALESCE(OLD.mailbox_id, v_mb_text::bigint, 0);
            EXCEPTION WHEN OTHERS THEN
                v_scope_id := COALESCE(OLD.mailbox_id, 0);
            END;
        END IF;
        PERFORM public.work_enqueue(
            'search.purge_evict',
            jsonb_build_object(
                'corpus', v_corpus,
                'scope_id', v_scope_id,
                'entity_id', v_entity_id,
                'sub_id', 0,
                'received_at', OLD.fire_at
            ),
            format('search.purge_evict:%s:%s:%s:0', v_corpus, v_scope_id, v_entity_id),
            now(),
            10::smallint,
            10
        );
        RETURN OLD;
    END IF;

    RETURN OLD;
END;
$$;

DO $$
DECLARE
    v_had_create boolean := false;
    v_sig        text;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
        SELECT has_schema_privilege('setjoin_worker', 'public', 'CREATE') INTO v_had_create;
        IF NOT v_had_create THEN
            GRANT CREATE ON SCHEMA public TO setjoin_worker;
        END IF;
        ALTER FUNCTION public.search_purge_evict_trg_fn() OWNER TO setjoin_worker;
        IF NOT v_had_create THEN
            REVOKE CREATE ON SCHEMA public FROM setjoin_worker;
        END IF;
    END IF;

    FOREACH v_sig IN ARRAY ARRAY[
        'public.search_chat_revision_doc_id(bigint)',
        'public.search_leader_try_acquire(text,text,integer)',
        'public.search_leader_heartbeat(text,bigint,bigint,bigint,integer)',
        'public.search_leader_release(text,bigint)',
        'public.search_leader_current()',
        'public.search_fenced_settle_batch(text,bigint,bigint[],text,bigint,bigint,bigint,text)',
        'public.search_purge_enqueue(text,bigint,bigint,timestamptz,bigint)',
        'public.search_ediscovery_complete_atomic(bigint,bigint,bigint[],bigint,jsonb)',
        'public.search_ediscovery_complete_kql_atomic(bigint,bigint,text,text[],jsonb)',
        'public.search_purge_evict_trg_fn()'
    ] LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', v_sig);
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
            EXECUTE format('REVOKE ALL ON FUNCTION %s FROM setjoin_app', v_sig);
        END IF;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
            EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO setjoin_worker', v_sig);
        END IF;
    END LOOP;
END
$$;

-- 5. Attach gated lawful-purge physical eviction triggers on hard DELETEs (parents + children).
DROP TRIGGER IF EXISTS trg_search_purge_messages_before_delete ON public.messages;
CREATE TRIGGER trg_search_purge_messages_before_delete
    BEFORE DELETE ON public.messages
    FOR EACH ROW EXECUTE FUNCTION public.search_purge_evict_trg_fn('messages_before_delete');

DROP TRIGGER IF EXISTS trg_search_purge_message_attachments ON public.message_attachments;
CREATE TRIGGER trg_search_purge_message_attachments
    BEFORE DELETE ON public.message_attachments
    FOR EACH ROW EXECUTE FUNCTION public.search_purge_evict_trg_fn('message_attachments');

DROP TRIGGER IF EXISTS trg_search_purge_messages ON public.messages;
CREATE TRIGGER trg_search_purge_messages
    AFTER DELETE ON public.messages
    FOR EACH ROW EXECUTE FUNCTION public.search_purge_evict_trg_fn('messages');

DROP TRIGGER IF EXISTS trg_search_purge_chat_messages ON public.chat_messages;
CREATE TRIGGER trg_search_purge_chat_messages
    AFTER DELETE ON public.chat_messages
    FOR EACH ROW EXECUTE FUNCTION public.search_purge_evict_trg_fn('chat_messages');

DROP TRIGGER IF EXISTS trg_search_purge_drive_nodes_before_delete ON public.drive_nodes;
CREATE TRIGGER trg_search_purge_drive_nodes_before_delete
    BEFORE DELETE ON public.drive_nodes
    FOR EACH ROW EXECUTE FUNCTION public.search_purge_evict_trg_fn('drive_nodes_before_delete');

DROP TRIGGER IF EXISTS trg_search_purge_drive_file_versions ON public.drive_file_versions;
CREATE TRIGGER trg_search_purge_drive_file_versions
    BEFORE DELETE ON public.drive_file_versions
    FOR EACH ROW EXECUTE FUNCTION public.search_purge_evict_trg_fn('drive_file_versions');

DROP TRIGGER IF EXISTS trg_search_purge_drive_nodes ON public.drive_nodes;
CREATE TRIGGER trg_search_purge_drive_nodes
    AFTER DELETE ON public.drive_nodes
    FOR EACH ROW EXECUTE FUNCTION public.search_purge_evict_trg_fn('drive_nodes');

DROP TRIGGER IF EXISTS trg_search_purge_scheduled_actions ON public.scheduled_actions;
CREATE TRIGGER trg_search_purge_scheduled_actions
    BEFORE DELETE ON public.scheduled_actions
    FOR EACH ROW EXECUTE FUNCTION public.search_purge_evict_trg_fn('scheduled_actions');

INSERT INTO public.schema_migrations (version, applied_at) VALUES (299, now())
    ON CONFLICT (version) DO NOTHING;

COMMIT;
