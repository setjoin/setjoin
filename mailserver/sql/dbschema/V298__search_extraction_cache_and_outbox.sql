-- V298__search_extraction_cache_and_outbox.sql — Wave 3.2 (#557):
-- Content-addressed extraction cache (`public.search_extracted_text`),
-- commit-ordered monotonic search indexing outbox (`public.search_index_outbox`),
-- strictly additive `search_index_watermarks.indexed_outbox_seq`,
-- `drive_file_versions_content_sha256_idx`, worker-only extraction GC sweep +
-- outbox/watermark helpers, and gated production write-capture triggers.
--
-- Non-negotiable invariants:
--   1. Zero `blobs` columns added; zero `feature_toggles` rows added.
--   2. `search_extracted_text` and `search_index_outbox` are worker-only
--      `system_only` tables with ENABLE + FORCE ROW LEVEL SECURITY, ZERO
--      policies (deny-all to `setjoin_app` and `PUBLIC`), owned by
--      `setjoin_owner`, with table/sequence grants restricted to
--      `setjoin_worker` (restated in `scripts/provision-roles.sql`).
--   3. `search_extracted_text.content_sha256` and `search_index_outbox.content_sha256`
--      are classified under `blobs_internal` in `config/blob-reference-manifest.json`
--      (NOT `live_roots` anchors), and orphaned cache rows are reclaimed by
--      `search_extracted_text_gc_sweep()` only when unreferenced on BOTH planes.
--   4. `search_index_outbox_trg_fn()` is owned by `setjoin_worker` (`SECURITY DEFINER`)
--      using transient `GRANT/REVOKE CREATE ON SCHEMA public TO setjoin_worker` so
--      non-superuser `setjoin_owner` replay succeeds with zero drift on existing
--      `SECURITY DEFINER` functions, and is gated on `search_index_watermarks`
--      having >= 1 row (zero overhead while Tier-2 search is OFF).

BEGIN;

-- 1. Content-addressed extraction cache table (deduplicates extraction by SHA-256).
CREATE TABLE IF NOT EXISTS public.search_extracted_text (
    content_sha256    text        PRIMARY KEY
                      CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
    storage_plane     text        NOT NULL
                      CHECK (storage_plane IN ('blob', 'drive_file_version')),
    extraction_status text        NOT NULL
                      CHECK (extraction_status IN ('extracted', 'encrypted', 'unsupported', 'truncated_limit', 'failed')),
    extractor_version smallint    NOT NULL DEFAULT 1,
    extracted_text    text
                      CHECK (extracted_text IS NULL OR octet_length(extracted_text) <= 524288),
    extracted_bytes   integer     NOT NULL DEFAULT 0
                      CHECK (extracted_bytes >= 0),
    detected_mime     text,
    error_code        text
                      CHECK (error_code IS NULL OR length(error_code) <= 128),
    extracted_at      timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    CHECK ((extraction_status IN ('extracted', 'truncated_limit')) OR extracted_text IS NULL)
);

CREATE INDEX IF NOT EXISTS search_extracted_text_gc_idx
    ON public.search_extracted_text (storage_plane, extracted_at, content_sha256);

-- 2. Gap-free monotonic search indexing outbox across all five indexed corpora.
CREATE TABLE IF NOT EXISTS public.search_index_outbox (
    seq            bigserial   PRIMARY KEY,
    corpus         text        NOT NULL
                   CHECK (corpus IN ('mail', 'mail_attachment', 'chat', 'drive', 'drive_file')),
    op             text        NOT NULL
                   CHECK (op IN ('upsert', 'delete')),
    scope_id       bigint      NOT NULL,
    entity_id      bigint      NOT NULL,
    sub_id         bigint      NOT NULL DEFAULT 0,
    received_at    timestamptz,
    content_sha256 text
                   CHECK (content_sha256 IS NULL OR content_sha256 ~ '^[0-9a-f]{64}$'),
    action_id      uuid,
    txid           xid8        NOT NULL DEFAULT pg_catalog.pg_current_xact_id(),
    processed_at   timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS search_index_outbox_corpus_seq_idx
    ON public.search_index_outbox (corpus, seq);

CREATE INDEX IF NOT EXISTS search_index_outbox_unprocessed_idx
    ON public.search_index_outbox (corpus, seq)
    WHERE processed_at IS NULL;

CREATE INDEX IF NOT EXISTS search_index_outbox_created_idx
    ON public.search_index_outbox (created_at);

-- 3. Strictly additive monotonic outbox watermark column on search_index_watermarks.
ALTER TABLE public.search_index_watermarks
    ADD COLUMN IF NOT EXISTS indexed_outbox_seq bigint NOT NULL DEFAULT 0
    CHECK (indexed_outbox_seq >= 0);

-- 4. Deny-all FORCE RLS + owner/worker privilege posture on both new tables.
ALTER TABLE public.search_extracted_text ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.search_extracted_text FORCE ROW LEVEL SECURITY;

ALTER TABLE public.search_index_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.search_index_outbox FORCE ROW LEVEL SECURITY;

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['search_extracted_text', 'search_index_outbox'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_owner') THEN
            EXECUTE format('ALTER TABLE public.%I OWNER TO setjoin_owner', t);
        END IF;
        EXECUTE format('REVOKE ALL ON TABLE public.%I FROM PUBLIC', t);
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
            EXECUTE format('REVOKE ALL ON TABLE public.%I FROM setjoin_app', t);
        END IF;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
            EXECUTE format('REVOKE ALL ON TABLE public.%I FROM setjoin_worker', t);
            EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.%I TO setjoin_worker', t);
        END IF;
    END LOOP;

    IF to_regclass('public.search_index_outbox_seq_seq') IS NOT NULL THEN
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_owner') THEN
            ALTER SEQUENCE public.search_index_outbox_seq_seq OWNER TO setjoin_owner;
        END IF;
        REVOKE ALL ON SEQUENCE public.search_index_outbox_seq_seq FROM PUBLIC;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
            REVOKE ALL ON SEQUENCE public.search_index_outbox_seq_seq FROM setjoin_app;
        END IF;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
            REVOKE ALL ON SEQUENCE public.search_index_outbox_seq_seq FROM setjoin_worker;
            GRANT USAGE, SELECT ON SEQUENCE public.search_index_outbox_seq_seq TO setjoin_worker;
        END IF;
    END IF;
END
$$;

-- 5. Worker-only helper reducers & trigger function (verbatim copy of reducers/search_extraction.sql).
-- search_extraction.sql — Wave 3.2 (#557):
-- Content-addressed extraction cache GC sweep, commit-ordered monotonic search
-- indexing outbox enqueue/claim helpers, epoch-guarded monotonic watermark
-- advancement, deterministic scheduled-action doc ID helper, and production
-- write-capture outbox trigger function.
--
-- Security posture:
--   - search_extracted_text_gc_sweep, search_outbox_enqueue,
--     search_outbox_claim_batch, and search_watermark_advance are worker-only
--     SECURITY INVOKER with SET search_path = pg_catalog, public, pg_temp and
--     enforce (rolbypassrls OR rolsuper) raising BZ003.
--   - search_scheduled_action_doc_id is pure IMMUTABLE SQL (SECURITY INVOKER)
--     using built-in pg_catalog.sha256 (matching Rust scheduled_action_doc_id).
--   - search_index_outbox_trg_fn is a narrow worker-owned SECURITY DEFINER
--     trigger function (OWNER TO setjoin_worker, SET search_path = pg_catalog,
--     public, pg_temp) gated on EXISTS (SELECT 1 FROM search_index_watermarks
--     LIMIT 1) so Tier-2-OFF installations incur zero outbox/WorkQueue writes.
--   - EXECUTE is revoked from PUBLIC and setjoin_app and granted strictly to
--     setjoin_worker (restated in scripts/provision-roles.sql).

-- Deterministic strictly-negative bigint doc ID matching Rust
-- `setjoin_search::scheduled_action_doc_id(uuid)`.
CREATE OR REPLACE FUNCTION search_scheduled_action_doc_id(p_action_id uuid)
RETURNS bigint
LANGUAGE sql
IMMUTABLE
STRICT
SECURITY INVOKER
SET search_path = pg_catalog, public, pg_temp
AS $$
    WITH d AS (
        SELECT pg_catalog.sha256(
            pg_catalog.convert_to('scheduled_action:' || lower(p_action_id::text), 'UTF8')
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

-- Mark-and-Sweep GC cleanup helper for derived content-addressed extraction
-- cache rows (`public.search_extracted_text`).
-- Because `search_extracted_text` deduplicates globally by content_sha256 across
-- both blob and Drive planes, a row is deleted ONLY when aged past p_grace_minutes
-- AND unreferenced on BOTH planes:
--   - NOT public.blob_has_live_reference(content_sha256)
--   - NOT EXISTS (SELECT 1 FROM public.drive_file_versions v WHERE v.content_sha256 = t.content_sha256)
-- Recoverable 30-day Drive admin trash (`drive_nodes.purged_at IS NOT NULL`)
-- still retains its `drive_file_versions` row and therefore keeps its cache row
-- until hard deletion (`drive_node_destroy_hard`).
CREATE OR REPLACE FUNCTION search_extracted_text_gc_sweep(
    p_grace_minutes integer DEFAULT 1440,
    p_batch_size    integer DEFAULT 500
)
RETURNS integer
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    v_grace   integer;
    v_batch   integer;
    v_deleted integer := 0;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
         WHERE rolname = current_user
           AND (rolbypassrls OR rolsuper)
    ) THEN
        RAISE EXCEPTION 'search_extracted_text_gc_sweep: caller role % lacks BYPASSRLS privilege', current_user
            USING ERRCODE = 'BZ003',
                  HINT = '{"type":"forbidden","reason":"bypassrls_required"}'::text;
    END IF;

    IF p_grace_minutes IS NULL OR p_grace_minutes < 0 THEN
        RAISE EXCEPTION 'search_extracted_text_gc_sweep: p_grace_minutes must be non-negative'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"grace_minutes"}'::text;
    END IF;
    IF p_batch_size IS NULL OR p_batch_size < 1 THEN
        RAISE EXCEPTION 'search_extracted_text_gc_sweep: p_batch_size must be positive'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"batch_size"}'::text;
    END IF;

    v_grace := p_grace_minutes;
    v_batch := LEAST(p_batch_size, 10000);

    WITH victims AS (
        SELECT t.content_sha256
          FROM public.search_extracted_text t
         WHERE t.extracted_at <= now() - make_interval(mins => v_grace)
           AND NOT public.blob_has_live_reference(t.content_sha256)
           AND NOT EXISTS (
               SELECT 1
                 FROM public.drive_file_versions v
                WHERE v.content_sha256 = t.content_sha256
           )
         ORDER BY t.extracted_at ASC, t.content_sha256 ASC
         LIMIT v_batch
         FOR UPDATE SKIP LOCKED
    )
    DELETE FROM public.search_extracted_text t
     USING victims v
     WHERE t.content_sha256 = v.content_sha256;

    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted;
END;
$$;

-- Append one commit-ordered event to public.search_index_outbox.
CREATE OR REPLACE FUNCTION search_outbox_enqueue(
    p_corpus         text,
    p_op             text,
    p_scope_id       bigint,
    p_entity_id      bigint,
    p_sub_id         bigint      DEFAULT 0,
    p_received_at    timestamptz DEFAULT NULL,
    p_content_sha256 text        DEFAULT NULL,
    p_action_id      uuid        DEFAULT NULL
)
RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    v_seq bigint;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
         WHERE rolname = current_user
           AND (rolbypassrls OR rolsuper)
    ) THEN
        RAISE EXCEPTION 'search_outbox_enqueue: caller role % lacks BYPASSRLS privilege', current_user
            USING ERRCODE = 'BZ003',
                  HINT = '{"type":"forbidden","reason":"bypassrls_required"}'::text;
    END IF;

    IF p_corpus IS NULL OR p_corpus NOT IN ('mail', 'mail_attachment', 'chat', 'drive', 'drive_file') THEN
        RAISE EXCEPTION 'search_outbox_enqueue: invalid p_corpus %', p_corpus
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"corpus"}'::text;
    END IF;
    IF p_op IS NULL OR p_op NOT IN ('upsert', 'delete') THEN
        RAISE EXCEPTION 'search_outbox_enqueue: invalid p_op %', p_op
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"op"}'::text;
    END IF;
    IF p_scope_id IS NULL OR p_entity_id IS NULL THEN
        RAISE EXCEPTION 'search_outbox_enqueue: p_scope_id and p_entity_id are required'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"entity_id"}'::text;
    END IF;
    IF p_content_sha256 IS NOT NULL AND p_content_sha256 !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'search_outbox_enqueue: p_content_sha256 must be lowercase 64-hex SHA-256'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"content_sha256"}'::text;
    END IF;

    INSERT INTO public.search_index_outbox (
        corpus,
        op,
        scope_id,
        entity_id,
        sub_id,
        received_at,
        content_sha256,
        action_id,
        txid
    )
    VALUES (
        p_corpus,
        p_op,
        p_scope_id,
        p_entity_id,
        COALESCE(p_sub_id, 0),
        p_received_at,
        p_content_sha256,
        p_action_id,
        pg_catalog.pg_current_xact_id()
    )
    RETURNING seq INTO v_seq;

    RETURN v_seq;
END;
$$;

-- Read the next gap-free batch of unprocessed outbox entries for one corpus after
-- p_after_seq. Filtering on processed_at IS NULL (claimed with p_after_seq = 0 by
-- the indexing pipeline) guarantees that out-of-order commits (e.g., seq=2 commits
-- before seq=1) can never permanently skip a lower seq.
CREATE OR REPLACE FUNCTION search_outbox_claim_batch(
    p_corpus    text,
    p_after_seq bigint,
    p_limit     integer DEFAULT 200
)
RETURNS TABLE (
    seq            bigint,
    corpus         text,
    op             text,
    scope_id       bigint,
    entity_id      bigint,
    sub_id         bigint,
    received_at    timestamptz,
    content_sha256 text,
    created_at     timestamptz,
    action_id      uuid
)
LANGUAGE plpgsql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    v_after      bigint;
    v_limit      integer;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
         WHERE rolname = current_user
           AND (rolbypassrls OR rolsuper)
    ) THEN
        RAISE EXCEPTION 'search_outbox_claim_batch: caller role % lacks BYPASSRLS privilege', current_user
            USING ERRCODE = 'BZ003',
                  HINT = '{"type":"forbidden","reason":"bypassrls_required"}'::text;
    END IF;

    IF p_corpus IS NULL OR p_corpus NOT IN ('mail', 'mail_attachment', 'chat', 'drive', 'drive_file') THEN
        RAISE EXCEPTION 'search_outbox_claim_batch: invalid p_corpus %', p_corpus
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"corpus"}'::text;
    END IF;
    IF p_after_seq IS NULL OR p_after_seq < 0 THEN
        RAISE EXCEPTION 'search_outbox_claim_batch: p_after_seq must be non-negative'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"after_seq"}'::text;
    END IF;
    IF p_limit IS NULL OR p_limit < 1 THEN
        RAISE EXCEPTION 'search_outbox_claim_batch: p_limit must be positive'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"limit"}'::text;
    END IF;

    v_after := p_after_seq;
    v_limit := LEAST(p_limit, 1000);

    RETURN QUERY
    SELECT o.seq,
           o.corpus,
           o.op,
           o.scope_id,
           o.entity_id,
           o.sub_id,
           o.received_at,
           o.content_sha256,
           o.created_at,
           o.action_id
      FROM public.search_index_outbox o
     WHERE o.corpus = p_corpus
       AND o.processed_at IS NULL
       AND o.seq > v_after
     ORDER BY o.seq ASC
     LIMIT v_limit;
END;
$$;

-- Mark the exact committed outbox sequence numbers as processed so gap-free
-- out-of-order commits never drop lower sequences and processed rows are not re-claimed.
CREATE OR REPLACE FUNCTION search_outbox_mark_processed(
    p_seqs bigint[]
)
RETURNS integer
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    v_updated integer := 0;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
         WHERE rolname = current_user
           AND (rolbypassrls OR rolsuper)
    ) THEN
        RAISE EXCEPTION 'search_outbox_mark_processed: caller role % lacks BYPASSRLS privilege', current_user
            USING ERRCODE = 'BZ003',
                  HINT = '{"type":"forbidden","reason":"bypassrls_required"}'::text;
    END IF;

    IF p_seqs IS NULL OR cardinality(p_seqs) = 0 THEN
        RETURN 0;
    END IF;

    UPDATE public.search_index_outbox
       SET processed_at = now()
     WHERE seq = ANY(p_seqs)
       AND processed_at IS NULL;

    GET DIAGNOSTICS v_updated = ROW_COUNT;
    RETURN v_updated;
END;
$$;

-- Epoch-guarded strictly monotonic watermark advancement:
--   - EXCLUDED.epoch < w.epoch: stale epoch ignored (leaves all columns untouched)
--   - EXCLUDED.epoch > w.epoch: advances cleanly to new epoch's generation/seq/schema_hash
--   - EXCLUDED.epoch = w.epoch: applies GREATEST monotonically on generation & indexed_outbox_seq
CREATE OR REPLACE FUNCTION search_watermark_advance(
    p_corpus             text,
    p_epoch              bigint,
    p_generation         bigint,
    p_indexed_outbox_seq bigint,
    p_schema_hash        text
)
RETURNS TABLE (
    corpus             text,
    epoch              bigint,
    generation         bigint,
    indexed_outbox_seq bigint,
    schema_hash        text,
    updated_at         timestamptz
)
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
        RAISE EXCEPTION 'search_watermark_advance: caller role % lacks BYPASSRLS privilege', current_user
            USING ERRCODE = 'BZ003',
                  HINT = '{"type":"forbidden","reason":"bypassrls_required"}'::text;
    END IF;

    IF p_corpus IS NULL OR p_corpus NOT IN ('mail', 'mail_attachment', 'chat', 'drive', 'drive_file') THEN
        RAISE EXCEPTION 'search_watermark_advance: invalid p_corpus %', p_corpus
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"corpus"}'::text;
    END IF;
    IF p_epoch IS NULL OR p_epoch < 0 THEN
        RAISE EXCEPTION 'search_watermark_advance: p_epoch must be non-negative'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"epoch"}'::text;
    END IF;
    IF p_generation IS NULL OR p_generation < 0 THEN
        RAISE EXCEPTION 'search_watermark_advance: p_generation must be non-negative'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"generation"}'::text;
    END IF;
    IF p_indexed_outbox_seq IS NULL OR p_indexed_outbox_seq < 0 THEN
        RAISE EXCEPTION 'search_watermark_advance: p_indexed_outbox_seq must be non-negative'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","field":"indexed_outbox_seq"}'::text;
    END IF;

    RETURN QUERY
    INSERT INTO public.search_index_watermarks AS w (
        corpus,
        epoch,
        generation,
        indexed_outbox_seq,
        schema_hash,
        watermark_ts,
        updated_at
    )
    VALUES (
        p_corpus,
        p_epoch,
        p_generation,
        p_indexed_outbox_seq,
        COALESCE(p_schema_hash, ''),
        now(),
        now()
    )
    ON CONFLICT ON CONSTRAINT search_index_watermarks_pkey DO UPDATE
        SET epoch = CASE
                WHEN EXCLUDED.epoch < w.epoch THEN w.epoch
                ELSE EXCLUDED.epoch
            END,
            generation = CASE
                WHEN EXCLUDED.epoch < w.epoch THEN w.generation
                WHEN EXCLUDED.epoch > w.epoch THEN EXCLUDED.generation
                ELSE GREATEST(w.generation, EXCLUDED.generation)
            END,
            indexed_outbox_seq = CASE
                WHEN EXCLUDED.epoch < w.epoch THEN w.indexed_outbox_seq
                WHEN EXCLUDED.epoch > w.epoch THEN EXCLUDED.indexed_outbox_seq
                ELSE GREATEST(w.indexed_outbox_seq, EXCLUDED.indexed_outbox_seq)
            END,
            schema_hash = CASE
                WHEN EXCLUDED.epoch < w.epoch THEN w.schema_hash
                WHEN EXCLUDED.schema_hash <> '' THEN EXCLUDED.schema_hash
                ELSE w.schema_hash
            END,
            watermark_ts = CASE
                WHEN EXCLUDED.epoch < w.epoch THEN w.watermark_ts
                ELSE now()
            END,
            updated_at = CASE
                WHEN EXCLUDED.epoch < w.epoch THEN w.updated_at
                ELSE now()
            END
    RETURNING w.corpus,
              w.epoch,
              w.generation,
              w.indexed_outbox_seq,
              w.schema_hash,
              w.updated_at;
END;
$$;

-- Production write-capture trigger function (worker-owned SECURITY DEFINER).
-- Strictly inert while Tier-2 search is OFF (gated on search_index_watermarks
-- having at least one row). Captures Mail, MailAttachment, Chat, ChatRevisions,
-- ChatAttachments, Drive, DriveFileVersions, and ScheduledActions writes into
-- public.search_index_outbox and enqueues coalesced search.extract /
-- search.index_batch WorkQueue items.
CREATE OR REPLACE FUNCTION search_index_outbox_trg_fn()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    v_mailbox_id bigint;
    v_name       text;
    v_scope_id   bigint;
    v_entity_id  bigint;
    v_corpus     text;
    v_op         text;
    v_is_chat    boolean;
    v_chan_text  text;
    v_mb_text    text;
    v_txid       xid8;
    v_src        text;
BEGIN
    -- Zero outbox/WorkQueue writes when Tier-2 search has not been initialized.
    IF NOT EXISTS (SELECT 1 FROM public.search_index_watermarks LIMIT 1) THEN
        RETURN COALESCE(NEW, OLD);
    END IF;

    v_txid := pg_catalog.pg_current_xact_id();
    v_src := CASE WHEN TG_NARGS > 0 THEN TG_ARGV[0] ELSE TG_TABLE_NAME END;

    IF v_src = 'messages_before_delete' THEN
        -- Runs BEFORE ON DELETE CASCADE deletes message_attachments so each child
        -- attachment tombstone captures the real OLD.mailbox_id instead of scope_id = 0.
        IF TG_OP = 'DELETE' THEN
            INSERT INTO public.search_index_outbox (corpus, op, scope_id, entity_id, sub_id, received_at, content_sha256, txid)
            SELECT 'mail_attachment', 'delete', OLD.mailbox_id, OLD.id, ma.id, OLD.received_at, ma.blob_sha256, v_txid
              FROM public.message_attachments ma
             WHERE ma.message_id = OLD.id
               AND ma.received_at = OLD.received_at;
            IF FOUND THEN
                PERFORM public.work_enqueue(
                    'search.index_batch',
                    jsonb_build_object('corpus', 'mail_attachment'),
                    'search.index_batch:mail_attachment',
                    now(),
                    0::smallint,
                    5
                );
            END IF;
        END IF;
        RETURN OLD;
    ELSIF v_src = 'messages' THEN
        IF TG_OP = 'DELETE' THEN
            INSERT INTO public.search_index_outbox (corpus, op, scope_id, entity_id, sub_id, received_at, txid)
            VALUES ('mail', 'delete', OLD.mailbox_id, OLD.id, 0, OLD.received_at, v_txid);
        ELSE
            INSERT INTO public.search_index_outbox (corpus, op, scope_id, entity_id, sub_id, received_at, txid)
            VALUES ('mail', 'upsert', NEW.mailbox_id, NEW.id, 0, NEW.received_at, v_txid);
        END IF;
        PERFORM public.work_enqueue(
            'search.index_batch',
            jsonb_build_object('corpus', 'mail'),
            'search.index_batch:mail',
            now(),
            0::smallint,
            5
        );
    ELSIF v_src = 'message_attachments' THEN
        IF TG_OP = 'DELETE' THEN
            SELECT m.mailbox_id INTO v_mailbox_id
              FROM public.messages m
             WHERE m.id = OLD.message_id AND m.received_at = OLD.received_at;
            -- When v_mailbox_id IS NULL, the parent message was deleted via CASCADE
            -- and trg_search_outbox_messages_before_delete already emitted scoped tombstones.
            IF v_mailbox_id IS NOT NULL THEN
                INSERT INTO public.search_index_outbox (corpus, op, scope_id, entity_id, sub_id, received_at, content_sha256, txid)
                VALUES
                    ('mail_attachment', 'delete', v_mailbox_id, OLD.message_id, OLD.id, OLD.received_at, OLD.blob_sha256, v_txid),
                    ('mail', 'upsert', v_mailbox_id, OLD.message_id, 0, OLD.received_at, NULL, v_txid);
                PERFORM public.work_enqueue(
                    'search.index_batch',
                    jsonb_build_object('corpus', 'mail_attachment'),
                    'search.index_batch:mail_attachment',
                    now(),
                    0::smallint,
                    5
                );
                PERFORM public.work_enqueue(
                    'search.index_batch',
                    jsonb_build_object('corpus', 'mail'),
                    'search.index_batch:mail',
                    now(),
                    0::smallint,
                    5
                );
            END IF;
        ELSE
            SELECT m.mailbox_id INTO v_mailbox_id
              FROM public.messages m
             WHERE m.id = NEW.message_id AND m.received_at = NEW.received_at;
            INSERT INTO public.search_index_outbox (corpus, op, scope_id, entity_id, sub_id, received_at, content_sha256, txid)
            VALUES
                ('mail_attachment', 'upsert', COALESCE(v_mailbox_id, 0), NEW.message_id, NEW.id, NEW.received_at, NEW.blob_sha256, v_txid),
                ('mail', 'upsert', COALESCE(v_mailbox_id, 0), NEW.message_id, 0, NEW.received_at, NEW.blob_sha256, v_txid);
            IF NEW.blob_sha256 ~ '^[0-9a-f]{64}$'
               AND NOT EXISTS (
                   SELECT 1 FROM public.search_extracted_text et
                    WHERE et.content_sha256 = NEW.blob_sha256
               ) THEN
                PERFORM public.work_enqueue(
                    'search.extract',
                    jsonb_build_object(
                        'content_sha256', NEW.blob_sha256,
                        'storage_plane', 'blob',
                        'content_type', NEW.content_type,
                        'filename', NEW.filename
                    ),
                    'search.extract:blob:' || NEW.blob_sha256,
                    now(),
                    0::smallint,
                    5
                );
            END IF;
            PERFORM public.work_enqueue(
                'search.index_batch',
                jsonb_build_object('corpus', 'mail_attachment'),
                'search.index_batch:mail_attachment',
                now(),
                0::smallint,
                5
            );
            PERFORM public.work_enqueue(
                'search.index_batch',
                jsonb_build_object('corpus', 'mail'),
                'search.index_batch:mail',
                now(),
                0::smallint,
                5
            );
        END IF;
    ELSIF v_src = 'chat_messages' THEN
        IF TG_OP = 'DELETE' THEN
            INSERT INTO public.search_index_outbox (corpus, op, scope_id, entity_id, sub_id, received_at, txid)
            VALUES ('chat', 'delete', OLD.channel_id, OLD.id, 0, OLD.created_at, v_txid);
        ELSE
            INSERT INTO public.search_index_outbox (corpus, op, scope_id, entity_id, sub_id, received_at, txid)
            VALUES ('chat', 'upsert', NEW.channel_id, NEW.id, 0, NEW.created_at, v_txid);
        END IF;
        PERFORM public.work_enqueue(
            'search.index_batch',
            jsonb_build_object('corpus', 'chat'),
            'search.index_batch:chat',
            now(),
            0::smallint,
            5
        );
    ELSIF v_src = 'chat_message_revisions' THEN
        IF TG_OP = 'DELETE' THEN
            INSERT INTO public.search_index_outbox (corpus, op, scope_id, entity_id, sub_id, received_at, txid)
            VALUES ('chat', 'upsert', OLD.channel_id, OLD.message_id, 0, OLD.created_at, v_txid);
        ELSE
            INSERT INTO public.search_index_outbox (corpus, op, scope_id, entity_id, sub_id, received_at, txid)
            VALUES ('chat', 'upsert', NEW.channel_id, NEW.message_id, 0, NEW.created_at, v_txid);
        END IF;
        PERFORM public.work_enqueue(
            'search.index_batch',
            jsonb_build_object('corpus', 'chat'),
            'search.index_batch:chat',
            now(),
            0::smallint,
            5
        );
    ELSIF v_src = 'chat_message_attachments' THEN
        IF TG_OP = 'DELETE' THEN
            INSERT INTO public.search_index_outbox (corpus, op, scope_id, entity_id, sub_id, received_at, txid)
            VALUES ('chat', 'upsert', OLD.channel_id, OLD.message_id, 0, OLD.created_at, v_txid);
        ELSE
            INSERT INTO public.search_index_outbox (corpus, op, scope_id, entity_id, sub_id, received_at, txid)
            VALUES ('chat', 'upsert', NEW.channel_id, NEW.message_id, 0, NEW.created_at, v_txid);
        END IF;
        PERFORM public.work_enqueue(
            'search.index_batch',
            jsonb_build_object('corpus', 'chat'),
            'search.index_batch:chat',
            now(),
            0::smallint,
            5
        );
    ELSIF v_src = 'drive_nodes' THEN
        IF TG_OP = 'DELETE' THEN
            INSERT INTO public.search_index_outbox (corpus, op, scope_id, entity_id, sub_id, received_at, txid)
            VALUES ('drive', 'delete', OLD.space_id, OLD.id, 0, OLD.created_at, v_txid);
        ELSE
            INSERT INTO public.search_index_outbox (corpus, op, scope_id, entity_id, sub_id, received_at, txid)
            VALUES ('drive', 'upsert', NEW.space_id, NEW.id, 0, NEW.created_at, v_txid);
        END IF;
        PERFORM public.work_enqueue(
            'search.index_batch',
            jsonb_build_object('corpus', 'drive'),
            'search.index_batch:drive',
            now(),
            0::smallint,
            5
        );
    ELSIF v_src = 'drive_file_versions' THEN
        IF TG_OP = 'DELETE' THEN
            INSERT INTO public.search_index_outbox (corpus, op, scope_id, entity_id, sub_id, received_at, content_sha256, txid)
            VALUES ('drive_file', 'delete', OLD.space_id, OLD.file_node_id, OLD.id, OLD.created_at, OLD.content_sha256, v_txid);
            PERFORM public.work_enqueue(
                'search.index_batch',
                jsonb_build_object('corpus', 'drive_file'),
                'search.index_batch:drive_file',
                now(),
                0::smallint,
                5
            );
        ELSE
            INSERT INTO public.search_index_outbox (corpus, op, scope_id, entity_id, sub_id, received_at, content_sha256, txid)
            VALUES
                ('drive_file', 'upsert', NEW.space_id, NEW.file_node_id, NEW.id, NEW.created_at, NEW.content_sha256, v_txid),
                ('drive', 'upsert', NEW.space_id, NEW.file_node_id, 0, NEW.created_at, NEW.content_sha256, v_txid);
            IF NEW.content_sha256 ~ '^[0-9a-f]{64}$'
               AND NOT EXISTS (
                   SELECT 1 FROM public.search_extracted_text et
                    WHERE et.content_sha256 = NEW.content_sha256
               ) THEN
                SELECT dn.name INTO v_name
                  FROM public.drive_nodes dn
                 WHERE dn.id = NEW.file_node_id;
                PERFORM public.work_enqueue(
                    'search.extract',
                    jsonb_build_object(
                        'content_sha256', NEW.content_sha256,
                        'storage_plane', 'drive_file_version',
                        'drive_version_id', NEW.id,
                        'content_type', NEW.content_type,
                        'filename', v_name
                    ),
                    'search.extract:drive_file_version:' || NEW.content_sha256,
                    now(),
                    0::smallint,
                    5
                );
            END IF;
            PERFORM public.work_enqueue(
                'search.index_batch',
                jsonb_build_object('corpus', 'drive_file'),
                'search.index_batch:drive_file',
                now(),
                0::smallint,
                5
            );
            PERFORM public.work_enqueue(
                'search.index_batch',
                jsonb_build_object('corpus', 'drive'),
                'search.index_batch:drive',
                now(),
                0::smallint,
                5
            );
        END IF;
    ELSIF v_src = 'scheduled_actions' THEN
        IF TG_OP = 'DELETE' THEN
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
                v_chan_text := COALESCE(NULLIF(OLD.payload->>'channelId', ''), NULLIF(OLD.payload->>'channel_id', ''));
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
            INSERT INTO public.search_index_outbox (corpus, op, scope_id, entity_id, sub_id, received_at, action_id, txid)
            VALUES (v_corpus, 'delete', v_scope_id, v_entity_id, 0, OLD.fire_at, OLD.id, v_txid);
            PERFORM public.work_enqueue(
                'search.index_batch',
                jsonb_build_object('corpus', v_corpus),
                'search.index_batch:' || v_corpus,
                now(),
                0::smallint,
                5
            );
        ELSE
            v_is_chat := (
                lower(NEW.action_kind) LIKE '%chat%'
                OR (NEW.payload ? 'channelId')
                OR (NEW.payload ? 'channel_id')
            );
            IF NOT v_is_chat AND NEW.action_kind <> 'send' AND NEW.mailbox_id IS NULL THEN
                RETURN NEW;
            END IF;
            v_corpus := CASE WHEN v_is_chat THEN 'chat' ELSE 'mail' END;
            v_entity_id := public.search_scheduled_action_doc_id(NEW.id);
            IF v_is_chat THEN
                v_chan_text := COALESCE(NULLIF(NEW.payload->>'channelId', ''), NULLIF(NEW.payload->>'channel_id', ''));
                BEGIN
                    v_scope_id := COALESCE(v_chan_text::bigint, 0);
                EXCEPTION WHEN OTHERS THEN
                    v_scope_id := 0;
                END;
            ELSE
                v_mb_text := NULLIF(NEW.payload->>'mailbox_id', '');
                BEGIN
                    v_scope_id := COALESCE(NEW.mailbox_id, v_mb_text::bigint, 0);
                EXCEPTION WHEN OTHERS THEN
                    v_scope_id := COALESCE(NEW.mailbox_id, 0);
                END;
            END IF;
            IF TG_OP = 'UPDATE' AND NOT v_is_chat AND OLD.fire_at IS DISTINCT FROM NEW.fire_at THEN
                INSERT INTO public.search_index_outbox (corpus, op, scope_id, entity_id, sub_id, received_at, action_id, txid)
                VALUES ('mail', 'delete', v_scope_id, v_entity_id, 0, OLD.fire_at, OLD.id, v_txid);
            END IF;
            v_op := CASE WHEN NEW.status = 'done' THEN 'delete' ELSE 'upsert' END;
            INSERT INTO public.search_index_outbox (corpus, op, scope_id, entity_id, sub_id, received_at, action_id, txid)
            VALUES (v_corpus, v_op, v_scope_id, v_entity_id, 0, NEW.fire_at, NEW.id, v_txid);
            PERFORM public.work_enqueue(
                'search.index_batch',
                jsonb_build_object('corpus', v_corpus),
                'search.index_batch:' || v_corpus,
                now(),
                0::smallint,
                5
            );
        END IF;
    END IF;

    RETURN COALESCE(NEW, OLD);
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
        ALTER FUNCTION public.search_index_outbox_trg_fn() OWNER TO setjoin_worker;
        IF NOT v_had_create THEN
            REVOKE CREATE ON SCHEMA public FROM setjoin_worker;
        END IF;
    END IF;

    FOREACH v_sig IN ARRAY ARRAY[
        'public.search_scheduled_action_doc_id(uuid)',
        'public.search_extracted_text_gc_sweep(integer,integer)',
        'public.search_outbox_enqueue(text,text,bigint,bigint,bigint,timestamptz,text,uuid)',
        'public.search_outbox_claim_batch(text,bigint,integer)',
        'public.search_outbox_mark_processed(bigint[])',
        'public.search_watermark_advance(text,bigint,bigint,bigint,text)',
        'public.search_index_outbox_trg_fn()'
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

-- 6. Attach gated write-capture triggers across all 8 indexed domain tables.
--    Passing the logical table name as TG_ARGV[0] guarantees partitioned tables
--    (e.g. public.messages -> messages_YYYY_MM / messages_default) match cleanly.
DROP TRIGGER IF EXISTS trg_search_outbox_messages_before_delete ON public.messages;
CREATE TRIGGER trg_search_outbox_messages_before_delete
    BEFORE DELETE ON public.messages
    FOR EACH ROW EXECUTE FUNCTION public.search_index_outbox_trg_fn('messages_before_delete');

DROP TRIGGER IF EXISTS trg_search_outbox_messages ON public.messages;
CREATE TRIGGER trg_search_outbox_messages
    AFTER INSERT OR UPDATE OR DELETE ON public.messages
    FOR EACH ROW EXECUTE FUNCTION public.search_index_outbox_trg_fn('messages');

DROP TRIGGER IF EXISTS trg_search_outbox_message_attachments ON public.message_attachments;
CREATE TRIGGER trg_search_outbox_message_attachments
    AFTER INSERT OR UPDATE OR DELETE ON public.message_attachments
    FOR EACH ROW EXECUTE FUNCTION public.search_index_outbox_trg_fn('message_attachments');

DROP TRIGGER IF EXISTS trg_search_outbox_chat_messages ON public.chat_messages;
CREATE TRIGGER trg_search_outbox_chat_messages
    AFTER INSERT OR UPDATE OR DELETE ON public.chat_messages
    FOR EACH ROW EXECUTE FUNCTION public.search_index_outbox_trg_fn('chat_messages');

DROP TRIGGER IF EXISTS trg_search_outbox_chat_message_revisions ON public.chat_message_revisions;
CREATE TRIGGER trg_search_outbox_chat_message_revisions
    AFTER INSERT OR UPDATE OR DELETE ON public.chat_message_revisions
    FOR EACH ROW EXECUTE FUNCTION public.search_index_outbox_trg_fn('chat_message_revisions');

DROP TRIGGER IF EXISTS trg_search_outbox_chat_message_attachments ON public.chat_message_attachments;
CREATE TRIGGER trg_search_outbox_chat_message_attachments
    AFTER INSERT OR UPDATE OR DELETE ON public.chat_message_attachments
    FOR EACH ROW EXECUTE FUNCTION public.search_index_outbox_trg_fn('chat_message_attachments');

DROP TRIGGER IF EXISTS trg_search_outbox_drive_nodes ON public.drive_nodes;
CREATE TRIGGER trg_search_outbox_drive_nodes
    AFTER INSERT OR UPDATE OR DELETE ON public.drive_nodes
    FOR EACH ROW EXECUTE FUNCTION public.search_index_outbox_trg_fn('drive_nodes');

DROP TRIGGER IF EXISTS trg_search_outbox_drive_file_versions ON public.drive_file_versions;
CREATE TRIGGER trg_search_outbox_drive_file_versions
    AFTER INSERT OR UPDATE OR DELETE ON public.drive_file_versions
    FOR EACH ROW EXECUTE FUNCTION public.search_index_outbox_trg_fn('drive_file_versions');

DROP TRIGGER IF EXISTS trg_search_outbox_scheduled_actions ON public.scheduled_actions;
CREATE TRIGGER trg_search_outbox_scheduled_actions
    AFTER INSERT OR UPDATE OR DELETE ON public.scheduled_actions
    FOR EACH ROW EXECUTE FUNCTION public.search_index_outbox_trg_fn('scheduled_actions');

INSERT INTO public.schema_migrations (version, applied_at) VALUES (298, now())
    ON CONFLICT (version) DO NOTHING;

COMMIT;
