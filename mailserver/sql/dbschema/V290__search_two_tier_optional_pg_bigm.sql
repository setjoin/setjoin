-- V290__search_two_tier_optional_pg_bigm.sql — Wave 3.1 (#556):
-- Two-Tier SearchEngine seam, optional pg_bigm Tier-1 acceleration probe,
-- and worker-only freshness fencing tables (search_dirty_keys, search_index_watermarks).
--
-- Non-negotiable invariants:
--   1. pg_bigm is strictly OPTIONAL: never fail when pg_bigm is unavailable
--      (Xinchuang / managed PostgreSQL / local PG17 without pg_bigm).
--   2. Zero feature_toggles seed rows added (Tier-2 opt-in via env
--      SETJOIN_SEARCH_TIER2_ENABLED=true; V275 goldens untouched).
--   3. Zero blobs columns added (Wave 3.2 owns content extraction schema).
--   4. search_dirty_keys and search_index_watermarks are worker-only system
--      tables with ENABLE + FORCE ROW LEVEL SECURITY, ZERO policies (deny-all
--      to setjoin_app and PUBLIC), owned by setjoin_owner, with table grants
--      restricted to setjoin_worker (restated in scripts/provision-roles.sql).

BEGIN;

-- 1. Optional pg_bigm extension & indexes (never fatal when unavailable).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'pg_bigm') THEN
        BEGIN
            CREATE EXTENSION IF NOT EXISTS pg_bigm;
        EXCEPTION
            WHEN insufficient_privilege OR undefined_file OR feature_not_supported THEN
                RAISE NOTICE 'V290: pg_bigm unavailable or unprivileged; continuing with Tier-1 baseline';
        END;
    END IF;
END
$$;

DO $$
DECLARE
    v_bigm_schema text;
BEGIN
    SELECT n.nspname
      INTO v_bigm_schema
      FROM pg_extension e
      JOIN pg_namespace n ON n.oid = e.extnamespace
     WHERE e.extname = 'pg_bigm';

    IF v_bigm_schema IS NOT NULL THEN
        BEGIN
            EXECUTE format(
                'CREATE INDEX IF NOT EXISTS chat_messages_body_bigm_idx ON public.chat_messages USING gin (lower(body) %I.gin_bigm_ops)',
                v_bigm_schema
            );
            EXECUTE format(
                'CREATE INDEX IF NOT EXISTS drive_nodes_name_bigm_idx ON public.drive_nodes USING gin (lower(name) %I.gin_bigm_ops)',
                v_bigm_schema
            );
        EXCEPTION
            WHEN OTHERS THEN
                RAISE NOTICE 'V290: optional pg_bigm index creation skipped (%): %', SQLSTATE, SQLERRM;
        END;
    END IF;
END
$$;

-- 2. Worker-only coalescing dirty-key staging table for freshness fencing and
--    Wave 3.2 WorkQueue incremental indexing (preserving V283 composite
--    (id, received_at_us) mail keys and reserved attachment/file sub_id).
CREATE TABLE IF NOT EXISTS public.search_dirty_keys (
    corpus         text        NOT NULL
                   CHECK (corpus IN ('mail', 'chat', 'drive', 'mail_attachment', 'drive_file')),
    scope_id       bigint      NOT NULL,
    doc_id         bigint      NOT NULL,
    received_at_us bigint      NOT NULL DEFAULT 0,
    sub_id         bigint      NOT NULL DEFAULT 0,
    op             text        NOT NULL CHECK (op IN ('upsert', 'delete')),
    generation     bigint      NOT NULL DEFAULT 0 CHECK (generation >= 0),
    dirty_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (corpus, scope_id, doc_id, received_at_us, sub_id)
);

CREATE INDEX IF NOT EXISTS search_dirty_keys_corpus_dirty_idx
    ON public.search_dirty_keys (corpus, dirty_at, scope_id);

-- 3. Worker-only per-corpus search index watermark fence.
CREATE TABLE IF NOT EXISTS public.search_index_watermarks (
    corpus       text        PRIMARY KEY
                 CHECK (corpus IN ('mail', 'chat', 'drive', 'mail_attachment', 'drive_file')),
    epoch        bigint      NOT NULL DEFAULT 0 CHECK (epoch >= 0),
    generation   bigint      NOT NULL DEFAULT 0 CHECK (generation >= 0),
    schema_hash  text        NOT NULL DEFAULT '',
    watermark_ts timestamptz NOT NULL DEFAULT 'epoch'::timestamptz,
    updated_at   timestamptz NOT NULL DEFAULT now()
);

-- Deny-all FORCE RLS on both worker-only search staging tables (zero policies).
ALTER TABLE public.search_dirty_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.search_dirty_keys FORCE ROW LEVEL SECURITY;

ALTER TABLE public.search_index_watermarks ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.search_index_watermarks FORCE ROW LEVEL SECURITY;

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['search_dirty_keys', 'search_index_watermarks'] LOOP
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
END
$$;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (290, now())
    ON CONFLICT (version) DO NOTHING;

COMMIT;
