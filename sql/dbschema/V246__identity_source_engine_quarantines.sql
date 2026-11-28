-- V246: Directory-sync engine durable quarantine accounting (med-shard2-012).
--
-- The normalized directory-sync engine skips two object classes instead of
-- staging them: objects without an immutable subject and in-scope upserts
-- without a usable mail attribute (the deterministic BZ228 block class).
-- Skipping is required so one malformed object cannot wedge the source
-- cursor every cycle, but the skip previously left only a process-local log
-- line: after the page cursor advanced, later incremental pages need not
-- repeat the object, so the sole evidence of the owed review work was lost
-- on restart. This ledger gives the engine a durable, source-scoped
-- quarantine record that is written BEFORE the page cursor is acknowledged
-- (identity_source_quarantine_record reducer), keyed by source + object key
-- + reason so re-traversals accumulate occurrences instead of duplicating
-- evidence. Row retention is deliberate: the accounting survives cursor
-- advancement and process restarts until an operator resolves the source
-- condition and retires the row.
--
-- Isolation posture mirrors the identity substrate (V156/V158): ENABLE+FORCE
-- RLS with zero permissive policies — fail-closed deny for every runtime
-- role; access flows only through the SECURITY DEFINER reducer driven by the
-- BYPASSRLS sync worker. Denial is proved by
-- tests/identity_source_engine_quarantine.pg.

CREATE TABLE public.identity_source_quarantines (
    source_id            BIGINT NOT NULL
                         REFERENCES public.identity_sources(id) ON DELETE RESTRICT,
    object_key           TEXT NOT NULL,
    reason_code          TEXT NOT NULL,
    subject_digest       BYTEA NOT NULL CHECK (octet_length(subject_digest) = 32),
    last_generation      BIGINT NOT NULL CHECK (last_generation > 0),
    occurrences          BIGINT NOT NULL DEFAULT 1 CHECK (occurrences > 0),
    first_quarantined_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    last_quarantined_at  TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (source_id, object_key, reason_code),
    CONSTRAINT identity_source_quarantines_object_key_check CHECK (
        octet_length(object_key) BETWEEN 1 AND 512
        AND object_key !~ '[[:cntrl:]]'
    ),
    CONSTRAINT identity_source_quarantines_reason_code_check CHECK (
        reason_code ~ '^[A-Z0-9_.:-]{1,64}$'
    )
);

CREATE INDEX identity_source_quarantines_recent_idx
    ON public.identity_source_quarantines (last_quarantined_at DESC);

ALTER TABLE public.identity_source_quarantines ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.identity_source_quarantines FORCE ROW LEVEL SECURITY;
ALTER TABLE public.identity_source_quarantines OWNER TO setjoin_owner;

INSERT INTO public.schema_migrations (version, applied_at)
VALUES (246, now());
