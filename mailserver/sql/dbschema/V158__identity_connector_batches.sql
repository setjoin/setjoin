-- V158: Identity Model Modernization I2 connector durability.
--
-- Discovery and application are deliberately separate. A connector first
-- persists one bounded page plus its remote cursor, then workers apply the
-- inbox rows. The committed source cursor advances only after the whole batch
-- is terminal. Source generations fence stale workers before any person write.

ALTER TABLE public.identity_sync_log
    DROP CONSTRAINT identity_sync_log_source_check;
ALTER TABLE public.identity_sync_log
    ADD CONSTRAINT identity_sync_log_source_check
    CHECK (source IN ('ad','ldap','scim','manual'));

CREATE TABLE public.identity_source_batches (
    source_id             BIGINT NOT NULL
                          REFERENCES public.identity_sources(id) ON DELETE RESTRICT,
    batch_id              UUID NOT NULL,
    source_generation     BIGINT NOT NULL CHECK (source_generation > 0),
    remote_cursor         JSONB NOT NULL,
    remote_cursor_digest  BYTEA NOT NULL CHECK (octet_length(remote_cursor_digest) = 32),
    state                 TEXT NOT NULL DEFAULT 'staged',
    entry_count           INTEGER NOT NULL CHECK (entry_count BETWEEN 0 AND 500),
    applied_count         INTEGER NOT NULL DEFAULT 0 CHECK (applied_count >= 0),
    quarantined_count     INTEGER NOT NULL DEFAULT 0 CHECK (quarantined_count >= 0),
    last_error_code       TEXT,
    discovered_at         TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    started_at            TIMESTAMPTZ,
    completed_at          TIMESTAMPTZ,
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (source_id, batch_id),
    CONSTRAINT identity_source_batches_state_check CHECK (
        state IN ('staged','draining','blocked','completed')
    ),
    CONSTRAINT identity_source_batches_counts_check CHECK (
        applied_count + quarantined_count <= entry_count
    ),
    CONSTRAINT identity_source_batches_terminal_check CHECK (
        (state = 'completed'
         AND completed_at IS NOT NULL
         AND applied_count + quarantined_count = entry_count)
        OR
        (state <> 'completed' AND completed_at IS NULL)
    )
);

CREATE UNIQUE INDEX identity_source_batches_one_open_idx
    ON public.identity_source_batches (source_id)
    WHERE state <> 'completed';
CREATE INDEX identity_source_batches_work_idx
    ON public.identity_source_batches (state, updated_at);

ALTER TABLE public.identity_source_batches ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.identity_source_batches FORCE ROW LEVEL SECURITY;
ALTER TABLE public.identity_source_batches OWNER TO setjoin_owner;

-- Retrying the legacy backfill or a connector collision must not create an
-- unbounded stack of identical undecided evidence.
CREATE UNIQUE INDEX identity_match_candidates_open_fact_key
    ON public.identity_match_candidates (
        source_id, external_subject, candidate_user_id, evidence_class, generation
    ) NULLS NOT DISTINCT
    WHERE status IN ('pending','deferred');

-- A source kind is as durable as its key. Converting an AD source into LDAP or
-- OIDC would reinterpret subjects and retained tombstones.
CREATE FUNCTION public.identity_source_kind_immutable()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NEW.kind IS DISTINCT FROM OLD.kind THEN
        RAISE EXCEPTION 'identity source kind is immutable'
            USING ERRCODE = 'BZ228',
                  HINT = '{"type":"identity_source_invalid","field":"kind","remediation":"create a new source for a different connector kind"}';
    END IF;
    RETURN NEW;
END;
$$;
SELECT public.apply_worker_ownership(
    'public.identity_source_kind_immutable()'::regprocedure
);

CREATE TRIGGER identity_sources_kind_immutable
    BEFORE UPDATE OF kind ON public.identity_sources
    FOR EACH ROW EXECUTE FUNCTION public.identity_source_kind_immutable();

-- I2 needs explicit connector facts while keeping the I1 ledger append-only.
ALTER TABLE public.identity_link_events
    DROP CONSTRAINT identity_link_events_action_check;
ALTER TABLE public.identity_link_events
    ADD CONSTRAINT identity_link_events_action_check CHECK (
        action IN (
            'source_created','source_updated','source_entry_applied',
            'source_entry_quarantined','source_cursor_committed',
            'candidate_recorded','link_activated','link_suspended',
            'link_detached','link_relinked','authority_changed',
            'conflict_decided','legacy_backfilled'
        )
    );

INSERT INTO public.schema_migrations (version, applied_at)
VALUES (158, now());
