-- V167: durable Identity Model Modernization operator jobs and diagnostics.
--
-- Identity jobs are cross-person operator work and are therefore worker-only:
-- FORCE RLS with no application policy. The public gateway is a thin caller of
-- SECURITY DEFINER reducers owned by setjoin_worker. Jobs retain bounded,
-- sanitized facts for seven days and never store credentials or raw subjects.

CREATE TABLE public.identity_jobs (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind                TEXT NOT NULL CHECK (
        kind IN ('upgrade_backfill','diagnostics','cohort_preview')
    ),
    state               TEXT NOT NULL DEFAULT 'queued' CHECK (
        state IN (
            'queued','running','completed','completed_with_failures',
            'failed','cancelled','expired'
        )
    ),
    actor_user_id       BIGINT NOT NULL
                            REFERENCES public.users(id) ON DELETE RESTRICT,
    source_id           BIGINT
                            REFERENCES public.identity_sources(id) ON DELETE RESTRICT,
    transition_id       UUID
                            REFERENCES public.identity_transitions(id) ON DELETE RESTRICT,
    snapshot_id         UUID NOT NULL DEFAULT gen_random_uuid(),
    idempotency_key     UUID NOT NULL,
    request_digest      BYTEA NOT NULL CHECK (octet_length(request_digest) = 32),
    request             JSONB NOT NULL CHECK (
                            jsonb_typeof(request) = 'object'
                            AND octet_length(request::text) <= 65536
                        ),
    progress            JSONB NOT NULL DEFAULT
                            '{"processed":0,"failed":0}'::jsonb CHECK (
                            jsonb_typeof(progress) = 'object'
                            AND octet_length(progress::text) <= 65536
                        ),
    next_action         TEXT NOT NULL DEFAULT 'wait' CHECK (
                            octet_length(next_action) BETWEEN 1 AND 256
                            AND next_action !~ '[[:cntrl:]]'
                        ),
    reason              TEXT NOT NULL CHECK (
                            octet_length(reason) BETWEEN 1 AND 1024
                            AND reason !~ '[[:cntrl:]]'
                        ),
    cancel_requested    BOOLEAN NOT NULL DEFAULT FALSE,
    worker_id           UUID,
    lease_expires_at    TIMESTAMPTZ,
    attempt_count       INTEGER NOT NULL DEFAULT 0 CHECK (
                            attempt_count BETWEEN 0 AND 20
                        ),
    artifact            BYTEA,
    artifact_sha256     BYTEA,
    artifact_manifest   JSONB,
    redaction_counts    JSONB,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    started_at          TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    expires_at          TIMESTAMPTZ NOT NULL DEFAULT
                            (statement_timestamp() + interval '7 days'),
    CONSTRAINT identity_jobs_actor_idempotency_key
        UNIQUE (actor_user_id, kind, idempotency_key),
    CONSTRAINT identity_jobs_scope_check CHECK (
        (kind = 'diagnostics'
         AND (source_id IS NULL) <> (transition_id IS NULL))
        OR (kind <> 'diagnostics' AND transition_id IS NULL)
    ),
    CONSTRAINT identity_jobs_lease_check CHECK (
        (state = 'running' AND worker_id IS NOT NULL
                           AND lease_expires_at IS NOT NULL)
        OR (state <> 'running' AND worker_id IS NULL
                            AND lease_expires_at IS NULL)
    ),
    CONSTRAINT identity_jobs_terminal_check CHECK (
        (state IN (
            'completed','completed_with_failures','failed','cancelled','expired'
         ) AND completed_at IS NOT NULL)
        OR (state IN ('queued','running') AND completed_at IS NULL)
    ),
    CONSTRAINT identity_jobs_artifact_check CHECK (
        (artifact IS NULL AND artifact_sha256 IS NULL
                          AND artifact_manifest IS NULL
                          AND redaction_counts IS NULL)
        OR
        (kind = 'diagnostics'
         AND artifact IS NOT NULL
         AND octet_length(artifact) <= 26214400
         AND octet_length(artifact_sha256) = 32
         AND jsonb_typeof(artifact_manifest) = 'object'
         AND jsonb_typeof(redaction_counts) = 'object')
    ),
    CONSTRAINT identity_jobs_expiry_check CHECK (
        expires_at > created_at
        AND expires_at <= created_at + interval '7 days 5 minutes'
    )
);

CREATE INDEX identity_jobs_claim_idx
    ON public.identity_jobs (state, updated_at, created_at)
    WHERE state IN ('queued','running');
CREATE INDEX identity_jobs_actor_created_idx
    ON public.identity_jobs (actor_user_id, created_at DESC);
CREATE INDEX identity_jobs_source_created_idx
    ON public.identity_jobs (source_id, created_at DESC)
    WHERE source_id IS NOT NULL;
CREATE INDEX identity_jobs_transition_created_idx
    ON public.identity_jobs (transition_id, created_at DESC)
    WHERE transition_id IS NOT NULL;
CREATE INDEX identity_jobs_expiry_idx
    ON public.identity_jobs (expires_at)
    WHERE state IN (
        'completed','completed_with_failures','failed','cancelled'
    );

CREATE TABLE public.identity_job_results (
    job_id              UUID NOT NULL
                            REFERENCES public.identity_jobs(id) ON DELETE RESTRICT,
    sequence            BIGINT NOT NULL CHECK (sequence > 0),
    user_id             BIGINT REFERENCES public.users(id) ON DELETE RESTRICT,
    state               TEXT NOT NULL CHECK (
                            state IN ('completed','failed','skipped','blocked')
                        ),
    result              JSONB NOT NULL CHECK (
                            jsonb_typeof(result) = 'object'
                            AND octet_length(result::text) <= 65536
                        ),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (job_id, sequence)
);

CREATE INDEX identity_job_results_user_idx
    ON public.identity_job_results (user_id, job_id)
    WHERE user_id IS NOT NULL;
CREATE UNIQUE INDEX identity_job_results_job_user_key
    ON public.identity_job_results (job_id, user_id)
    WHERE user_id IS NOT NULL;

ALTER TABLE public.identity_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.identity_jobs FORCE ROW LEVEL SECURITY;
ALTER TABLE public.identity_jobs OWNER TO setjoin_owner;
ALTER TABLE public.identity_job_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.identity_job_results FORCE ROW LEVEL SECURITY;
ALTER TABLE public.identity_job_results OWNER TO setjoin_owner;

INSERT INTO public.schema_migrations (version, applied_at)
VALUES (167, now()) ON CONFLICT (version) DO NOTHING;
