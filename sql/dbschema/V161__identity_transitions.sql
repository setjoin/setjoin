-- V161: authoritative, restart-safe identity transition protocol.
--
-- This migration is expand-only. All three identity rollout flags remain OFF.
-- The reducers own every legal state transition; the tables are worker-only
-- FORCE-RLS evidence and orchestration state.

ALTER TABLE public.approval_policies
    DROP CONSTRAINT approval_policies_consumer_type_check;
ALTER TABLE public.approval_policies
    ADD CONSTRAINT approval_policies_consumer_type_check
    CHECK (consumer_type IN (
        'rbac.jit_activation','mail.external_send','mail.group_moderation',
        'hr.leave','hr.expense','drive.share','drive.export','guest.invite',
        'identity.transition'
    ));
ALTER TABLE public.approval_requests
    DROP CONSTRAINT approval_requests_consumer_type_check;
ALTER TABLE public.approval_requests
    ADD CONSTRAINT approval_requests_consumer_type_check
    CHECK (consumer_type IN (
        'rbac.jit_activation','mail.external_send','mail.group_moderation',
        'hr.leave','hr.expense','drive.share','drive.export','guest.invite',
        'identity.transition'
    ));

-- Disabled until an operator selects an independent break-glass approver.
INSERT INTO public.approval_policies(
    consumer_type,name,enabled,priority,conditions,requires_approval,approver_spec
) VALUES(
    'identity.transition',
    'Protected identity transition',
    false,
    100,
    '{"protected":true}'::jsonb,
    true,
    '{"kind":"default_admin"}'::jsonb
) ON CONFLICT(consumer_type,priority) DO NOTHING;

CREATE TABLE public.identity_transitions (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                  BIGINT NOT NULL
                                 REFERENCES public.users(id) ON DELETE RESTRICT,
    kind                     TEXT NOT NULL
                                 CHECK (kind IN ('directory_to_local')),
    state                    TEXT NOT NULL DEFAULT 'draft' CHECK (
        state IN (
            'draft','previewed','awaiting_approval','authorized','executing',
            'authority_committed','effects_pending','completed',
            'failed_precommit','failed_recoverable','rollback_previewed',
            'rolling_back','rolled_back','cancelled','expired'
        )
    ),
    transition_generation    BIGINT NOT NULL DEFAULT 1
                                 CHECK (transition_generation > 0),
    source_id                BIGINT NOT NULL
                                 REFERENCES public.identity_sources(id)
                                 ON DELETE RESTRICT,
    link_id                  BIGINT NOT NULL
                                 REFERENCES public.user_identity_links(id)
                                 ON DELETE RESTRICT,
    source_generation        BIGINT NOT NULL CHECK (source_generation > 0),
    link_generation          BIGINT NOT NULL CHECK (link_generation > 0),
    lifecycle_generation     BIGINT NOT NULL CHECK (lifecycle_generation > 0),
    preview_version          BIGINT NOT NULL DEFAULT 1
                                 CHECK (preview_version > 0),
    preview_digest           BYTEA NOT NULL
                                 CHECK (octet_length(preview_digest) = 32),
    preview_snapshot         JSONB NOT NULL
                                 CHECK (jsonb_typeof(preview_snapshot) = 'object'),
    preview_expires_at       TIMESTAMPTZ NOT NULL,
    actor_user_id            BIGINT NOT NULL
                                 REFERENCES public.users(id) ON DELETE RESTRICT,
    approval_request_id      BIGINT
                                 REFERENCES public.approval_requests(id)
                                 ON DELETE RESTRICT,
    requester_elevation_id   UUID,
    approver_elevation_id    UUID,
    execution_elevation_id   UUID,
    requested_at             TIMESTAMPTZ,
    requested_generation     BIGINT CHECK (requested_generation > 0),
    approved_by_user_id      BIGINT
                                 REFERENCES public.users(id) ON DELETE RESTRICT,
    approved_at              TIMESTAMPTZ,
    authorized_at            TIMESTAMPTZ,
    authorized_generation    BIGINT CHECK (authorized_generation > 0),
    reason                   TEXT NOT NULL CHECK (
        octet_length(reason) BETWEEN 1 AND 1024
        AND reason !~ '[[:cntrl:]]'
    ),
    idempotency_key          UUID NOT NULL,
    request_digest           BYTEA NOT NULL
                                 CHECK (octet_length(request_digest) = 32),
    protected                BOOLEAN NOT NULL DEFAULT false,
    rollback_boundary        TEXT NOT NULL DEFAULT 'not_committed' CHECK (
        rollback_boundary IN (
            'not_committed','reversible','new_login_observed',
            'irreversible_effect','window_expired','rolled_back'
        )
    ),
    authority_before         JSONB,
    committed_lifecycle_generation BIGINT
                                 CHECK (committed_lifecycle_generation > 0),
    committed_link_generation BIGINT
                                 CHECK (committed_link_generation > 0),
    rollback_preview_digest  BYTEA
                                 CHECK (rollback_preview_digest IS NULL
                                     OR octet_length(rollback_preview_digest)=32),
    rollback_preview_snapshot JSONB
                                 CHECK (rollback_preview_snapshot IS NULL
                                     OR jsonb_typeof(rollback_preview_snapshot)='object'),
    rollback_preview_expires_at TIMESTAMPTZ,
    rollback_reason           TEXT CHECK (
        rollback_reason IS NULL
        OR (octet_length(rollback_reason) BETWEEN 1 AND 1024
            AND rollback_reason !~ '[[:cntrl:]]')
    ),
    rollback_approval_request_id BIGINT
                                 REFERENCES public.approval_requests(id)
                                 ON DELETE RESTRICT,
    rollback_requester_elevation_id UUID,
    rollback_approver_elevation_id UUID,
    rollback_execution_elevation_id UUID,
    rollback_requested_at    TIMESTAMPTZ,
    rollback_requested_generation BIGINT
                                 CHECK (rollback_requested_generation > 0),
    rollback_approved_by_user_id BIGINT
                                 REFERENCES public.users(id) ON DELETE RESTRICT,
    rollback_approved_at     TIMESTAMPTZ,
    rollback_authorized_generation BIGINT
                                 CHECK (rollback_authorized_generation > 0),
    failure_code             TEXT,
    correlation_id           UUID NOT NULL DEFAULT gen_random_uuid(),
    started_at               TIMESTAMPTZ,
    committed_at             TIMESTAMPTZ,
    completed_at             TIMESTAMPTZ,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT identity_transitions_preview_expiry_check
        CHECK (preview_expires_at > created_at),
    CONSTRAINT identity_transitions_approval_pair_check
        CHECK (
            (approved_by_user_id IS NULL AND approved_at IS NULL)
            OR (approved_by_user_id IS NOT NULL AND approved_at IS NOT NULL)
        ),
    CONSTRAINT identity_transitions_rollback_preview_pair_check
        CHECK (
            (rollback_preview_digest IS NULL
             AND rollback_preview_snapshot IS NULL
             AND rollback_preview_expires_at IS NULL)
            OR
            (rollback_preview_digest IS NOT NULL
             AND rollback_preview_snapshot IS NOT NULL
             AND rollback_preview_expires_at IS NOT NULL)
        ),
    CONSTRAINT identity_transitions_rollback_approval_pair_check
        CHECK (
            (rollback_approved_by_user_id IS NULL
             AND rollback_approved_at IS NULL)
            OR
            (rollback_approved_by_user_id IS NOT NULL
             AND rollback_approved_at IS NOT NULL)
        ),
    UNIQUE(actor_user_id,kind,idempotency_key)
);
CREATE INDEX identity_transitions_user_idx
    ON public.identity_transitions(user_id,created_at DESC);
CREATE INDEX identity_transitions_source_idx
    ON public.identity_transitions(source_id,created_at DESC);
CREATE INDEX identity_transitions_state_idx
    ON public.identity_transitions(state,updated_at);
CREATE INDEX identity_transitions_approval_idx
    ON public.identity_transitions(approval_request_id)
    WHERE approval_request_id IS NOT NULL;
CREATE INDEX identity_transitions_correlation_idx
    ON public.identity_transitions(correlation_id);

CREATE TABLE public.identity_transition_steps (
    transition_id  UUID NOT NULL
                       REFERENCES public.identity_transitions(id)
                       ON DELETE RESTRICT,
    ordinal        SMALLINT NOT NULL CHECK (ordinal BETWEEN 1 AND 64),
    stage          TEXT NOT NULL CHECK (
        stage IN (
            'preview','request','approval','authority_commit',
            'auth_sessions','livekit_sessions','subscriber_notice',
            'rollback_preview','rollback_request','rollback_approval',
            'rollback_authority','rollback_auth_sessions',
            'rollback_livekit_sessions','rollback_subscriber_notice'
        )
    ),
    state          TEXT NOT NULL CHECK (
        state IN ('pending','running','completed','failed','disposed')
    ),
    attempt_count  INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 20),
    input_digest   BYTEA CHECK (
        input_digest IS NULL OR octet_length(input_digest)=32
    ),
    output_digest  BYTEA CHECK (
        output_digest IS NULL OR octet_length(output_digest)=32
    ),
    started_at     TIMESTAMPTZ,
    finished_at    TIMESTAMPTZ,
    retry_at       TIMESTAMPTZ,
    error_code     TEXT,
    error_detail   TEXT CHECK (
        error_detail IS NULL OR octet_length(error_detail) <= 2048
    ),
    PRIMARY KEY(transition_id,ordinal),
    UNIQUE(transition_id,stage)
);

CREATE TABLE public.identity_transition_elevations (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_user_id         BIGINT NOT NULL
                              REFERENCES public.users(id) ON DELETE RESTRICT,
    transition_id         UUID NOT NULL
                              REFERENCES public.identity_transitions(id)
                              ON DELETE RESTRICT,
    transition_generation BIGINT NOT NULL CHECK (transition_generation > 0),
    preview_digest        BYTEA NOT NULL CHECK (octet_length(preview_digest)=32),
    session_digest        BYTEA NOT NULL CHECK (octet_length(session_digest)=32),
    factor_digest         BYTEA NOT NULL CHECK (octet_length(factor_digest)=32),
    amr                   TEXT[] NOT NULL CHECK (cardinality(amr) BETWEEN 1 AND 16),
    acr                   TEXT NOT NULL CHECK (
        octet_length(acr) BETWEEN 1 AND 128 AND acr !~ '[[:cntrl:]]'
    ),
    issued_at             TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    expires_at            TIMESTAMPTZ NOT NULL,
    consumed_at           TIMESTAMPTZ,
    invalidated_at        TIMESTAMPTZ,
    idempotency_key       UUID NOT NULL,
    request_digest        BYTEA NOT NULL CHECK (octet_length(request_digest)=32),
    CONSTRAINT identity_transition_elevations_expiry_check
        CHECK (expires_at > issued_at AND expires_at <= issued_at + interval '5 minutes'),
    CONSTRAINT identity_transition_elevations_terminal_check
        CHECK (consumed_at IS NULL OR invalidated_at IS NULL),
    UNIQUE(actor_user_id,idempotency_key)
);
CREATE INDEX identity_transition_elevations_consume_idx
    ON public.identity_transition_elevations(
        transition_id,actor_user_id,expires_at
    ) WHERE consumed_at IS NULL AND invalidated_at IS NULL;

CREATE TABLE public.identity_transition_challenges (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_user_id         BIGINT NOT NULL
                              REFERENCES public.users(id) ON DELETE RESTRICT,
    transition_id         UUID NOT NULL
                              REFERENCES public.identity_transitions(id)
                              ON DELETE RESTRICT,
    transition_generation BIGINT NOT NULL CHECK (transition_generation > 0),
    preview_digest        BYTEA NOT NULL CHECK (octet_length(preview_digest)=32),
    handoff_method        TEXT NOT NULL DEFAULT 'browser'
                              CHECK (handoff_method='browser'),
    issued_at             TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    expires_at            TIMESTAMPTZ NOT NULL,
    completed_at          TIMESTAMPTZ,
    invalidated_at        TIMESTAMPTZ,
    elevation_id          UUID UNIQUE,
    idempotency_key       UUID NOT NULL,
    request_digest        BYTEA NOT NULL CHECK (octet_length(request_digest)=32),
    CONSTRAINT identity_transition_challenges_expiry_check
        CHECK (expires_at > issued_at
           AND expires_at <= issued_at + interval '5 minutes'),
    CONSTRAINT identity_transition_challenges_completion_check
        CHECK (
            (completed_at IS NULL AND elevation_id IS NULL)
            OR (completed_at IS NOT NULL AND elevation_id IS NOT NULL)
        ),
    CONSTRAINT identity_transition_challenges_terminal_check
        CHECK (completed_at IS NULL OR invalidated_at IS NULL),
    UNIQUE(actor_user_id,idempotency_key)
);
CREATE INDEX identity_transition_challenges_active_idx
    ON public.identity_transition_challenges(
        transition_id,actor_user_id,expires_at
    ) WHERE completed_at IS NULL AND invalidated_at IS NULL;

ALTER TABLE public.identity_transition_elevations
    ADD COLUMN challenge_id UUID NOT NULL UNIQUE
        REFERENCES public.identity_transition_challenges(id)
        ON DELETE RESTRICT;
ALTER TABLE public.identity_transition_challenges
    ADD CONSTRAINT identity_transition_challenges_elevation_fk
    FOREIGN KEY(elevation_id)
        REFERENCES public.identity_transition_elevations(id)
        ON DELETE RESTRICT;

CREATE TABLE public.identity_transition_idempotency (
    actor_user_id    BIGINT NOT NULL
                         REFERENCES public.users(id) ON DELETE RESTRICT,
    operation        TEXT NOT NULL CHECK (
        octet_length(operation) BETWEEN 1 AND 128
        AND operation !~ '[[:cntrl:]]'
    ),
    idempotency_key  UUID NOT NULL,
    transition_id    UUID NOT NULL
                         REFERENCES public.identity_transitions(id)
                         ON DELETE RESTRICT,
    request_digest   BYTEA NOT NULL CHECK (octet_length(request_digest)=32),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY(actor_user_id,operation,idempotency_key)
);

CREATE TABLE public.identity_transition_effects (
    transition_id      UUID NOT NULL
                           REFERENCES public.identity_transitions(id)
                           ON DELETE RESTRICT,
    effect_kind        TEXT NOT NULL CHECK (
        effect_kind IN (
            'auth_sessions','livekit_sessions','subscriber_notice',
            'rollback_auth_sessions','rollback_livekit_sessions',
            'rollback_subscriber_notice'
        )
    ),
    effect_id          UUID NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    state              TEXT NOT NULL DEFAULT 'pending' CHECK (
        state IN ('pending','running','completed','failed','disposed')
    ),
    attempt_count      INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 20),
    next_attempt_at    TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    worker_id          TEXT CHECK (
        worker_id IS NULL
        OR (octet_length(worker_id) BETWEEN 1 AND 255
            AND worker_id !~ '[[:cntrl:]]')
    ),
    lease_expires_at   TIMESTAMPTZ,
    last_error_code    TEXT,
    completed_at       TIMESTAMPTZ,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT identity_transition_effects_lease_check CHECK (
        (state='running' AND worker_id IS NOT NULL
                         AND lease_expires_at IS NOT NULL)
        OR (state<>'running' AND worker_id IS NULL
                          AND lease_expires_at IS NULL)
    ),
    PRIMARY KEY(transition_id,effect_kind)
);
CREATE INDEX identity_transition_effects_work_idx
    ON public.identity_transition_effects(state,next_attempt_at);
CREATE INDEX identity_transition_effects_transition_idx
    ON public.identity_transition_effects(transition_id,effect_id);

CREATE TABLE public.identity_transition_effect_targets (
    transition_id UUID NOT NULL,
    effect_kind   TEXT NOT NULL,
    target_key    TEXT NOT NULL CHECK (
        octet_length(target_key) BETWEEN 1 AND 2048
        AND target_key !~ '[[:cntrl:]]'
    ),
    completed_at  TIMESTAMPTZ,
    last_error    TEXT CHECK (
        last_error IS NULL OR octet_length(last_error) <= 2048
    ),
    PRIMARY KEY(transition_id,effect_kind,target_key),
    FOREIGN KEY(transition_id,effect_kind)
        REFERENCES public.identity_transition_effects(transition_id,effect_kind)
        ON DELETE RESTRICT
);

ALTER TABLE public.identity_transitions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.identity_transitions FORCE ROW LEVEL SECURITY;
ALTER TABLE public.identity_transition_steps ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.identity_transition_steps FORCE ROW LEVEL SECURITY;
ALTER TABLE public.identity_transition_elevations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.identity_transition_elevations FORCE ROW LEVEL SECURITY;
ALTER TABLE public.identity_transition_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.identity_transition_challenges FORCE ROW LEVEL SECURITY;
ALTER TABLE public.identity_transition_idempotency ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.identity_transition_idempotency FORCE ROW LEVEL SECURITY;
ALTER TABLE public.identity_transition_effects ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.identity_transition_effects FORCE ROW LEVEL SECURITY;
ALTER TABLE public.identity_transition_effect_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.identity_transition_effect_targets FORCE ROW LEVEL SECURITY;

ALTER TABLE public.identity_transitions OWNER TO setjoin_owner;
ALTER TABLE public.identity_transition_steps OWNER TO setjoin_owner;
ALTER TABLE public.identity_transition_elevations OWNER TO setjoin_owner;
ALTER TABLE public.identity_transition_challenges OWNER TO setjoin_owner;
ALTER TABLE public.identity_transition_idempotency OWNER TO setjoin_owner;
ALTER TABLE public.identity_transition_effects OWNER TO setjoin_owner;
ALTER TABLE public.identity_transition_effect_targets OWNER TO setjoin_owner;

ALTER TABLE public.identity_link_events
    DROP CONSTRAINT identity_link_events_action_check;
ALTER TABLE public.identity_link_events
    ADD CONSTRAINT identity_link_events_action_check CHECK (
        action IN (
            'source_created','source_updated','source_entry_applied',
            'source_entry_quarantined','source_cursor_committed',
            'candidate_recorded','link_activated','link_suspended',
            'link_detached','link_relinked','auth_resolved','auth_jit_created',
            'attribute_authority_applied','entitlements_reconciled',
            'transition_previewed','transition_requested',
            'transition_approval_requested','transition_approved',
            'transition_denied','transition_cancelled','transition_expired',
            'transition_executing','transition_committed',
            'transition_effect_retried','transition_failed',
            'transition_completed','transition_rollback_previewed',
            'transition_rollback_requested','transition_rollback_approved',
            'transition_rollback_started','transition_rolled_back',
            'authority_changed','conflict_decided','legacy_backfilled'
        )
    );

INSERT INTO public.schema_migrations(version, applied_at)
VALUES (161, now()) ON CONFLICT(version) DO NOTHING;
