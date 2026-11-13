-- V165: normalized identity-source operator lifecycle.
--
-- Source configuration remains opaque ciphertext to PostgreSQL.  One previous
-- envelope may be retained for a bounded credential-rotation grace period; it
-- is never returned by an API reader.  Operation receipts provide durable,
-- request-digest-bound idempotency for every source mutation.

ALTER TABLE public.identity_sources
    DROP CONSTRAINT identity_sources_state_check;
ALTER TABLE public.identity_sources
    ADD CONSTRAINT identity_sources_state_check CHECK (
        state IN ('draft','validated','active','paused','error','retired')
    );

ALTER TABLE public.identity_sources
    ADD COLUMN previous_config_envelope BYTEA,
    ADD COLUMN previous_config_key_version BIGINT,
    ADD COLUMN previous_config_expires_at TIMESTAMPTZ,
    ADD CONSTRAINT identity_sources_previous_config_check CHECK (
        (previous_config_envelope IS NULL
         AND previous_config_key_version IS NULL
         AND previous_config_expires_at IS NULL)
        OR
        (previous_config_envelope IS NOT NULL
         AND previous_config_key_version > 0
         AND previous_config_expires_at IS NOT NULL)
    );

CREATE TABLE public.identity_source_operations (
    idempotency_key UUID PRIMARY KEY,
    source_id BIGINT REFERENCES public.identity_sources(id) ON DELETE RESTRICT,
    actor_user_id BIGINT REFERENCES public.users(id) ON DELETE SET NULL,
    operation TEXT NOT NULL,
    request_digest BYTEA NOT NULL CHECK (octet_length(request_digest) = 32),
    result JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT identity_source_operations_operation_check CHECK (
        operation IN (
            'apply','set_secret','rotate_secret','validate',
            'activate','pause','resume','retire'
        )
    )
);
CREATE INDEX identity_source_operations_source_created_idx
    ON public.identity_source_operations (source_id, created_at DESC);
ALTER TABLE public.identity_source_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.identity_source_operations FORCE ROW LEVEL SECURITY;
ALTER TABLE public.identity_source_operations OWNER TO setjoin_owner;

ALTER TABLE public.identity_link_events
    DROP CONSTRAINT identity_link_events_action_check;
ALTER TABLE public.identity_link_events
    ADD CONSTRAINT identity_link_events_action_check CHECK (
        action IN (
            'source_created','source_updated','source_entry_applied',
            'source_entry_quarantined','source_cursor_committed',
            'source_secret_set','source_secret_rotated','source_validated',
            'source_activated','source_paused','source_resumed','source_retired',
            'candidate_recorded','link_activated','link_suspended',
            'link_detached','link_relinked','auth_resolved','auth_jit_created',
            'auth_linked','auth_unlinked','attribute_authority_applied',
            'entitlements_reconciled','transition_previewed',
            'transition_requested','transition_approval_requested',
            'transition_approved','transition_denied',
            'transition_cancelled','transition_expired',
            'transition_executing','transition_committed',
            'transition_effect_retried','transition_failed',
            'transition_completed','transition_rollback_previewed',
            'transition_rollback_requested','transition_rollback_approved',
            'transition_rollback_started','transition_rolled_back',
            'authority_changed','conflict_decided','legacy_backfilled'
        )
    );

INSERT INTO public.schema_migrations (version, applied_at)
VALUES (165, now());
