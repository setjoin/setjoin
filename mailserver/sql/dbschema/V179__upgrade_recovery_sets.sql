-- V179: application recovery-set evidence for transactional upgrades.
-- Expand-only: evidence tables plus nullable bindings on pre-existing intents.

ALTER TABLE public.upgrade_control_state
    ADD COLUMN timeline_id uuid NOT NULL DEFAULT gen_random_uuid();

CREATE TABLE public.upgrade_recovery_sets (
    recovery_set_id      uuid PRIMARY KEY,
    installation_id     uuid NOT NULL,
    timeline_id         uuid NOT NULL,
    source_release_id   text NOT NULL CHECK (
        source_release_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'
    ),
    schema_version      integer NOT NULL CHECK (schema_version > 0),
    manifest_digest    bytea NOT NULL UNIQUE CHECK (octet_length(manifest_digest)=32),
    status             text NOT NULL CHECK (status IN ('verified','invalidated')),
    checks             jsonb NOT NULL CHECK (
        jsonb_typeof(checks)='object' AND octet_length(checks::text)<=65536
    ),
    created_at         timestamptz NOT NULL,
    expires_at         timestamptz NOT NULL,
    recorded_by_user_id bigint NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    recorded_at        timestamptz NOT NULL DEFAULT statement_timestamp(),
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '24 hours')
);
CREATE INDEX upgrade_recovery_sets_fresh_idx
    ON public.upgrade_recovery_sets(installation_id,expires_at DESC)
    WHERE status='verified';

CREATE TABLE public.upgrade_restore_proofs (
    proof_id             uuid PRIMARY KEY,
    recovery_set_id      uuid NOT NULL REFERENCES public.upgrade_recovery_sets(recovery_set_id) ON DELETE RESTRICT,
    target_id            text NOT NULL CHECK (
        target_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ),
    checks               jsonb NOT NULL CHECK (
        jsonb_typeof(checks)='object' AND octet_length(checks::text)<=65536
    ),
    proved_at            timestamptz NOT NULL,
    recorded_by_user_id  bigint NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    recorded_at          timestamptz NOT NULL DEFAULT statement_timestamp(),
    UNIQUE(recovery_set_id,target_id)
);

ALTER TABLE public.upgrade_intents
    ADD COLUMN recovery_set_id uuid REFERENCES public.upgrade_recovery_sets(recovery_set_id) ON DELETE RESTRICT,
    ADD COLUMN recovery_set_digest bytea CHECK (
        recovery_set_digest IS NULL OR octet_length(recovery_set_digest)=32
    ),
    ADD CONSTRAINT upgrade_intents_recovery_binding_check CHECK (
        (recovery_set_id IS NULL) = (recovery_set_digest IS NULL)
    );

ALTER TABLE public.upgrade_recovery_sets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.upgrade_recovery_sets FORCE ROW LEVEL SECURITY;
ALTER TABLE public.upgrade_restore_proofs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.upgrade_restore_proofs FORCE ROW LEVEL SECURITY;
ALTER TABLE public.upgrade_recovery_sets OWNER TO setjoin_owner;
ALTER TABLE public.upgrade_restore_proofs OWNER TO setjoin_owner;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (179, now())
ON CONFLICT (version) DO NOTHING;
