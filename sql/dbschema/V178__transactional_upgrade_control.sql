-- V178: transactional updater control plane.
--
-- This migration is expand-only. It creates no host execution path and seeds
-- every release/continuity feature OFF. PostgreSQL reducers remain the authority
-- for preview, authorization, approval, claim, progress, cancel, and completion.

ALTER TABLE public.approval_policies
    DROP CONSTRAINT approval_policies_consumer_type_check;
ALTER TABLE public.approval_policies
    ADD CONSTRAINT approval_policies_consumer_type_check
    CHECK (consumer_type IN (
        'rbac.jit_activation','mail.external_send','mail.group_moderation',
        'hr.leave','hr.expense','drive.share','drive.export','guest.invite',
        'identity.transition','system_upgrade'
    ));
ALTER TABLE public.approval_requests
    DROP CONSTRAINT approval_requests_consumer_type_check;
ALTER TABLE public.approval_requests
    ADD CONSTRAINT approval_requests_consumer_type_check
    CHECK (consumer_type IN (
        'rbac.jit_activation','mail.external_send','mail.group_moderation',
        'hr.leave','hr.expense','drive.share','drive.export','guest.invite',
        'identity.transition','system_upgrade'
    ));

-- Optional independent approval. Disabled means permission + fresh step-up is
-- sufficient; an operator may enable and configure this through the existing
-- approval-policy surface.
INSERT INTO public.approval_policies(
    consumer_type,name,enabled,priority,conditions,requires_approval,approver_spec
) VALUES(
    'system_upgrade','Independent system-upgrade approval',false,100,
    '{}'::jsonb,true,'{"kind":"default_admin"}'::jsonb
) ON CONFLICT(consumer_type,priority) DO NOTHING;

INSERT INTO public.feature_toggles(key,enabled,description) VALUES
    ('feature.transactional_upgrades_catalog',false,
     'Expose locally verified signed release metadata without permitting installation'),
    ('feature.transactional_upgrades_execution',false,
     'Permit creation and claim of transactional host-upgrade intents'),
    ('feature.client_recovery_receipts',false,
     'Issue signed native-client recovery receipts'),
    ('feature.client_recovery_cache',false,
     'Permit opt-in encrypted native-client recovery caching'),
    ('feature.client_recovery_ingest',false,
     'Permit approved client-assisted recovery intake')
ON CONFLICT(key) DO NOTHING;

CREATE TABLE public.upgrade_control_state (
    singleton          boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    installation_id    uuid NOT NULL UNIQUE,
    catalog_generation bigint NOT NULL DEFAULT 1 CHECK (catalog_generation > 0),
    policy_generation  bigint NOT NULL DEFAULT 1 CHECK (policy_generation > 0),
    updated_at         timestamptz NOT NULL DEFAULT statement_timestamp()
);
INSERT INTO public.upgrade_control_state(singleton,installation_id)
SELECT true,(value #>> '{}')::uuid
  FROM public.system_config
 WHERE key='identity.deployment_id'
ON CONFLICT(singleton) DO NOTHING;

-- Owner-only evidence for the host migration runner. This is deliberately not
-- writable by setjoin_updater: schema mutation uses a distinct LoadCredential
-- owner identity, and each file records its signed manifest binding in the
-- same transaction as the migration itself.
CREATE TABLE public.upgrade_schema_migration_evidence (
    schema_version     integer PRIMARY KEY CHECK (schema_version > 0),
    release_id         text NOT NULL CHECK (release_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    manifest_digest    text NOT NULL CHECK (manifest_digest ~ '^[a-f0-9]{64}$'),
    migration_id       text NOT NULL CHECK (migration_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    migration_sha256   text NOT NULL CHECK (migration_sha256 ~ '^[a-f0-9]{64}$'),
    applied_at         timestamptz NOT NULL DEFAULT statement_timestamp()
);
ALTER TABLE public.upgrade_schema_migration_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.upgrade_schema_migration_evidence FORCE ROW LEVEL SECURITY;
CREATE POLICY upgrade_schema_migration_owner
    ON public.upgrade_schema_migration_evidence
    USING (current_user='setjoin_owner')
    WITH CHECK (current_user='setjoin_owner');
ALTER TABLE public.upgrade_schema_migration_evidence OWNER TO setjoin_owner;

CREATE OR REPLACE FUNCTION public.trg_upgrade_policy_generation_fn()
RETURNS trigger LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF (TG_OP='DELETE' AND OLD.consumer_type='system_upgrade')
       OR (TG_OP<>'DELETE' AND NEW.consumer_type='system_upgrade') THEN
        UPDATE public.upgrade_control_state
           SET policy_generation=policy_generation+1,
               updated_at=statement_timestamp()
         WHERE singleton;
    END IF;
    RETURN NULL;
END;
$$;
CREATE TRIGGER trg_approval_policies_upgrade_generation
AFTER INSERT OR UPDATE OR DELETE ON public.approval_policies
FOR EACH ROW EXECUTE FUNCTION public.trg_upgrade_policy_generation_fn();

CREATE TABLE public.upgrade_release_catalog (
    release_id              text PRIMARY KEY CHECK (
        release_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'
    ),
    version                 text NOT NULL CHECK (
        octet_length(version) BETWEEN 1 AND 64 AND version !~ '[[:cntrl:]]'
    ),
    channel                 text NOT NULL CHECK (channel IN ('community','enterprise')),
    platform                text NOT NULL CHECK (platform IN ('linux')),
    architecture            text NOT NULL CHECK (architecture IN ('amd64','arm64')),
    manifest_digest         bytea NOT NULL UNIQUE CHECK (octet_length(manifest_digest)=32),
    manifest                jsonb NOT NULL CHECK (
        jsonb_typeof(manifest)='object' AND octet_length(manifest::text)<=1048576
    ),
    metadata_version        bigint NOT NULL CHECK (metadata_version > 0),
    catalog_generation      bigint NOT NULL CHECK (catalog_generation > 0),
    verified_by_key_ids     text[] NOT NULL CHECK (
        cardinality(verified_by_key_ids) BETWEEN 1 AND 16
    ),
    verified_at             timestamptz NOT NULL,
    metadata_expires_at     timestamptz NOT NULL,
    entitlement_digest      bytea CHECK (
        entitlement_digest IS NULL OR octet_length(entitlement_digest)=32
    ),
    entitlement_grace_until timestamptz,
    status                  text NOT NULL DEFAULT 'available'
                                CHECK (status IN ('available','withdrawn')),
    imported_by_user_id     bigint REFERENCES public.users(id) ON DELETE RESTRICT,
    created_at              timestamptz NOT NULL DEFAULT statement_timestamp(),
    CHECK (metadata_expires_at > verified_at),
    CHECK (
        (channel='community' AND entitlement_digest IS NULL
                             AND entitlement_grace_until IS NULL)
        OR
        (channel='enterprise' AND entitlement_digest IS NOT NULL
                              AND entitlement_grace_until IS NOT NULL)
    )
);
COMMENT ON COLUMN public.upgrade_release_catalog.entitlement_grace_until IS
    'Signed offline entitlement grace_until; new Enterprise claims fail at this boundary while installed releases remain usable';
CREATE INDEX upgrade_release_catalog_available_idx
    ON public.upgrade_release_catalog(channel,created_at DESC)
    WHERE status='available';

CREATE TABLE public.upgrade_readiness (
    release_id            text PRIMARY KEY
                               REFERENCES public.upgrade_release_catalog(release_id)
                               ON DELETE RESTRICT,
    manifest_digest       bytea NOT NULL CHECK (octet_length(manifest_digest)=32),
    readiness_generation  bigint NOT NULL CHECK (readiness_generation > 0),
    status                text NOT NULL CHECK (status IN ('checking','ready','blocked')),
    source_version        text NOT NULL CHECK (
        octet_length(source_version) BETWEEN 1 AND 64
        AND source_version !~ '[[:cntrl:]]'
    ),
    source_schema_version bigint NOT NULL CHECK (source_schema_version > 0),
    target_schema_version bigint NOT NULL CHECK (target_schema_version > 0),
    checks                jsonb NOT NULL CHECK (
        jsonb_typeof(checks)='object' AND octet_length(checks::text)<=262144
    ),
    blocker_count         integer NOT NULL CHECK (blocker_count BETWEEN 0 AND 1024),
    expires_at            timestamptz NOT NULL,
    checked_by_user_id    bigint NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    updated_at            timestamptz NOT NULL DEFAULT statement_timestamp(),
    CHECK ((status='ready' AND blocker_count=0) OR status<>'ready')
);

CREATE TABLE public.upgrade_challenges (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_user_id       bigint NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    release_id          text NOT NULL REFERENCES public.upgrade_release_catalog(release_id),
    preview_digest      bytea NOT NULL CHECK (octet_length(preview_digest)=32),
    readiness_generation bigint NOT NULL CHECK (readiness_generation > 0),
    policy_generation   bigint NOT NULL CHECK (policy_generation > 0),
    issued_at           timestamptz NOT NULL DEFAULT statement_timestamp(),
    expires_at          timestamptz NOT NULL,
    completed_at        timestamptz,
    invalidated_at      timestamptz,
    elevation_id        uuid UNIQUE,
    idempotency_key     uuid NOT NULL,
    request_digest      bytea NOT NULL CHECK (octet_length(request_digest)=32),
    CHECK (expires_at > issued_at AND expires_at <= issued_at + interval '5 minutes'),
    CHECK ((completed_at IS NULL AND elevation_id IS NULL)
        OR (completed_at IS NOT NULL AND elevation_id IS NOT NULL)),
    CHECK (completed_at IS NULL OR invalidated_at IS NULL),
    UNIQUE(actor_user_id,idempotency_key)
);

CREATE TABLE public.upgrade_elevations (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_user_id       bigint NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    challenge_id        uuid NOT NULL UNIQUE REFERENCES public.upgrade_challenges(id),
    release_id          text NOT NULL REFERENCES public.upgrade_release_catalog(release_id),
    preview_digest      bytea NOT NULL CHECK (octet_length(preview_digest)=32),
    readiness_generation bigint NOT NULL CHECK (readiness_generation > 0),
    policy_generation   bigint NOT NULL CHECK (policy_generation > 0),
    session_digest      bytea NOT NULL CHECK (octet_length(session_digest)=32),
    factor_digest       bytea NOT NULL CHECK (octet_length(factor_digest)=32),
    amr                 text[] NOT NULL CHECK (cardinality(amr) BETWEEN 2 AND 16),
    acr                 text NOT NULL CHECK (
        octet_length(acr) BETWEEN 1 AND 128 AND acr !~ '[[:cntrl:]]'
    ),
    issued_at           timestamptz NOT NULL DEFAULT statement_timestamp(),
    expires_at          timestamptz NOT NULL,
    consumed_at         timestamptz,
    invalidated_at      timestamptz,
    request_digest      bytea NOT NULL CHECK (octet_length(request_digest)=32),
    CHECK (expires_at > issued_at AND expires_at <= issued_at + interval '5 minutes'),
    CHECK (consumed_at IS NULL OR invalidated_at IS NULL)
);
ALTER TABLE public.upgrade_challenges
    ADD CONSTRAINT upgrade_challenges_elevation_fk
    FOREIGN KEY(elevation_id) REFERENCES public.upgrade_elevations(id)
    ON DELETE RESTRICT;

CREATE TABLE public.upgrade_intents (
    id                    bigserial PRIMARY KEY,
    installation_id       uuid NOT NULL,
    release_id            text NOT NULL REFERENCES public.upgrade_release_catalog(release_id),
    manifest_digest       bytea NOT NULL CHECK (octet_length(manifest_digest)=32),
    catalog_generation    bigint NOT NULL CHECK (catalog_generation > 0),
    readiness_generation  bigint NOT NULL CHECK (readiness_generation > 0),
    policy_generation     bigint NOT NULL CHECK (policy_generation > 0),
    preview_digest        bytea NOT NULL CHECK (octet_length(preview_digest)=32),
    state                 text NOT NULL CHECK (state IN (
        'awaiting_approval','approved','scheduled','claimed','preflight',
        'recovery_point','staged','maintenance','migrations','switched',
        'readiness','committed','verified','cancel_requested','rolling_back',
        'rolled_back','failed','recovery_required','cancelled','expired'
    )),
    state_generation      bigint NOT NULL DEFAULT 1 CHECK (state_generation > 0),
    requested_by_user_id  bigint NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    requester_elevation_id uuid NOT NULL UNIQUE REFERENCES public.upgrade_elevations(id),
    approval_request_id   bigint REFERENCES public.approval_requests(id) ON DELETE RESTRICT,
    approved_by_user_id   bigint REFERENCES public.users(id) ON DELETE RESTRICT,
    reason                text NOT NULL CHECK (
        octet_length(reason) BETWEEN 8 AND 1024 AND reason !~ '[[:cntrl:]]'
    ),
    schedule_at           timestamptz,
    expires_at            timestamptz NOT NULL,
    idempotency_key       uuid NOT NULL,
    request_digest        bytea NOT NULL CHECK (octet_length(request_digest)=32),
    executor_id           text CHECK (
        executor_id IS NULL OR (
            octet_length(executor_id) BETWEEN 1 AND 128
            AND executor_id ~ '^[A-Za-z0-9._:-]+$'
        )
    ),
    lease_id              uuid,
    claimed_at            timestamptz,
    cancel_requested_at   timestamptz,
    completed_at          timestamptz,
    result                jsonb CHECK (
        result IS NULL OR (
            jsonb_typeof(result)='object' AND octet_length(result::text)<=262144
        )
    ),
    created_at            timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT statement_timestamp(),
    UNIQUE(requested_by_user_id,idempotency_key),
    CHECK (schedule_at IS NULL OR schedule_at <= created_at + interval '31 days'),
    CHECK ((executor_id IS NULL AND lease_id IS NULL AND claimed_at IS NULL)
        OR (executor_id IS NOT NULL AND lease_id IS NOT NULL AND claimed_at IS NOT NULL))
);
CREATE UNIQUE INDEX upgrade_intents_one_active_installation_idx
    ON public.upgrade_intents(installation_id)
    WHERE state NOT IN ('verified','rolled_back','failed','cancelled','expired');
CREATE INDEX upgrade_intents_history_idx
    ON public.upgrade_intents(created_at DESC,id DESC);

CREATE TABLE public.upgrade_intent_events (
    id               bigserial PRIMARY KEY,
    intent_id        bigint NOT NULL REFERENCES public.upgrade_intents(id) ON DELETE RESTRICT,
    state_generation bigint NOT NULL CHECK (state_generation > 0),
    from_state       text,
    to_state         text NOT NULL,
    actor_user_id    bigint REFERENCES public.users(id) ON DELETE RESTRICT,
    executor_id      text,
    evidence_digest  bytea CHECK (evidence_digest IS NULL OR octet_length(evidence_digest)=32),
    evidence         jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (
        jsonb_typeof(evidence)='object' AND octet_length(evidence::text)<=65536
    ),
    occurred_at      timestamptz NOT NULL DEFAULT statement_timestamp(),
    UNIQUE(intent_id,state_generation)
);
CREATE INDEX upgrade_intent_events_intent_idx
    ON public.upgrade_intent_events(intent_id,id);

CREATE OR REPLACE FUNCTION public.upgrade_intent_events_append_only_fn()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'upgrade intent events are append-only'
        USING ERRCODE='BZ017',
              HINT='{"type":"audit_append_only","table":"upgrade_intent_events"}';
END;
$$;
CREATE TRIGGER trg_upgrade_intent_events_append_only
BEFORE UPDATE OR DELETE ON public.upgrade_intent_events
FOR EACH ROW EXECUTE FUNCTION public.upgrade_intent_events_append_only_fn();

-- No direct table policy exists: both the gateway and updater use named
-- SECURITY DEFINER reducers, while the BYPASSRLS worker owner supplies the
-- narrow implementation privilege.
ALTER TABLE public.upgrade_control_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.upgrade_control_state FORCE ROW LEVEL SECURITY;
ALTER TABLE public.upgrade_release_catalog ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.upgrade_release_catalog FORCE ROW LEVEL SECURITY;
ALTER TABLE public.upgrade_readiness ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.upgrade_readiness FORCE ROW LEVEL SECURITY;
ALTER TABLE public.upgrade_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.upgrade_challenges FORCE ROW LEVEL SECURITY;
ALTER TABLE public.upgrade_elevations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.upgrade_elevations FORCE ROW LEVEL SECURITY;
ALTER TABLE public.upgrade_intents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.upgrade_intents FORCE ROW LEVEL SECURITY;
ALTER TABLE public.upgrade_intent_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.upgrade_intent_events FORCE ROW LEVEL SECURITY;

ALTER TABLE public.upgrade_control_state OWNER TO setjoin_owner;
ALTER TABLE public.upgrade_release_catalog OWNER TO setjoin_owner;
ALTER TABLE public.upgrade_readiness OWNER TO setjoin_owner;
ALTER TABLE public.upgrade_challenges OWNER TO setjoin_owner;
ALTER TABLE public.upgrade_elevations OWNER TO setjoin_owner;
ALTER TABLE public.upgrade_intents OWNER TO setjoin_owner;
ALTER TABLE public.upgrade_intent_events OWNER TO setjoin_owner;
ALTER SEQUENCE public.upgrade_intents_id_seq OWNER TO setjoin_owner;
ALTER SEQUENCE public.upgrade_intent_events_id_seq OWNER TO setjoin_owner;
ALTER FUNCTION public.trg_upgrade_policy_generation_fn() OWNER TO setjoin_worker;
REVOKE ALL ON FUNCTION public.trg_upgrade_policy_generation_fn() FROM PUBLIC;
ALTER FUNCTION public.upgrade_intent_events_append_only_fn() OWNER TO setjoin_owner;

-- Migration-time ownership/grant applicator. p_gateway and p_updater are exact
-- allow bits; in particular, updater-only state mutation functions are not
-- executable by the gateway role.
CREATE OR REPLACE FUNCTION public.apply_upgrade_ownership(
    p_func regprocedure,
    p_gateway boolean,
    p_updater boolean
) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='setjoin_worker') THEN
        EXECUTE format('ALTER FUNCTION %s OWNER TO setjoin_worker',p_func::text);
    END IF;
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',p_func::text);
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='setjoin_app') THEN
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM setjoin_app',p_func::text);
        IF p_gateway THEN
            EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO setjoin_app',p_func::text);
        END IF;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='setjoin_updater') THEN
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM setjoin_updater',p_func::text);
        IF p_updater THEN
            EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO setjoin_updater',p_func::text);
        END IF;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='setjoin_owner') THEN
        EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO setjoin_owner',p_func::text);
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='setjoin_worker') THEN
        EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO setjoin_worker',p_func::text);
    END IF;
END;
$$;
REVOKE ALL ON FUNCTION public.apply_upgrade_ownership(regprocedure,boolean,boolean)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.apply_upgrade_ownership(regprocedure,boolean,boolean)
    TO setjoin_owner;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (178, now())
ON CONFLICT (version) DO NOTHING;
