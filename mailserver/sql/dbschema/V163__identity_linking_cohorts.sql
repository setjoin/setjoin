-- V163: authenticated-link provider binding and bounded read canary cohorts.
--
-- The normalized schema remains expand-only. Legacy pairs remain available for
-- rollback, while provider_key connects operator SSO configuration provenance
-- to its protocol-defined issuer source.

ALTER TABLE public.identity_sources
    ADD COLUMN provider_key TEXT;

ALTER TABLE public.identity_sources
    ADD CONSTRAINT identity_sources_provider_key_check CHECK (
        provider_key IS NULL OR (
            octet_length(provider_key) BETWEEN 3 AND 255
            AND provider_key = btrim(provider_key)
            AND provider_key ~ '^(saml|oidc):[A-Za-z0-9._:-]+$'
        )
    );

CREATE UNIQUE INDEX identity_sources_provider_key_key
    ON public.identity_sources(provider_key)
    WHERE provider_key IS NOT NULL;

UPDATE public.identity_sources s
   SET provider_key='saml:'||r.id::text
  FROM public.saml_sp_registrations r
 WHERE s.kind='saml'
   AND s.source_key='saml:'||
       substr(encode(digest(r.idp_entity_id,'sha256'),'hex'),1,48)
   AND s.provider_key IS NULL;

UPDATE public.identity_sources s
   SET provider_key='oidc:'||(c.value->>'name')
  FROM public.system_config c
 WHERE c.key LIKE 'oidc_provider_%_config'
   AND c.value ? 'name'
   AND c.value ? 'provider_url'
   AND s.kind='oidc'
   AND s.source_key='oidc:'||
       substr(encode(digest(c.value->>'provider_url','sha256'),'hex'),1,48)
   AND s.provider_key IS NULL;

CREATE TABLE public.identity_read_cohort (
    source_id       BIGINT NOT NULL REFERENCES public.identity_sources(id) ON DELETE RESTRICT,
    user_id         BIGINT NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    source_generation BIGINT NOT NULL CHECK (source_generation > 0),
    added_by        BIGINT NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    reason          TEXT NOT NULL CHECK (
        octet_length(reason) BETWEEN 1 AND 1024 AND reason !~ '[[:cntrl:]]'
    ),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY(source_id,user_id)
);
CREATE INDEX identity_read_cohort_user_idx
    ON public.identity_read_cohort(user_id,source_id);

ALTER TABLE public.identity_read_cohort ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.identity_read_cohort FORCE ROW LEVEL SECURITY;
ALTER TABLE public.identity_read_cohort OWNER TO setjoin_owner;

ALTER TABLE public.identity_link_events
    DROP CONSTRAINT identity_link_events_action_check;
ALTER TABLE public.identity_link_events
    ADD CONSTRAINT identity_link_events_action_check CHECK (
        action IN (
            'source_created','source_updated','source_entry_applied',
            'source_entry_quarantined','source_cursor_committed',
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

-- The 30-second identity metrics collector counts these bounded action
-- classes. Keep that hot read index-only without indexing the full evidence
-- stream or changing its append-only contract.
CREATE INDEX identity_link_events_metrics_action_idx
    ON public.identity_link_events(action)
    WHERE action IN (
        'auth_jit_created','auth_linked','auth_resolved',
        'entitlements_reconciled','authority_changed','transition_committed'
    );

INSERT INTO public.schema_migrations (version, applied_at)
VALUES (163, now());
