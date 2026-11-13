-- Source-bound SCIM groups and durable, short-lived LiveKit admission leases.

ALTER TABLE public.distribution_groups
    ADD COLUMN scim_source_id BIGINT
        REFERENCES public.identity_sources(id) ON DELETE RESTRICT;

UPDATE public.distribution_groups g
   SET scim_source_id=s.id
  FROM public.identity_sources s
 WHERE g.scim_external_id IS NOT NULL
   AND g.scim_source_id IS NULL
   AND s.source_key='legacy:scim';

ALTER TABLE public.distribution_groups
    ADD CONSTRAINT distribution_groups_scim_source_pair_check CHECK (
        (scim_external_id IS NULL AND scim_source_id IS NULL)
        OR (scim_external_id IS NOT NULL AND scim_source_id IS NOT NULL)
    );

DROP INDEX IF EXISTS public.dg_scim_external_id_idx;
CREATE UNIQUE INDEX distribution_groups_scim_source_external_idx
    ON public.distribution_groups(scim_source_id,scim_external_id)
    WHERE scim_external_id IS NOT NULL;
CREATE INDEX distribution_groups_scim_source_idx
    ON public.distribution_groups(scim_source_id,id)
    WHERE scim_source_id IS NOT NULL;

-- Remove the pre-source-bound overloads before the reducer loader installs the
-- source-aware contracts. Leaving them callable would preserve a cross-source
-- bypass after an upgrade.
DROP FUNCTION IF EXISTS public.scim_upsert_group(TEXT,TEXT);
DROP FUNCTION IF EXISTS public.scim_apply_group_members(TEXT,TEXT[]);
DROP FUNCTION IF EXISTS public.scim_delete_group(BIGINT);

CREATE TABLE public.identity_media_admissions (
    user_id       BIGINT NOT NULL
                      REFERENCES public.users(id) ON DELETE CASCADE,
    room_name     TEXT NOT NULL CHECK (
        octet_length(room_name) BETWEEN 1 AND 255
        AND room_name !~ '[[:cntrl:]]'
    ),
    identity      TEXT NOT NULL CHECK (
        octet_length(identity) BETWEEN 3 AND 255
        AND identity !~ '[[:cntrl:]]'
    ),
    expires_at    TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY(user_id,room_name,identity),
    CHECK (identity='u:'||user_id::text),
    CHECK (expires_at>created_at AND expires_at<=created_at+interval '75 seconds')
);
CREATE INDEX identity_media_admissions_expiry_idx
    ON public.identity_media_admissions(expires_at);
ALTER TABLE public.identity_media_admissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.identity_media_admissions FORCE ROW LEVEL SECURITY;
ALTER TABLE public.identity_media_admissions OWNER TO setjoin_owner;

ALTER TABLE public.identity_transition_effect_targets
    ADD COLUMN evict_until TIMESTAMPTZ;

-- Claims count successful backfill pages as well as retry attempts. Keep that
-- telemetry unbounded by the failure budget so a supported 10k-user backfill
-- cannot wedge merely because it needs more than twenty batches.
ALTER TABLE public.identity_jobs
    DROP CONSTRAINT identity_jobs_attempt_count_check;
ALTER TABLE public.identity_jobs
    ADD CONSTRAINT identity_jobs_attempt_count_check
        CHECK (attempt_count >= 0),
    ADD COLUMN failure_count INTEGER NOT NULL DEFAULT 0
        CHECK (failure_count BETWEEN 0 AND 20);

INSERT INTO public.schema_migrations (version, applied_at)
VALUES (168, now()) ON CONFLICT (version) DO NOTHING;
