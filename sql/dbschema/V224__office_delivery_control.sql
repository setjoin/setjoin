-- V224: Office provider qualification and managed CODE delivery control.
--
-- This migration is expand-only. All managed behavior remains OFF. Reducers
-- own authorization and transitions; the privileged app runner owns only the
-- fixed Docker effects described by an accepted operation.

ALTER TABLE public.office_provider_policies
  ADD COLUMN route_state text NOT NULL DEFAULT 'disconnected'
    CHECK (route_state IN ('disconnected','connected_inactive','active_for_scope','draining','fenced')),
  ADD COLUMN config_sha256 text NOT NULL DEFAULT repeat('0',64)
    CHECK (config_sha256 ~ '^[0-9a-f]{64}$'),
  ADD COLUMN active_qualification_id uuid;

UPDATE public.office_provider_policies
   SET route_state=CASE
         WHEN draining THEN 'draining'
         WHEN enabled THEN 'active_for_scope'
         ELSE 'connected_inactive'
       END,
       config_sha256=encode(digest(config::text,'sha256'),'hex');

CREATE TABLE public.office_provider_qualifications (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  provider_id           text NOT NULL REFERENCES public.office_provider_policies(provider_id),
  provider_generation   bigint NOT NULL CHECK (provider_generation > 0),
  config_sha256         text NOT NULL CHECK (config_sha256 ~ '^[0-9a-f]{64}$'),
  status                text NOT NULL CHECK (status IN ('passed','failed','expired')),
  profile               text NOT NULL CHECK (profile IN (
                           'existing-provider','managed-wildcard',
                           'managed-customer-cert','managed-customer-proxy')),
  checks                jsonb NOT NULL CHECK (
                           jsonb_typeof(checks)='object' AND octet_length(checks::text)<=262144),
  discovery_fingerprint text CHECK (
                           discovery_fingerprint IS NULL OR discovery_fingerprint ~ '^[0-9a-f]{64}$'),
  build_digest          text CHECK (build_digest IS NULL OR build_digest ~ '^sha256:[0-9a-f]{64}$'),
  route_revision        bigint NOT NULL DEFAULT 1 CHECK (route_revision > 0),
  synthetic_receipt_id  bigint REFERENCES public.office_save_receipts(id),
  created_by            bigint NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  created_at            timestamptz NOT NULL DEFAULT statement_timestamp(),
  expires_at            timestamptz NOT NULL,
  CHECK (expires_at > created_at),
  UNIQUE(provider_id,provider_generation,config_sha256,profile)
);
CREATE INDEX office_provider_qualifications_current_idx
  ON public.office_provider_qualifications(provider_id,created_at DESC);

ALTER TABLE public.office_provider_policies
  ADD CONSTRAINT office_provider_policies_active_qualification_fk
  FOREIGN KEY(active_qualification_id)
  REFERENCES public.office_provider_qualifications(id) ON DELETE SET NULL;

CREATE TABLE public.office_provider_health_observations (
  id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  provider_id         text NOT NULL REFERENCES public.office_provider_policies(provider_id),
  provider_generation bigint NOT NULL CHECK (provider_generation > 0),
  app_revision_id     uuid,
  state               text NOT NULL CHECK (state IN ('healthy','degraded','failed')),
  capacity_state      text NOT NULL CHECK (capacity_state IN ('available','exhausted','unknown')),
  facts               jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (
                        jsonb_typeof(facts)='object' AND octet_length(facts::text)<=65536),
  observed_at         timestamptz NOT NULL DEFAULT statement_timestamp(),
  expires_at          timestamptz NOT NULL,
  CHECK (expires_at > observed_at)
);
CREATE INDEX office_provider_health_current_idx
  ON public.office_provider_health_observations(provider_id,observed_at DESC,id DESC);

CREATE TABLE public.office_app_revisions (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  app_id            text NOT NULL CHECK (app_id='collabora-code'),
  revision          bigint NOT NULL CHECK (revision > 0),
  provider_id       text NOT NULL REFERENCES public.office_provider_policies(provider_id),
  state             text NOT NULL CHECK (state IN (
                      'absent','staged','qualified','active','previous',
                      'retention_pending','removed','failed')),
  image_reference   text NOT NULL CHECK (octet_length(image_reference) BETWEEN 1 AND 512),
  image_digest      text NOT NULL CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),
  artifact_receipt  jsonb NOT NULL CHECK (
                      jsonb_typeof(artifact_receipt)='object'
                      AND octet_length(artifact_receipt::text)<=262144),
  runtime_config    jsonb NOT NULL CHECK (
                      jsonb_typeof(runtime_config)='object'
                      AND octet_length(runtime_config::text)<=65536),
  created_at        timestamptz NOT NULL DEFAULT statement_timestamp(),
  updated_at        timestamptz NOT NULL DEFAULT statement_timestamp(),
  UNIQUE(app_id,revision),
  UNIQUE(app_id,image_digest)
);
CREATE UNIQUE INDEX office_app_revisions_active_uniq
  ON public.office_app_revisions(app_id) WHERE state='active';

ALTER TABLE public.office_provider_health_observations
  ADD CONSTRAINT office_provider_health_app_revision_fk
  FOREIGN KEY(app_revision_id) REFERENCES public.office_app_revisions(id) ON DELETE SET NULL;

CREATE TABLE public.office_app_operations (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  app_id              text NOT NULL CHECK (app_id='collabora-code'),
  kind                text NOT NULL CHECK (kind IN (
                        'install','update','rollback','disable','uninstall')),
  state               text NOT NULL CHECK (state IN (
                        'requested','claimed','preflight','pulling','verifying',
                        'staging','starting','qualifying','connected_inactive',
                        'disabling_launches','draining','blocked_drain',
                        'rolling_back','rolled_back','retention_pending',
                        'removed','paused_recoverable','failed_terminal','cancelled')),
  state_generation    bigint NOT NULL DEFAULT 1 CHECK (state_generation > 0),
  requested_by        bigint NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  reason              text NOT NULL CHECK (
                        octet_length(reason) BETWEEN 1 AND 1024 AND reason !~ '[[:cntrl:]]'),
  idempotency_key     uuid NOT NULL,
  request_digest      text NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
  request             jsonb NOT NULL CHECK (
                        jsonb_typeof(request)='object' AND octet_length(request::text)<=65536),
  app_revision_id     uuid REFERENCES public.office_app_revisions(id) ON DELETE SET NULL,
  executor_id         text CHECK (
                        executor_id IS NULL OR executor_id ~ '^[A-Za-z0-9._:-]{1,128}$'),
  lease_id            uuid,
  phase               text NOT NULL DEFAULT 'requested' CHECK (octet_length(phase) BETWEEN 1 AND 64),
  progress            jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (
                        jsonb_typeof(progress)='object' AND octet_length(progress::text)<=65536),
  error               jsonb CHECK (
                        error IS NULL OR (jsonb_typeof(error)='object' AND octet_length(error::text)<=65536)),
  claimed_at          timestamptz,
  completed_at        timestamptz,
  created_at          timestamptz NOT NULL DEFAULT statement_timestamp(),
  updated_at          timestamptz NOT NULL DEFAULT statement_timestamp(),
  UNIQUE(app_id,idempotency_key)
);
CREATE UNIQUE INDEX office_app_operations_one_active_uniq
  ON public.office_app_operations(app_id)
  WHERE state IN ('requested','claimed','preflight','pulling','verifying','staging',
                  'starting','qualifying','disabling_launches','draining','rolling_back');

ALTER TABLE public.office_provider_qualifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.office_provider_qualifications FORCE ROW LEVEL SECURITY;
ALTER TABLE public.office_provider_health_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.office_provider_health_observations FORCE ROW LEVEL SECURITY;
ALTER TABLE public.office_app_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.office_app_revisions FORCE ROW LEVEL SECURITY;
ALTER TABLE public.office_app_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.office_app_operations FORCE ROW LEVEL SECURITY;

CREATE POLICY office_provider_qualifications_admin_read
  ON public.office_provider_qualifications FOR SELECT TO public USING (
    public.drive_has_admin_perm(NULLIF(current_setting('app.current_user_id',true),'')::bigint,'office.view')
    OR public.drive_has_admin_perm(NULLIF(current_setting('app.current_user_id',true),'')::bigint,'office.manage'));
CREATE POLICY office_provider_health_admin_read
  ON public.office_provider_health_observations FOR SELECT TO public USING (
    public.drive_has_admin_perm(NULLIF(current_setting('app.current_user_id',true),'')::bigint,'office.view')
    OR public.drive_has_admin_perm(NULLIF(current_setting('app.current_user_id',true),'')::bigint,'office.manage'));
CREATE POLICY office_app_revisions_admin_read
  ON public.office_app_revisions FOR SELECT TO public USING (
    public.drive_has_admin_perm(NULLIF(current_setting('app.current_user_id',true),'')::bigint,'apps.view')
    OR public.drive_has_admin_perm(NULLIF(current_setting('app.current_user_id',true),'')::bigint,'apps.manage'));
CREATE POLICY office_app_operations_admin_read
  ON public.office_app_operations FOR SELECT TO public USING (
    requested_by=NULLIF(current_setting('app.current_user_id',true),'')::bigint
    OR public.drive_has_admin_perm(NULLIF(current_setting('app.current_user_id',true),'')::bigint,'apps.view')
    OR public.drive_has_admin_perm(NULLIF(current_setting('app.current_user_id',true),'')::bigint,'apps.manage'));

INSERT INTO public.feature_toggles(key,enabled,description) VALUES
  ('feature.office_managed_delivery',false,
   'Permit the closed Collabora CODE test-editor installation lifecycle')
ON CONFLICT(key) DO UPDATE SET description=EXCLUDED.description;

INSERT INTO public.admin_permissions(permission_key,category,description,is_sensitive) VALUES
  ('apps.view','Applications','View curated application runtime and operation state',false),
  ('apps.manage','Applications','Install, update, disable and remove curated application runtimes',true)
ON CONFLICT(permission_key) DO NOTHING;

UPDATE public.admin_role_groups
   SET permissions=(SELECT array_agg(DISTINCT p ORDER BY p)
                      FROM unnest(permissions || ARRAY['apps.view','apps.manage']) p)
 WHERE id=1;

INSERT INTO public.schema_migrations(version,applied_at) VALUES (224,now())
ON CONFLICT (version) DO NOTHING;
