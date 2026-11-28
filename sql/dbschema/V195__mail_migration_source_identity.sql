-- V195__mail_migration_source_identity.sql
INSERT INTO public.feature_toggles(key,enabled,description) VALUES
  ('feature.mail_migration_source_identity',false,
   'Stable per-source identity, exact replay and reconciliation for mail migration. DEFAULT OFF.')
ON CONFLICT(key) DO NOTHING;
-- Expand-only authority for source-mailbox identity, immutable source objects,
-- committed checkpoints, and bounded post-import thread reconciliation.
-- No existing migration behavior reads these tables until its OFF feature gate
-- is enabled.

CREATE TABLE public.migration_source_instances (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  job_id bigint NOT NULL UNIQUE REFERENCES public.migration_jobs(id) ON DELETE CASCADE,
  source_type text NOT NULL CHECK (source_type IN ('imap','ews','m365')),
  source_mailbox_key text NOT NULL CHECK (length(source_mailbox_key) BETWEEN 1 AND 2048),
  selector_digest text NOT NULL CHECK (selector_digest ~ '^[0-9a-f]{64}$'),
  generation bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX migration_source_instances_identity_uniq
  ON public.migration_source_instances(source_type, source_mailbox_key, job_id);

CREATE TABLE public.migration_source_objects (
  source_instance_id uuid NOT NULL REFERENCES public.migration_source_instances(id) ON DELETE CASCADE,
  object_type text NOT NULL CHECK (object_type IN ('mail','calendar','contact')),
  source_object_id text NOT NULL CHECK (length(source_object_id) BETWEEN 1 AND 4096),
  source_version text NOT NULL DEFAULT '' CHECK (length(source_version) <= 4096),
  source_folder_id text NOT NULL DEFAULT '' CHECK (length(source_folder_id) <= 4096),
  projection_state text NOT NULL CHECK (projection_state IN ('applied','tombstoned')),
  target_kind text CHECK (target_kind IN ('message','calendar_event','contact')),
  target_id bigint,
  content_hash text CHECK (content_hash IS NULL OR content_hash ~ '^[0-9a-f]{64}$'),
  applied_operation_id uuid NOT NULL,
  applied_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (source_instance_id, object_type, source_object_id),
  CONSTRAINT migration_source_objects_target_shape CHECK (
    (projection_state = 'tombstoned' AND target_kind IS NULL AND target_id IS NULL)
    OR (projection_state = 'applied' AND target_kind IS NOT NULL AND target_id IS NOT NULL)
  )
);
CREATE INDEX migration_source_objects_target_idx
  ON public.migration_source_objects(target_kind, target_id)
  WHERE projection_state = 'applied';

CREATE TABLE public.migration_object_operations (
  operation_id uuid PRIMARY KEY,
  job_id bigint NOT NULL REFERENCES public.migration_jobs(id) ON DELETE CASCADE,
  source_instance_id uuid NOT NULL REFERENCES public.migration_source_instances(id) ON DELETE CASCADE,
  object_type text NOT NULL CHECK (object_type IN ('mail','calendar','contact')),
  source_object_id text NOT NULL CHECK (length(source_object_id) BETWEEN 1 AND 4096),
  source_version text NOT NULL DEFAULT '' CHECK (length(source_version) <= 4096),
  source_folder_id text NOT NULL DEFAULT '' CHECK (length(source_folder_id) <= 4096),
  source_change text NOT NULL CHECK (source_change IN ('upsert','move','delete')),
  content_hash text CHECK (content_hash IS NULL OR content_hash ~ '^[0-9a-f]{64}$'),
  state text NOT NULL CHECK (state IN ('accepted','completed','failed')),
  target_kind text,
  target_id bigint,
  error_code text,
  created_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  CONSTRAINT migration_object_operations_terminal_shape CHECK (
    (state = 'accepted' AND completed_at IS NULL)
    OR (state IN ('completed','failed') AND completed_at IS NOT NULL)
  )
);
CREATE INDEX migration_object_operations_job_created_idx
  ON public.migration_object_operations(job_id, created_at, operation_id);

CREATE TABLE public.migration_checkpoints (
  job_id bigint NOT NULL REFERENCES public.migration_jobs(id) ON DELETE CASCADE,
  scope_key text NOT NULL CHECK (length(scope_key) BETWEEN 1 AND 4096),
  cursor_kind text NOT NULL CHECK (cursor_kind IN ('imap_uid','ews_sync_state','m365_delta_link')),
  cursor_value jsonb NOT NULL,
  source_generation bigint NOT NULL CHECK (source_generation > 0),
  committed_count bigint NOT NULL DEFAULT 0 CHECK (committed_count >= 0),
  committed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (job_id, scope_key, cursor_kind)
);

CREATE TABLE public.migration_thread_reconcile_jobs (
  job_id bigint PRIMARY KEY REFERENCES public.migration_jobs(id) ON DELETE CASCADE,
  target_mailbox_id bigint NOT NULL REFERENCES public.mailboxes(id) ON DELETE CASCADE,
  after_message_id bigint NOT NULL DEFAULT 0 CHECK (after_message_id >= 0),
  remaining bigint NOT NULL DEFAULT 0 CHECK (remaining >= 0),
  state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','running','completed','failed')),
  lease_until timestamptz,
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 100),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Tenant readers may inspect their own migration evidence. All mutations run
-- through SECURITY DEFINER reducers on the BYPASSRLS worker pool.
ALTER TABLE public.migration_source_instances ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.migration_source_instances FORCE ROW LEVEL SECURITY;
CREATE POLICY migration_source_instances_read ON public.migration_source_instances
  FOR SELECT TO public USING (EXISTS (
    SELECT 1 FROM public.migration_jobs j
    WHERE j.id = job_id AND j.target_mailbox_id =
      NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint
  ));

ALTER TABLE public.migration_source_objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.migration_source_objects FORCE ROW LEVEL SECURITY;
CREATE POLICY migration_source_objects_read ON public.migration_source_objects
  FOR SELECT TO public USING (EXISTS (
    SELECT 1 FROM public.migration_source_instances i
    JOIN public.migration_jobs j ON j.id = i.job_id
    WHERE i.id = source_instance_id AND j.target_mailbox_id =
      NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint
  ));

ALTER TABLE public.migration_object_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.migration_object_operations FORCE ROW LEVEL SECURITY;
CREATE POLICY migration_object_operations_read ON public.migration_object_operations
  FOR SELECT TO public USING (EXISTS (
    SELECT 1 FROM public.migration_jobs j
    WHERE j.id = job_id AND j.target_mailbox_id =
      NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint
  ));

ALTER TABLE public.migration_checkpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.migration_checkpoints FORCE ROW LEVEL SECURITY;
CREATE POLICY migration_checkpoints_read ON public.migration_checkpoints
  FOR SELECT TO public USING (EXISTS (
    SELECT 1 FROM public.migration_jobs j
    WHERE j.id = job_id AND j.target_mailbox_id =
      NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint
  ));

ALTER TABLE public.migration_thread_reconcile_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.migration_thread_reconcile_jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY migration_thread_reconcile_jobs_read ON public.migration_thread_reconcile_jobs
  FOR SELECT TO public USING (target_mailbox_id =
    NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint);

INSERT INTO public.schema_migrations (version, applied_at) VALUES (195, now())
ON CONFLICT(version) DO NOTHING;
