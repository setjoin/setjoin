-- Exchange replacement assessment contract. All product behavior is dormant
-- until feature.exchange_replacement_assessment is explicitly enabled.

CREATE TABLE public.exchange_registry_snapshots (
  registry_version integer PRIMARY KEY CHECK (registry_version > 0),
  source_digest text NOT NULL UNIQUE CHECK (source_digest ~ '^[0-9a-f]{64}$'),
  projection jsonb NOT NULL CHECK (jsonb_typeof(projection) = 'object'),
  installed_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE public.exchange_assessment_projects (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  domain_id bigint NOT NULL REFERENCES public.domains(id) ON DELETE RESTRICT,
  name text NOT NULL CHECK (name = btrim(name) AND octet_length(name) BETWEEN 1 AND 128),
  state text NOT NULL DEFAULT 'active' CHECK (state IN ('active','archived','deletion_pending','deleted')),
  retention_until timestamptz,
  created_by bigint NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (domain_id, name)
);

CREATE TABLE public.exchange_assessment_runs (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  project_id bigint NOT NULL REFERENCES public.exchange_assessment_projects(id) ON DELETE RESTRICT,
  generation bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
  state text NOT NULL DEFAULT 'created' CHECK (state IN (
    'created','preflight','uploading','validating','processing','partial','blocked',
    'ready','failed','cancelled','expired','deletion_pending','deleted'
  )),
  support_cell_id text NOT NULL,
  support_cell_digest text NOT NULL CHECK (support_cell_digest ~ '^[0-9a-f]{64}$'),
  registry_version integer NOT NULL REFERENCES public.exchange_registry_snapshots(registry_version),
  registry_digest text NOT NULL CHECK (registry_digest ~ '^[0-9a-f]{64}$'),
  catalog_version integer NOT NULL CHECK (catalog_version > 0),
  collector_version text NOT NULL,
  checkpoint jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(checkpoint) = 'object'),
  error_code text,
  created_by bigint NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  UNIQUE (project_id, generation),
  CONSTRAINT exchange_assessment_runs_error_shape CHECK (
    (state IN ('failed','blocked') AND error_code IS NOT NULL) OR state NOT IN ('failed','blocked')
  )
);
CREATE UNIQUE INDEX exchange_assessment_one_active_import_idx
  ON public.exchange_assessment_runs(project_id)
  WHERE state IN ('uploading','validating','processing');
CREATE INDEX exchange_assessment_runs_project_state_idx
  ON public.exchange_assessment_runs(project_id, state, id DESC);

CREATE TABLE public.exchange_assessment_leases (
  run_id bigint PRIMARY KEY REFERENCES public.exchange_assessment_runs(id) ON DELETE CASCADE,
  lease_owner text NOT NULL CHECK (octet_length(lease_owner) BETWEEN 1 AND 128),
  fencing_token bigint NOT NULL CHECK (fencing_token > 0),
  expires_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE public.exchange_assessment_probe_results (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  run_id bigint NOT NULL REFERENCES public.exchange_assessment_runs(id) ON DELETE CASCADE,
  root_id text NOT NULL,
  probe_id text NOT NULL,
  capability_id text NOT NULL,
  stable_instance_id text NOT NULL,
  terminal_state text NOT NULL CHECK (terminal_state IN (
    'collected','unknown_value','permission_denied','collection_failed',
    'unsupported_source','not_applicable'
  )),
  diagnostic_id text,
  facts jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(facts) = 'object'),
  observed_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (run_id, probe_id, stable_instance_id)
);
CREATE INDEX exchange_probe_results_keyset_idx
  ON public.exchange_assessment_probe_results(run_id, capability_id, terminal_state, stable_instance_id, id);

CREATE TABLE public.exchange_assessment_artifacts (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  run_id bigint NOT NULL REFERENCES public.exchange_assessment_runs(id) ON DELETE RESTRICT,
  kind text NOT NULL CHECK (kind IN ('bundle','manifest','report_json','report_html','report_pdf','receipt','support_bundle')),
  object_key text NOT NULL,
  sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  crypto_profile text NOT NULL CHECK (crypto_profile IN ('standard','smx','hybrid')),
  key_id text NOT NULL,
  disposition text NOT NULL DEFAULT 'active' CHECK (disposition IN (
    'temporary','active','active_store_deleted','backup_expiry_pending',
    'backup_expired_verified','external_key_destroyed'
  )),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (run_id, kind, sha256)
);

CREATE TABLE public.exchange_assessment_evidence (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  run_id bigint NOT NULL REFERENCES public.exchange_assessment_runs(id) ON DELETE RESTRICT,
  capability_id text NOT NULL,
  tier text NOT NULL CHECK (tier IN ('T0','T1','T2')),
  artifact_id bigint NOT NULL REFERENCES public.exchange_assessment_artifacts(id) ON DELETE RESTRICT,
  support_cell_digest text NOT NULL CHECK (support_cell_digest ~ '^[0-9a-f]{64}$'),
  case_ids text[] NOT NULL CHECK (cardinality(case_ids) > 0),
  captured_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  invalidated_at timestamptz,
  invalidation_reason text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX exchange_evidence_resolution_idx
  ON public.exchange_assessment_evidence(run_id, capability_id, tier, expires_at DESC, id DESC);

CREATE TABLE public.exchange_assessment_decisions (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  run_id bigint NOT NULL REFERENCES public.exchange_assessment_runs(id) ON DELETE RESTRICT,
  capability_id text NOT NULL,
  outcome_mapping text NOT NULL CHECK (outcome_mapping IN ('native','transformed','alternative','none')),
  decision text NOT NULL CHECK (decision IN ('pending','accepted','rejected','waived')),
  reason text,
  waiver_expires_at timestamptz,
  actor_id bigint NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  decided_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (run_id, capability_id)
);

CREATE TABLE public.exchange_assessment_publications (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  run_id bigint NOT NULL REFERENCES public.exchange_assessment_runs(id) ON DELETE RESTRICT,
  projection_digest text NOT NULL CHECK (projection_digest ~ '^[0-9a-f]{64}$'),
  receipt_artifact_id bigint NOT NULL REFERENCES public.exchange_assessment_artifacts(id) ON DELETE RESTRICT,
  published_by bigint NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  published_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  UNIQUE (run_id, projection_digest)
);

CREATE TABLE public.exchange_assessment_tombstones (
  artifact_digest text NOT NULL CHECK (artifact_digest ~ '^[0-9a-f]{64}$'),
  run_id bigint NOT NULL,
  disposition text NOT NULL CHECK (disposition IN ('active_store_deleted','backup_expiry_pending','backup_expired_verified','external_key_destroyed')),
  requested_by bigint NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  receipt_id text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(run_id,artifact_digest)
);

INSERT INTO public.admin_permissions(permission_key, category, description, is_sensitive) VALUES
  ('exchange.assessment.read',    'Exchange replacement', 'View assessment projects, runs, facts, reports and receipts', false),
  ('exchange.assessment.run',     'Exchange replacement', 'Create, upload, validate, process, cancel and resume assessments', true),
  ('exchange.assessment.decide',  'Exchange replacement', 'Accept, reject or waive capability mappings', true),
  ('exchange.assessment.attest',  'Exchange replacement', 'Attach operator and completeness attestations', true),
  ('exchange.assessment.audit',   'Exchange replacement', 'Read and export assessment evidence and audit records', true),
  ('exchange.assessment.publish', 'Exchange replacement', 'Publish evidence-derived comparison claims', true),
  ('exchange.assessment.delete',  'Exchange replacement', 'Delete assessment artifacts and request backup-expiry closure', true)
ON CONFLICT (permission_key) DO NOTHING;

UPDATE public.admin_role_groups
SET permissions = (SELECT array_agg(DISTINCT p ORDER BY p)
  FROM unnest(permissions || ARRAY[
    'exchange.assessment.read','exchange.assessment.run','exchange.assessment.decide',
    'exchange.assessment.attest','exchange.assessment.audit','exchange.assessment.publish',
    'exchange.assessment.delete'
  ]) p)
WHERE id = 1;

INSERT INTO public.feature_toggles(key, enabled, description) VALUES
  ('feature.exchange_replacement_assessment', false, 'Exchange replacement assessment, evidence, decision and publication workflow. Default OFF.')
ON CONFLICT (key) DO NOTHING;

INSERT INTO public.schema_migrations(version, applied_at) VALUES (213, now()) ON CONFLICT (version) DO NOTHING;
