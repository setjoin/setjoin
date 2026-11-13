-- Complete the default-OFF Exchange assessment evidence lifecycle. Business
-- authority remains in reducers; these tables only retain immutable facts and
-- generation-bound projections.

CREATE TABLE public.exchange_assessment_attestations (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  run_id bigint NOT NULL REFERENCES public.exchange_assessment_runs(id) ON DELETE RESTRICT,
  kind text NOT NULL CHECK (kind IN ('collection_zero','completeness','handling','backup_expiry')),
  subject_digest text NOT NULL CHECK (subject_digest ~ '^[0-9a-f]{64}$'),
  statement jsonb NOT NULL CHECK (jsonb_typeof(statement)='object' AND octet_length(statement::text)<=65536),
  actor_id bigint NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  issued_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  UNIQUE(run_id,kind,subject_digest)
);

CREATE TABLE public.exchange_assessment_claim_snapshots (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  run_id bigint NOT NULL REFERENCES public.exchange_assessment_runs(id) ON DELETE RESTRICT,
  run_generation bigint NOT NULL CHECK (run_generation>0),
  registry_digest text NOT NULL CHECK (registry_digest ~ '^[0-9a-f]{64}$'),
  support_cell_digest text NOT NULL CHECK (support_cell_digest ~ '^[0-9a-f]{64}$'),
  projection jsonb NOT NULL CHECK (jsonb_typeof(projection)='object'),
  projection_digest text NOT NULL CHECK (projection_digest ~ '^[0-9a-f]{64}$'),
  resolved_by bigint NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  resolved_at timestamptz NOT NULL DEFAULT now(),
  invalidated_at timestamptz,
  invalidation_reason text,
  UNIQUE(run_id,run_generation,projection_digest)
);
CREATE INDEX exchange_claim_snapshots_current_idx
  ON public.exchange_assessment_claim_snapshots(run_id,id DESC) WHERE invalidated_at IS NULL;

CREATE TABLE public.exchange_assessment_receipts (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  run_id bigint REFERENCES public.exchange_assessment_runs(id) ON DELETE RESTRICT,
  kind text NOT NULL CHECK (kind IN ('origin','import','publication','deletion','backup_expiry')),
  subject_digest text NOT NULL CHECK (subject_digest ~ '^[0-9a-f]{64}$'),
  receipt jsonb NOT NULL CHECK (jsonb_typeof(receipt)='object' AND octet_length(receipt::text)<=262144),
  signature_algorithm text NOT NULL CHECK (signature_algorithm IN ('ed25519','sm2')),
  signing_key_id text NOT NULL CHECK (octet_length(signing_key_id) BETWEEN 1 AND 128),
  signature bytea NOT NULL CHECK (octet_length(signature) BETWEEN 64 AND 512),
  created_by bigint NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(kind,subject_digest),
  CHECK (run_id IS NOT NULL OR kind='deletion')
);

CREATE TABLE public.exchange_assessment_uploads (
  id uuid PRIMARY KEY,
  run_id bigint NOT NULL UNIQUE REFERENCES public.exchange_assessment_runs(id) ON DELETE RESTRICT,
  origin_digest text NOT NULL CHECK (origin_digest ~ '^[0-9a-f]{64}$'),
  schema_version integer NOT NULL CHECK (schema_version>0),
  registry_digest text NOT NULL CHECK (registry_digest ~ '^[0-9a-f]{64}$'),
  support_cell_digest text NOT NULL CHECK (support_cell_digest ~ '^[0-9a-f]{64}$'),
  state text NOT NULL DEFAULT 'created' CHECK (state IN ('created','streaming','finalized','rejected','cancelled')),
  expected_size bigint NOT NULL CHECK (expected_size BETWEEN 1 AND 1073741824),
  received_size bigint NOT NULL DEFAULT 0 CHECK (received_size>=0),
  next_sequence integer NOT NULL DEFAULT 0 CHECK (next_sequence>=0),
  idempotency_key uuid NOT NULL UNIQUE,
  created_by bigint NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE public.exchange_assessment_upload_chunks (
  upload_id uuid NOT NULL REFERENCES public.exchange_assessment_uploads(id) ON DELETE CASCADE,
  sequence integer NOT NULL CHECK (sequence>=0),
  size_bytes integer NOT NULL CHECK (size_bytes BETWEEN 1 AND 8388608),
  sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  object_key text NOT NULL CHECK (octet_length(object_key) BETWEEN 1 AND 1024),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(upload_id,sequence)
);

CREATE TABLE public.exchange_assessment_deletion_requests (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  project_id bigint NOT NULL REFERENCES public.exchange_assessment_projects(id) ON DELETE RESTRICT,
  run_id bigint REFERENCES public.exchange_assessment_runs(id) ON DELETE RESTRICT,
  artifact_id bigint REFERENCES public.exchange_assessment_artifacts(id) ON DELETE RESTRICT,
  scope text NOT NULL CHECK (scope IN ('artifact','run','project')),
  state text NOT NULL DEFAULT 'requested' CHECK (state IN ('requested','active_deleted','backup_pending','verified','rejected')),
  reason text NOT NULL CHECK (reason=btrim(reason) AND octet_length(reason) BETWEEN 1 AND 1024),
  requested_by bigint NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  requested_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((scope='artifact' AND artifact_id IS NOT NULL AND run_id IS NOT NULL)
      OR (scope='run' AND artifact_id IS NULL AND run_id IS NOT NULL)
      OR (scope='project' AND artifact_id IS NULL AND run_id IS NULL))
);

ALTER TABLE public.exchange_assessment_artifacts
  ADD COLUMN ciphertext_size bigint CHECK (ciphertext_size>0),
  ADD COLUMN nonce bytea CHECK (nonce IS NULL OR octet_length(nonce) BETWEEN 12 AND 32),
  ADD COLUMN wrapped_dek bytea CHECK (wrapped_dek IS NULL OR octet_length(wrapped_dek) BETWEEN 32 AND 4096),
  ADD COLUMN aad_sha256 text CHECK (aad_sha256 IS NULL OR aad_sha256 ~ '^[0-9a-f]{64}$'),
  ADD COLUMN retention_until timestamptz,
  ADD COLUMN deleted_at timestamptz,
  ADD CONSTRAINT exchange_artifact_envelope_complete CHECK (
    (nonce IS NULL AND wrapped_dek IS NULL AND aad_sha256 IS NULL AND ciphertext_size IS NULL)
    OR (nonce IS NOT NULL AND wrapped_dek IS NOT NULL AND aad_sha256 IS NOT NULL AND ciphertext_size IS NOT NULL)
  );

INSERT INTO public.schema_migrations (version, applied_at) VALUES (216, now()) ON CONFLICT (version) DO NOTHING;
