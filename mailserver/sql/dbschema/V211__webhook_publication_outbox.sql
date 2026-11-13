-- R4 durable webhook publication: additive-only schema. Older binaries ignore
-- the new scope column/table and continue their legacy post-commit dispatch.

ALTER TABLE public.webhook_subscriptions
  ADD COLUMN scope text NOT NULL DEFAULT 'self';
ALTER TABLE public.webhook_subscriptions
  ADD CONSTRAINT webhook_subscriptions_scope_check
  CHECK (scope IN ('self','organization'));

-- Delivery admission is durable too: an executor owns a bounded lease before
-- an HTTP attempt can enter memory.  Older binaries ignore these additive
-- columns and keep using the pre-V211 status/attempt fields.
ALTER TABLE public.webhook_deliveries
  ADD COLUMN lease_owner uuid,
  ADD COLUMN lease_expires_at timestamptz,
  ADD COLUMN next_attempt_at timestamptz NOT NULL DEFAULT statement_timestamp();
ALTER TABLE public.webhook_deliveries
  ADD CONSTRAINT webhook_deliveries_lease_shape CHECK (
    (lease_owner IS NULL)=(lease_expires_at IS NULL)
  );
CREATE INDEX webhook_deliveries_claim_idx
  ON public.webhook_deliveries(next_attempt_at,id)
  WHERE status IN ('pending','failed');

CREATE TABLE public.webhook_publications (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  event_id text NOT NULL UNIQUE
    CHECK (octet_length(event_id) BETWEEN 1 AND 128),
  event_type text NOT NULL
    CHECK (octet_length(event_type) BETWEEN 1 AND 128),
  source text NOT NULL
    CHECK (octet_length(source) BETWEEN 1 AND 256),
  audience text NOT NULL CHECK (audience IN ('user','mailbox')),
  subject_user_id bigint NOT NULL,
  subject_mailbox_id bigint,
  payload jsonb NOT NULL
    CHECK (jsonb_typeof(payload)='object' AND octet_length(payload::text)<=16384),
  state text NOT NULL DEFAULT 'pending'
    CHECK (state IN ('pending','leased','delivered','exhausted')),
  lease_owner uuid,
  lease_expires_at timestamptz,
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 12),
  next_attempt_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  last_error text CHECK (last_error IS NULL OR octet_length(last_error)<=2048),
  created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  completed_at timestamptz,
  CONSTRAINT webhook_publications_lease_shape CHECK (
    (state='leased')=(lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)
  ),
  CONSTRAINT webhook_publications_terminal_shape CHECK (
    (state IN ('delivered','exhausted'))=(completed_at IS NOT NULL)
  ),
  CONSTRAINT webhook_publications_subject_shape CHECK (
    (audience='user' AND subject_mailbox_id IS NULL)
    OR (audience='mailbox' AND subject_mailbox_id IS NOT NULL)
  )
);

CREATE INDEX webhook_publications_claim_idx
  ON public.webhook_publications(next_attempt_at,id)
  WHERE state IN ('pending','leased');
CREATE INDEX webhook_publications_retention_idx
  ON public.webhook_publications(completed_at,id)
  WHERE state IN ('delivered','exhausted');

ALTER TABLE public.webhook_publications ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.webhook_publications FORCE ROW LEVEL SECURITY;
ALTER TABLE public.webhook_publications OWNER TO setjoin_owner;
CREATE POLICY webhook_publications_worker ON public.webhook_publications
  USING (current_user='setjoin_worker') WITH CHECK (current_user='setjoin_worker');

INSERT INTO public.schema_migrations(version,applied_at)
VALUES (211,statement_timestamp()) ON CONFLICT(version) DO NOTHING;
