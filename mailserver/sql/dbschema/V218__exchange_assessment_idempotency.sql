CREATE TABLE public.exchange_assessment_idempotency (
  idempotency_key uuid PRIMARY KEY,
  actor_id bigint NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  operation text NOT NULL CHECK (operation IN ('project.create','run.create')),
  payload_sha256 text NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
  result jsonb NOT NULL CHECK (jsonb_typeof(result)='object' AND octet_length(result::text)<=262144),
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.exchange_assessment_idempotency ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.exchange_assessment_idempotency FORCE ROW LEVEL SECURITY;
ALTER TABLE public.exchange_assessment_idempotency OWNER TO setjoin_worker;
GRANT SELECT,INSERT ON public.exchange_assessment_idempotency TO setjoin_worker;
REVOKE ALL ON public.exchange_assessment_idempotency FROM PUBLIC,setjoin_app;
INSERT INTO public.schema_migrations (version, applied_at) VALUES (218, now()) ON CONFLICT (version) DO NOTHING;
