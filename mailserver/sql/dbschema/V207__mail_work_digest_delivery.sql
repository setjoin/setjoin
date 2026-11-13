-- Durable delivery clock for calm daily work digests. Existing rows are made
-- immediately eligible once a worker running V207 observes them.
ALTER TABLE public.mail_work_digest_ledger
  ADD COLUMN deliver_after timestamptz NOT NULL DEFAULT statement_timestamp();
CREATE INDEX mail_work_digest_due_idx ON public.mail_work_digest_ledger(deliver_after)
  WHERE delivered_at IS NULL;

INSERT INTO public.schema_migrations (version, applied_at)
VALUES (207, statement_timestamp()) ON CONFLICT (version) DO NOTHING;
