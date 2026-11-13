-- Completion support for bounded SLA scanning and idempotent approved egress.
ALTER TABLE public.mail_thread_work
  ADD COLUMN sla_breached_at timestamptz;

CREATE UNIQUE INDEX mail_thread_work_sla_event_once_idx
  ON public.mail_thread_work_events(mailbox_id,thread_id,event_type)
  WHERE event_type='sla_breached';

COMMENT ON COLUMN public.mail_thread_work.sla_breached_at IS
  'Server-time breach marker; NULL until the bounded worker appends the one immutable breach event.';

INSERT INTO public.schema_migrations (version, applied_at)
VALUES (203, statement_timestamp()) ON CONFLICT (version) DO NOTHING;
