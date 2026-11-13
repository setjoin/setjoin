-- Complete the versioned mailbox SLA calendar and exactly-once first-response seam.
-- Existing behavior remains unreachable while feature.shared_mail_work is OFF.
CREATE TABLE public.mail_work_sla_policies (
  mailbox_id bigint PRIMARY KEY REFERENCES public.mailboxes(id) ON DELETE CASCADE,
  timezone text NOT NULL DEFAULT 'UTC' CHECK(octet_length(timezone) BETWEEN 1 AND 64),
  weekday_mask smallint NOT NULL DEFAULT 62 CHECK(weekday_mask BETWEEN 1 AND 127),
  workday_start time NOT NULL DEFAULT '09:00',
  workday_end time NOT NULL DEFAULT '17:00',
  holidays date[] NOT NULL DEFAULT '{}',
  sla_minutes integer NOT NULL DEFAULT 480 CHECK(sla_minutes BETWEEN 1 AND 525600),
  generation bigint NOT NULL DEFAULT 1 CHECK(generation > 0),
  updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  CHECK(workday_start < workday_end),
  CHECK(cardinality(holidays) <= 366)
);
ALTER TABLE public.mail_work_sla_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.mail_work_sla_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY mail_work_sla_policies_read ON public.mail_work_sla_policies FOR SELECT
  USING(mail_work_can_read(mailbox_id,NULLIF(current_setting('app.current_user_id',true),'')::bigint));

CREATE UNIQUE INDEX mail_thread_work_first_response_once_idx
  ON public.mail_thread_work_events(mailbox_id,thread_id,event_type)
  WHERE event_type='first_response';

COMMENT ON TABLE public.mail_work_sla_policies IS
  'Versioned mailbox business calendar. Absence means the documented UTC Monday-Friday 09:00-17:00, 480-minute default.';

INSERT INTO public.schema_migrations (version, applied_at)
VALUES (206, statement_timestamp()) ON CONFLICT (version) DO NOTHING;
