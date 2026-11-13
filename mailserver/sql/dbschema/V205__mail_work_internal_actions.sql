-- P1-C internal Task/Chat/Drive actions. All admission remains behind the
-- existing feature.shared_mail_integrations toggle (seeded OFF).
ALTER TABLE public.mail_thread_work_events DROP CONSTRAINT mail_thread_work_events_event_type_check;
ALTER TABLE public.mail_thread_work_events ADD CONSTRAINT mail_thread_work_events_event_type_check
  CHECK(event_type IN ('created','claimed','assigned','reassigned','status_changed','due_changed',
    'handed_off','reopened','first_response','completed','sla_breached','commented','mentioned',
    'action_requested','action_completed'));

CREATE TABLE public.mail_work_action_links (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  mailbox_id bigint NOT NULL REFERENCES public.mailboxes(id) ON DELETE CASCADE,
  thread_id text NOT NULL,
  action_kind text NOT NULL CHECK(action_kind IN ('task','chat','drive')),
  target_id bigint,
  result_id bigint NOT NULL,
  event_id uuid NOT NULL REFERENCES public.mail_thread_work_events(id) ON DELETE CASCADE,
  created_by bigint REFERENCES public.users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  UNIQUE(event_id,action_kind)
);
CREATE INDEX mail_work_action_links_thread_idx
  ON public.mail_work_action_links(mailbox_id,thread_id,created_at,id);
ALTER TABLE public.mail_work_action_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.mail_work_action_links FORCE ROW LEVEL SECURITY;
CREATE POLICY mail_work_action_links_read ON public.mail_work_action_links FOR SELECT
  USING(mail_work_can_read(mailbox_id,NULLIF(current_setting('app.current_user_id',true),'')::bigint));

INSERT INTO public.schema_migrations (version, applied_at)
VALUES (205, statement_timestamp()) ON CONFLICT (version) DO NOTHING;
