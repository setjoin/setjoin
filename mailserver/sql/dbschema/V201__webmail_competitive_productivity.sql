-- V201: OFF-gated mail productivity authorities. Existing JMAP/session state,
-- MIME and typed search remain byte-compatible until an individual flag flips.

INSERT INTO public.feature_toggles(key,enabled,description) VALUES
 ('feature.mail_search_builder',false,'Deterministic EN/ZH search intent and editable chips. DEFAULT OFF.'),
 ('feature.sender_control_center',false,'Reducer-authoritative personal sender controls. DEFAULT OFF.'),
 ('feature.shared_mail_work',false,'Delegated shared-mail thread ownership and SLA state. DEFAULT OFF.'),
 ('feature.shared_mail_comments',false,'Private shared-mail comments and handoff. DEFAULT OFF.'),
 ('feature.shared_mail_notifications',false,'Calm work notifications and digests. DEFAULT OFF.'),
 ('feature.shared_mail_analytics',false,'Aggregate shared-mail response analytics. DEFAULT OFF.'),
 ('feature.shared_mail_integrations',false,'Bounded work-event actions and signed egress. DEFAULT OFF.'),
 ('feature.shared_mail_drafts',false,'Lease-based shared draft collaboration. DEFAULT OFF.')
ON CONFLICT(key) DO NOTHING;

ALTER TABLE public.mailboxes ADD COLUMN jmap_mailwork_state bigint NOT NULL DEFAULT 0 CHECK(jmap_mailwork_state>=0);

CREATE TABLE public.sender_control_state (
  user_id bigint PRIMARY KEY REFERENCES public.users(id) ON DELETE CASCADE,
  generation bigint NOT NULL DEFAULT 1 CHECK(generation>0),
  updated_at timestamptz NOT NULL DEFAULT statement_timestamp()
);
INSERT INTO public.sender_control_state(user_id) SELECT id FROM public.users ON CONFLICT DO NOTHING;

CREATE TABLE public.sender_control_operations (
  operation_id uuid PRIMARY KEY,
  user_id bigint NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  generation bigint NOT NULL CHECK(generation>0),
  sender_address text NOT NULL CHECK(sender_address=lower(sender_address) AND octet_length(sender_address) BETWEEN 3 AND 320),
  sender_digest text NOT NULL CHECK(sender_digest~'^[0-9a-f]{64}$'),
  action text NOT NULL CHECK(action IN ('always_focus','never_focus','vip','not_vip','safe','block','never_block','report_phishing','report_spam','undo')),
  request_digest text NOT NULL CHECK(request_digest~'^[0-9a-f]{64}$'),
  target_operation_id uuid REFERENCES public.sender_control_operations(operation_id) ON DELETE RESTRICT,
  before_state jsonb NOT NULL DEFAULT '{}'::jsonb,
  result jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT statement_timestamp()
);
CREATE TABLE public.sender_feedback_outbox (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  operation_id uuid NOT NULL UNIQUE REFERENCES public.sender_control_operations(operation_id) ON DELETE CASCADE,
  user_id bigint NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  mailbox_id bigint NOT NULL REFERENCES public.mailboxes(id) ON DELETE CASCADE,
  message_id bigint NOT NULL,
  received_at timestamptz NOT NULL,
  feedback_kind text NOT NULL CHECK(feedback_kind IN ('spam','phishing')),
  state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','claimed','completed','failed','cancelled')),
  attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 100),
  lease_until timestamptz,last_error text,created_at timestamptz NOT NULL DEFAULT statement_timestamp(),completed_at timestamptz,
  UNIQUE(user_id,mailbox_id,message_id,received_at,feedback_kind)
);
CREATE TABLE public.sender_list_operations (
  operation_id uuid PRIMARY KEY,
  user_id bigint NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  generation bigint NOT NULL CHECK(generation>0),
  request_digest text NOT NULL CHECK(request_digest~'^[0-9a-f]{64}$'),
  result jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT statement_timestamp()
);

CREATE TABLE public.mail_work_changes (
  mailbox_id bigint NOT NULL REFERENCES public.mailboxes(id) ON DELETE CASCADE,
  state_seq bigint NOT NULL CHECK(state_seq>0),
  object_kind text NOT NULL CHECK(object_kind IN ('work','comment','draft','resync')),
  object_id text NOT NULL CHECK(octet_length(object_id) BETWEEN 1 AND 256),
  op text NOT NULL CHECK(op IN ('created','updated','destroyed','resync')),
  occurred_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  PRIMARY KEY(mailbox_id,state_seq,object_kind,object_id)
);
CREATE INDEX mail_work_changes_retention_idx ON public.mail_work_changes(occurred_at);

CREATE TABLE public.mail_thread_work (
  mailbox_id bigint NOT NULL REFERENCES public.mailboxes(id) ON DELETE CASCADE,
  thread_id text NOT NULL CHECK(octet_length(thread_id) BETWEEN 1 AND 256),
  status text NOT NULL DEFAULT 'unassigned' CHECK(status IN ('unassigned','owned','waiting','done')),
  assignee_user_id bigint REFERENCES public.users(id) ON DELETE SET NULL,
  due_at timestamptz,
  sla_minutes integer CHECK(sla_minutes BETWEEN 1 AND 525600),
  sla_policy_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
  generation bigint NOT NULL DEFAULT 1 CHECK(generation>0),
  first_activity_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  first_response_at timestamptz,last_activity_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  completed_at timestamptz,last_event_id uuid,
  PRIMARY KEY(mailbox_id,thread_id),
  CONSTRAINT mail_thread_work_shape CHECK(
    (status='unassigned' AND assignee_user_id IS NULL AND completed_at IS NULL)
    OR (status IN ('owned','waiting') AND assignee_user_id IS NOT NULL AND completed_at IS NULL)
    OR (status='done' AND completed_at IS NOT NULL))
);
CREATE INDEX mail_thread_work_queue_idx ON public.mail_thread_work(mailbox_id,status,due_at,last_activity_at);

CREATE TABLE public.mail_thread_work_events (
  id uuid PRIMARY KEY,
  mailbox_id bigint NOT NULL REFERENCES public.mailboxes(id) ON DELETE CASCADE,
  thread_id text NOT NULL,
  generation bigint NOT NULL CHECK(generation>0),
  event_type text NOT NULL CHECK(event_type IN ('created','claimed','assigned','reassigned','status_changed','due_changed','handed_off','reopened','first_response','completed','sla_breached','commented','mentioned')),
  actor_user_id bigint REFERENCES public.users(id) ON DELETE SET NULL,
  actor_display_snapshot text NOT NULL CHECK(octet_length(actor_display_snapshot) BETWEEN 1 AND 256),
  before_state jsonb NOT NULL,after_state jsonb NOT NULL,
  reason text NOT NULL CHECK(octet_length(reason) BETWEEN 1 AND 1024),
  occurred_at timestamptz NOT NULL DEFAULT statement_timestamp()
);
CREATE INDEX mail_thread_work_events_stream_idx ON public.mail_thread_work_events(mailbox_id,occurred_at,id);

CREATE TABLE public.mail_work_operations (
  operation_id uuid PRIMARY KEY,
  mailbox_id bigint NOT NULL REFERENCES public.mailboxes(id) ON DELETE CASCADE,
  actor_user_id bigint NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  operation_kind text NOT NULL CHECK(operation_kind IN ('work_set','comment_set','comment_edit','outbox_action','draft_acquire','draft_renew','draft_save','draft_release','draft_handoff','draft_takeover','draft_submit')),
  request_digest text NOT NULL CHECK(request_digest~'^[0-9a-f]{64}$'),
  result jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT statement_timestamp()
);

CREATE TABLE public.mail_thread_comments (
  id uuid PRIMARY KEY,
  mailbox_id bigint NOT NULL REFERENCES public.mailboxes(id) ON DELETE CASCADE,
  thread_id text NOT NULL,
  author_user_id bigint REFERENCES public.users(id) ON DELETE SET NULL,
  author_display_snapshot text NOT NULL CHECK(octet_length(author_display_snapshot) BETWEEN 1 AND 256),
  body text NOT NULL CHECK(octet_length(body) BETWEEN 1 AND 8192 AND body!~'[\x00]'),
  replaces_comment_id uuid REFERENCES public.mail_thread_comments(id) ON DELETE RESTRICT,
  tombstoned_at timestamptz,tombstoned_by bigint REFERENCES public.users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  operation_id uuid NOT NULL UNIQUE
);
CREATE INDEX mail_thread_comments_stream_idx ON public.mail_thread_comments(mailbox_id,thread_id,created_at,id);
CREATE TABLE public.mail_thread_comment_mentions (
  comment_id uuid NOT NULL REFERENCES public.mail_thread_comments(id) ON DELETE CASCADE,
  user_id bigint NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  capability text NOT NULL CHECK(capability IN ('view_only','comment')),
  PRIMARY KEY(comment_id,user_id)
);

CREATE TABLE public.mail_work_outbox (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  event_id uuid REFERENCES public.mail_thread_work_events(id) ON DELETE CASCADE,
  consumer_kind text NOT NULL CHECK(consumer_kind IN ('push','digest','metric','task','chat','drive','webhook')),
  dedupe_key text NOT NULL UNIQUE CHECK(octet_length(dedupe_key) BETWEEN 1 AND 256),
  payload_version integer NOT NULL DEFAULT 1 CHECK(payload_version=1),
  payload jsonb NOT NULL,
  state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','claimed','completed','failed','cancelled')),
  attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 100),
  lease_until timestamptz,last_error text,receipt jsonb,
  created_at timestamptz NOT NULL DEFAULT statement_timestamp(),completed_at timestamptz
);

CREATE TABLE public.mail_work_notification_preferences (
  mailbox_id bigint NOT NULL REFERENCES public.mailboxes(id) ON DELETE CASCADE,
  user_id bigint NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  category text NOT NULL CHECK(category IN ('assignment','mention','due','breach','comment','handoff','priority','mailbox_rule')),
  delivery text NOT NULL DEFAULT 'immediate' CHECK(delivery IN ('immediate','digest','off')),
  timezone text NOT NULL DEFAULT 'UTC' CHECK(octet_length(timezone) BETWEEN 1 AND 64),
  digest_hour smallint NOT NULL DEFAULT 9 CHECK(digest_hour BETWEEN 0 AND 23),
  generation bigint NOT NULL DEFAULT 1 CHECK(generation>0),
  PRIMARY KEY(mailbox_id,user_id,category)
);
CREATE TABLE public.mail_work_digest_ledger (
  mailbox_id bigint NOT NULL,user_id bigint NOT NULL,
  category text NOT NULL CHECK(category IN ('assignment','mention','due','breach','comment','handoff','priority','mailbox_rule')),
  window_start timestamptz NOT NULL,
  cursor_event_id uuid,dedupe_key text NOT NULL UNIQUE,delivered_at timestamptz,
  PRIMARY KEY(mailbox_id,user_id,category,window_start),
  FOREIGN KEY(mailbox_id,user_id,category) REFERENCES public.mail_work_notification_preferences(mailbox_id,user_id,category)
);

CREATE TABLE public.mail_work_notification_deliveries (
  outbox_id bigint NOT NULL REFERENCES public.mail_work_outbox(id) ON DELETE CASCADE,
  user_id bigint NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  event_id uuid NOT NULL REFERENCES public.mail_thread_work_events(id) ON DELETE CASCADE,
  category text NOT NULL CHECK(category IN ('assignment','mention','due','breach','comment','handoff','priority','mailbox_rule')),
  channel text NOT NULL CHECK(channel IN ('realtime','digest')),
  outcome text NOT NULL CHECK(outcome IN ('delivered','queued','suppressed')),
  why text NOT NULL CHECK(octet_length(why) BETWEEN 1 AND 128),
  delivered_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  PRIMARY KEY(outbox_id,user_id)
);
CREATE TABLE public.mail_work_notification_rate_windows (
  user_id bigint NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  window_start timestamptz NOT NULL,
  delivered_count smallint NOT NULL DEFAULT 0 CHECK(delivered_count BETWEEN 0 AND 6),
  PRIMARY KEY(user_id,window_start)
);
CREATE TABLE public.mail_work_consumer_effects (
  outbox_id bigint PRIMARY KEY REFERENCES public.mail_work_outbox(id) ON DELETE CASCADE,
  receipt jsonb NOT NULL,
  completed_at timestamptz NOT NULL DEFAULT statement_timestamp()
);

CREATE FUNCTION public.sender_control_user_seed() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,public AS $$ BEGIN
  INSERT INTO sender_control_state(user_id) VALUES(NEW.id) ON CONFLICT DO NOTHING;
  RETURN NEW;
END $$;
CREATE TRIGGER sender_control_user_seed AFTER INSERT ON public.users
FOR EACH ROW EXECUTE FUNCTION public.sender_control_user_seed();

CREATE TABLE public.mail_work_metric_daily (
  mailbox_id bigint NOT NULL REFERENCES public.mailboxes(id) ON DELETE CASCADE,
  metric_day date NOT NULL,policy_version integer NOT NULL DEFAULT 1 CHECK(policy_version>0),
  conversation_count integer NOT NULL DEFAULT 0 CHECK(conversation_count>=0),
  first_response_count integer NOT NULL DEFAULT 0 CHECK(first_response_count>=0),
  first_response_seconds bigint NOT NULL DEFAULT 0 CHECK(first_response_seconds>=0),
  completed_count integer NOT NULL DEFAULT 0 CHECK(completed_count>=0),
  breached_count integer NOT NULL DEFAULT 0 CHECK(breached_count>=0),
  actor_cohort_count integer NOT NULL DEFAULT 0 CHECK(actor_cohort_count>=0),
  rebuilt_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  PRIMARY KEY(mailbox_id,metric_day,policy_version)
);
CREATE TABLE public.mail_work_metric_conversations (
  mailbox_id bigint NOT NULL REFERENCES public.mailboxes(id) ON DELETE CASCADE,
  metric_day date NOT NULL,
  policy_version integer NOT NULL DEFAULT 1 CHECK(policy_version>0),
  thread_id text NOT NULL CHECK(octet_length(thread_id) BETWEEN 1 AND 256),
  PRIMARY KEY(mailbox_id,metric_day,policy_version,thread_id)
);
CREATE TABLE public.mail_work_metric_actors (
  mailbox_id bigint NOT NULL REFERENCES public.mailboxes(id) ON DELETE CASCADE,
  metric_day date NOT NULL,
  policy_version integer NOT NULL DEFAULT 1 CHECK(policy_version>0),
  actor_user_id bigint NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  PRIMARY KEY(mailbox_id,metric_day,policy_version,actor_user_id)
);

CREATE TABLE public.mail_draft_collaboration (
  draft_session_id uuid PRIMARY KEY,
  mailbox_id bigint NOT NULL REFERENCES public.mailboxes(id) ON DELETE CASCADE,
  message_id bigint NOT NULL,received_at timestamptz NOT NULL,
  content_revision bigint NOT NULL DEFAULT 1 CHECK(content_revision>0),
  lease_epoch bigint NOT NULL DEFAULT 0 CHECK(lease_epoch>=0),
  lease_holder_user_id bigint REFERENCES public.users(id) ON DELETE SET NULL,
  lease_expires_at timestamptz,
  final_sender_address text NOT NULL CHECK(octet_length(final_sender_address) BETWEEN 3 AND 254),
  generation bigint NOT NULL DEFAULT 1 CHECK(generation>0),
  state text NOT NULL DEFAULT 'active' CHECK(state IN ('active','submitted','abandoned')),
  last_operation_id uuid,updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  UNIQUE(mailbox_id,message_id,received_at),
  CONSTRAINT mail_draft_lease_shape CHECK((lease_holder_user_id IS NULL)=(lease_expires_at IS NULL))
);
CREATE TABLE public.mail_draft_revisions (
  draft_session_id uuid NOT NULL REFERENCES public.mail_draft_collaboration(draft_session_id) ON DELETE CASCADE,
  revision bigint NOT NULL CHECK(revision>0),
  message_id bigint NOT NULL,received_at timestamptz NOT NULL,
  editor_user_id bigint REFERENCES public.users(id) ON DELETE SET NULL,
  content_digest text NOT NULL CHECK(content_digest~'^[0-9a-f]{64}$'),
  attachment_digest text NOT NULL CHECK(attachment_digest~'^[0-9a-f]{64}$'),
  accepted_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  PRIMARY KEY(draft_session_id,revision)
);

-- Read policies call one worker-owned, pinned helper and never recurse into a
-- FORCE-RLS table. Writes remain reducer-only.
CREATE FUNCTION public.mail_work_can_read(p_mailbox_id bigint,p_user_id bigint) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT EXISTS(SELECT 1 FROM mailboxes m WHERE m.id=p_mailbox_id AND m.user_id=p_user_id)
    OR EXISTS(SELECT 1 FROM mailbox_delegates d WHERE d.mailbox_id=p_mailbox_id AND d.user_id=p_user_id
      AND d.permission IN ('read','send_as','send_on_behalf','full_access'))
$$;
ALTER FUNCTION public.mail_work_can_read(bigint,bigint) OWNER TO setjoin_worker;

DO $$ DECLARE t text; BEGIN FOREACH t IN ARRAY ARRAY[
 'sender_control_state','sender_control_operations','sender_feedback_outbox','sender_list_operations','mail_work_changes',
 'mail_thread_work','mail_thread_work_events','mail_work_operations','mail_thread_comments',
 'mail_thread_comment_mentions','mail_work_outbox','mail_work_notification_preferences',
 'mail_work_digest_ledger','mail_work_notification_deliveries','mail_work_notification_rate_windows','mail_work_consumer_effects',
 'mail_work_metric_daily','mail_work_metric_conversations','mail_work_metric_actors',
 'mail_draft_collaboration','mail_draft_revisions'
] LOOP EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',t);
       EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',t); END LOOP; END $$;

DO $$ DECLARE t text; BEGIN FOREACH t IN ARRAY ARRAY[
 'mail_work_changes','mail_thread_work','mail_thread_work_events','mail_work_operations',
 'mail_thread_comments','mail_work_notification_preferences','mail_work_metric_daily','mail_draft_collaboration'
] LOOP EXECUTE format('CREATE POLICY %I_read ON public.%I FOR SELECT USING (mail_work_can_read(mailbox_id,NULLIF(current_setting(''app.current_user_id'',true),'''')::bigint))',t,t); END LOOP; END $$;
CREATE POLICY mail_draft_revisions_read ON public.mail_draft_revisions FOR SELECT USING(
 EXISTS(SELECT 1 FROM mail_draft_collaboration d
         WHERE d.draft_session_id=mail_draft_revisions.draft_session_id
           AND mail_work_can_read(d.mailbox_id,NULLIF(current_setting('app.current_user_id',true),'')::bigint)));
CREATE POLICY mail_thread_comment_mentions_read ON public.mail_thread_comment_mentions FOR SELECT USING(
 EXISTS(SELECT 1 FROM mail_thread_comments c WHERE c.id=comment_id AND mail_work_can_read(c.mailbox_id,NULLIF(current_setting('app.current_user_id',true),'')::bigint)));
CREATE POLICY mail_work_outbox_owner ON public.mail_work_outbox USING(current_user='setjoin_worker') WITH CHECK(current_user='setjoin_worker');
CREATE POLICY mail_work_notification_deliveries_owner ON public.mail_work_notification_deliveries USING(current_user='setjoin_worker') WITH CHECK(current_user='setjoin_worker');
CREATE POLICY mail_work_notification_rate_windows_owner ON public.mail_work_notification_rate_windows USING(current_user='setjoin_worker') WITH CHECK(current_user='setjoin_worker');
CREATE POLICY mail_work_consumer_effects_owner ON public.mail_work_consumer_effects USING(current_user='setjoin_worker') WITH CHECK(current_user='setjoin_worker');
CREATE POLICY mail_work_metric_conversations_owner ON public.mail_work_metric_conversations USING(current_user='setjoin_worker') WITH CHECK(current_user='setjoin_worker');
CREATE POLICY mail_work_metric_actors_owner ON public.mail_work_metric_actors USING(current_user='setjoin_worker') WITH CHECK(current_user='setjoin_worker');
CREATE POLICY sender_control_state_self ON public.sender_control_state FOR SELECT USING(user_id=NULLIF(current_setting('app.current_user_id',true),'')::bigint);
CREATE POLICY sender_control_operations_self ON public.sender_control_operations FOR SELECT USING(user_id=NULLIF(current_setting('app.current_user_id',true),'')::bigint);
CREATE POLICY sender_feedback_outbox_owner ON public.sender_feedback_outbox USING(current_user='setjoin_worker') WITH CHECK(current_user='setjoin_worker');
CREATE POLICY sender_list_operations_self ON public.sender_list_operations FOR SELECT USING(user_id=NULLIF(current_setting('app.current_user_id',true),'')::bigint);
CREATE POLICY mail_work_digest_ledger_self ON public.mail_work_digest_ledger FOR SELECT USING(user_id=NULLIF(current_setting('app.current_user_id',true),'')::bigint);

INSERT INTO public.mailbox_retention_domains(domain_key,blocker_function,contract_version,owner_component)
VALUES('mail_work','mail_work_retention_blockers',1,'webmail_productivity') ON CONFLICT(domain_key) DO NOTHING;

INSERT INTO public.schema_migrations (version, applied_at)
VALUES (201, statement_timestamp()) ON CONFLICT (version) DO NOTHING;
