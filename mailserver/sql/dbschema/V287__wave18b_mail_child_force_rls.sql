-- V287__wave18b_mail_child_force_rls.sql — Wave 1.8 Phase 546c: Wave B FORCE RLS
-- across 17 mail/mailbox child tables:
--   tags, tasks, task_activity, quick_steps, mailbox_audit_log,
--   message_attachments, message_recalls, read_receipts, vote_responses,
--   quarantined_messages, user_sender_list, user_spam_model, aliases,
--   folders, scheduled_actions, rules, migration_jobs.
--
-- Security model (DATABASE_SECURITY.md R4 + ARCH-018):
--   1. All 17 tables receive ENABLE + FORCE ROW LEVEL SECURITY and least-privilege
--      `TO setjoin_app` policies. Missing/empty GUCs fail closed (NULLIF(..., '')
--      evaluates to NULL -> FALSE).
--   2. Reclassification: `message_recalls.message_id` is RFC-5322 text (not
--      `messages.id`), so `message_recalls` is `user_scoped` on `recalled_by`
--      (NULL fails closed).
--   3. `tasks` & `task_activity` honor `V112` shared `task_lists`/`task_list_members`
--      membership and `assignee_user_id` via pure-boolean `ARCH-018` SECURITY
--      DEFINER helpers owned by `setjoin_worker` (reading `app.current_user_id`
--      / `app.current_mailbox_id` internally; never accepting arbitrary user_id
--      or returning foreign IDs).
--   4. Nullable scope columns (`rules.mailbox_id` transport rules,
--      `scheduled_actions.mailbox_id` org/compliance jobs,
--      `message_recalls.recalled_by`) fail closed on NULL under `setjoin_app`;
--      org/admin paths run via `AdminReadTx`/`AdminWriteTx` (`setjoin_worker`),
--      and `chat_schedule_*` reducers use GUC-bound SECURITY DEFINER.
--   5. Locking & PG 15+ non-superuser DDL safety:
--      - `SET LOCAL lock_timeout = '5s'` inside a single transaction.
--      - Tables locked in canonical order (`collections -> items -> leaves`).
--      - Transient `GRANT CREATE ON SCHEMA public TO setjoin_worker` around
--        `apply_worker_ownership(...)` when absent, revoked before commit.

BEGIN;

SET LOCAL lock_timeout = '5s';

-- Canonical lock order: collections -> items -> leaves.
LOCK TABLE
  public.tags,
  public.folders,
  public.aliases,
  public.tasks,
  public.task_activity,
  public.quick_steps,
  public.rules,
  public.scheduled_actions,
  public.migration_jobs,
  public.message_attachments,
  public.read_receipts,
  public.vote_responses,
  public.quarantined_messages,
  public.message_recalls,
  public.mailbox_audit_log,
  public.user_sender_list,
  public.user_spam_model
IN ACCESS EXCLUSIVE MODE;

-- ── ARCH-018 SECURITY DEFINER RLS helpers (worker-owned, search_path pinned) ──
-- All helpers return pure BOOLEAN predicates (never raw foreign IDs or
-- permission strings) and read app.current_user_id / app.current_mailbox_id
-- internally.

-- Pure boolean shared task-list membership predicate (`V112`).
CREATE OR REPLACE FUNCTION public.rls_task_list_member(p_list_id bigint)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT p_list_id IS NOT NULL
    AND NULLIF(current_setting('app.current_user_id', true), '') IS NOT NULL
    AND (
      EXISTS (
        SELECT 1
          FROM public.task_lists l
         WHERE l.id = p_list_id
           AND l.owner_user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint
      )
      OR EXISTS (
        SELECT 1
          FROM public.task_list_members m
         WHERE m.list_id = p_list_id
           AND m.user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint
      )
    );
$$;

-- Pure boolean parent-task scope predicate for `task_activity` (breaks
-- tasks <-> task_activity nesting and honors V112 shared lists + personal assignee).
CREATE OR REPLACE FUNCTION public.rls_task_in_scope(p_task_id bigint)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT EXISTS (
    SELECT 1
      FROM public.tasks t
     WHERE t.id = p_task_id
       AND (
         public.rls_mailbox_in_scope(t.mailbox_id)
         OR (t.list_id IS NOT NULL AND public.rls_task_list_member(t.list_id))
         OR (
           t.list_id IS NULL
           AND t.assignee_user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint
         )
       )
  );
$$;

-- Pure boolean parent-message scope predicate for `message_attachments`,
-- `read_receipts`, and `vote_responses` (partition-pruned on (id, received_at)).
CREATE OR REPLACE FUNCTION public.rls_message_in_scope(
  p_message_id  bigint,
  p_received_at timestamptz
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT EXISTS (
    SELECT 1
      FROM public.messages m
     WHERE m.id = p_message_id
       AND m.received_at = p_received_at
       AND public.rls_mailbox_in_scope(m.mailbox_id)
  );
$$;

-- Pure boolean mailbox delegate predicate for `aliases` SELECT on delegated
-- send_as / full_access mailboxes during JMAP session discovery.
CREATE OR REPLACE FUNCTION public.rls_mailbox_delegate_for_current_user(
  p_mailbox_id  bigint,
  p_permissions text[]
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT EXISTS (
    SELECT 1
      FROM public.mailbox_delegates md
     WHERE md.mailbox_id = p_mailbox_id
       AND md.user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint
       AND md.permission = ANY(p_permissions)
  );
$$;

REVOKE ALL ON FUNCTION public.rls_task_list_member(bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rls_task_in_scope(bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rls_message_in_scope(bigint, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rls_mailbox_delegate_for_current_user(bigint, text[]) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION public.rls_task_list_member(bigint) TO setjoin_app, setjoin_worker;
GRANT EXECUTE ON FUNCTION public.rls_task_in_scope(bigint) TO setjoin_app, setjoin_worker;
GRANT EXECUTE ON FUNCTION public.rls_message_in_scope(bigint, timestamptz) TO setjoin_app, setjoin_worker;
GRANT EXECUTE ON FUNCTION public.rls_mailbox_delegate_for_current_user(bigint, text[]) TO setjoin_app, setjoin_worker;

-- PG 15+ owner-safe worker ownership transfer (transient CREATE on public only
-- when absent, always revoked before leaving the DO block).
DO $$
DECLARE
  v_granted_create boolean := false;
  v_fn regprocedure;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
    IF NOT has_schema_privilege('setjoin_worker', 'public', 'CREATE') THEN
      EXECUTE 'GRANT CREATE ON SCHEMA public TO setjoin_worker';
      v_granted_create := true;
    END IF;
  END IF;

  BEGIN
    FOREACH v_fn IN ARRAY ARRAY[
      'public.rls_task_list_member(bigint)'::regprocedure,
      'public.rls_task_in_scope(bigint)'::regprocedure,
      'public.rls_message_in_scope(bigint,timestamp with time zone)'::regprocedure,
      'public.rls_mailbox_delegate_for_current_user(bigint,text[])'::regprocedure
    ] LOOP
      PERFORM public.apply_worker_ownership(v_fn);
    END LOOP;
  EXCEPTION WHEN OTHERS THEN
    IF v_granted_create THEN
      EXECUTE 'REVOKE CREATE ON SCHEMA public FROM setjoin_worker';
    END IF;
    RAISE;
  END;

  IF v_granted_create THEN
    EXECUTE 'REVOKE CREATE ON SCHEMA public FROM setjoin_worker';
  END IF;
END $$;

-- ── Enable + Force RLS and least-privilege setjoin_app policies (17 tables) ──

-- 1. tags
ALTER TABLE public.tags ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.tags FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tags_app_all ON public.tags;
CREATE POLICY tags_app_all ON public.tags
  FOR ALL TO setjoin_app
  USING (public.rls_mailbox_in_scope(mailbox_id))
  WITH CHECK (public.rls_mailbox_in_scope(mailbox_id));

-- 2. folders
ALTER TABLE public.folders ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.folders FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS folders_app_all ON public.folders;
CREATE POLICY folders_app_all ON public.folders
  FOR ALL TO setjoin_app
  USING (public.rls_mailbox_in_scope(mailbox_id))
  WITH CHECK (public.rls_mailbox_in_scope(mailbox_id));

-- 3. aliases (owner scope + read-only send_as/full_access delegate discovery)
ALTER TABLE public.aliases ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.aliases FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aliases_app_select ON public.aliases;
CREATE POLICY aliases_app_select ON public.aliases
  FOR SELECT TO setjoin_app
  USING (
    public.rls_mailbox_in_scope(mailbox_id)
    OR public.rls_mailbox_delegate_for_current_user(
         mailbox_id, ARRAY['send_as', 'full_access']
       )
  );
DROP POLICY IF EXISTS aliases_app_insert ON public.aliases;
CREATE POLICY aliases_app_insert ON public.aliases
  FOR INSERT TO setjoin_app
  WITH CHECK (public.rls_mailbox_in_scope(mailbox_id));
DROP POLICY IF EXISTS aliases_app_update ON public.aliases;
CREATE POLICY aliases_app_update ON public.aliases
  FOR UPDATE TO setjoin_app
  USING (public.rls_mailbox_in_scope(mailbox_id))
  WITH CHECK (public.rls_mailbox_in_scope(mailbox_id));
DROP POLICY IF EXISTS aliases_app_delete ON public.aliases;
CREATE POLICY aliases_app_delete ON public.aliases
  FOR DELETE TO setjoin_app
  USING (public.rls_mailbox_in_scope(mailbox_id));

-- 4. tasks (owner scope + V112 shared list members + personal assignee read/status)
ALTER TABLE public.tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.tasks FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tasks_app_select ON public.tasks;
CREATE POLICY tasks_app_select ON public.tasks
  FOR SELECT TO setjoin_app
  USING (
    public.rls_mailbox_in_scope(mailbox_id)
    OR (list_id IS NOT NULL AND public.rls_task_list_member(list_id))
    OR (
      list_id IS NULL
      AND assignee_user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint
    )
  );
DROP POLICY IF EXISTS tasks_app_insert ON public.tasks;
CREATE POLICY tasks_app_insert ON public.tasks
  FOR INSERT TO setjoin_app
  WITH CHECK (
    public.rls_mailbox_in_scope(mailbox_id)
    OR (list_id IS NOT NULL AND public.rls_task_list_member(list_id))
  );
DROP POLICY IF EXISTS tasks_app_update ON public.tasks;
CREATE POLICY tasks_app_update ON public.tasks
  FOR UPDATE TO setjoin_app
  USING (
    public.rls_mailbox_in_scope(mailbox_id)
    OR (list_id IS NOT NULL AND public.rls_task_list_member(list_id))
  )
  WITH CHECK (
    public.rls_mailbox_in_scope(mailbox_id)
    OR (list_id IS NOT NULL AND public.rls_task_list_member(list_id))
  );
DROP POLICY IF EXISTS tasks_app_delete ON public.tasks;
CREATE POLICY tasks_app_delete ON public.tasks
  FOR DELETE TO setjoin_app
  USING (
    public.rls_mailbox_in_scope(mailbox_id)
    OR (list_id IS NOT NULL AND public.rls_task_list_member(list_id))
  );

-- 5. task_activity (honors V112 shared list members & personal assignees)
ALTER TABLE public.task_activity ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.task_activity FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS task_activity_app_select ON public.task_activity;
CREATE POLICY task_activity_app_select ON public.task_activity
  FOR SELECT TO setjoin_app
  USING (
    public.rls_mailbox_in_scope(mailbox_id)
    OR public.rls_task_in_scope(task_id)
  );
DROP POLICY IF EXISTS task_activity_app_insert ON public.task_activity;
CREATE POLICY task_activity_app_insert ON public.task_activity
  FOR INSERT TO setjoin_app
  WITH CHECK (
    public.rls_task_in_scope(task_id)
    AND (
      (
        public.rls_mailbox_in_scope(mailbox_id)
        AND (
          author_user_id IS NULL
          OR author_user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint
        )
      )
      OR author_user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint
    )
  );
DROP POLICY IF EXISTS task_activity_app_update ON public.task_activity;
CREATE POLICY task_activity_app_update ON public.task_activity
  FOR UPDATE TO setjoin_app
  USING (
    public.rls_mailbox_in_scope(mailbox_id)
    OR (
      public.rls_task_in_scope(task_id)
      AND author_user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint
    )
  )
  WITH CHECK (
    public.rls_mailbox_in_scope(mailbox_id)
    OR (
      public.rls_task_in_scope(task_id)
      AND author_user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint
    )
  );
DROP POLICY IF EXISTS task_activity_app_delete ON public.task_activity;
CREATE POLICY task_activity_app_delete ON public.task_activity
  FOR DELETE TO setjoin_app
  USING (
    public.rls_mailbox_in_scope(mailbox_id)
    OR (
      public.rls_task_in_scope(task_id)
      AND author_user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint
    )
  );

-- 6. quick_steps
ALTER TABLE public.quick_steps ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.quick_steps FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS quick_steps_app_all ON public.quick_steps;
CREATE POLICY quick_steps_app_all ON public.quick_steps
  FOR ALL TO setjoin_app
  USING (mailbox_id = NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint)
  WITH CHECK (mailbox_id = NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint);

-- 7. rules (nullable mailbox_id for org transport rules -> fail closed on NULL)
ALTER TABLE public.rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.rules FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rules_app_all ON public.rules;
CREATE POLICY rules_app_all ON public.rules
  FOR ALL TO setjoin_app
  USING (mailbox_id IS NOT NULL AND public.rls_mailbox_in_scope(mailbox_id))
  WITH CHECK (mailbox_id IS NOT NULL AND public.rls_mailbox_in_scope(mailbox_id));

-- 8. scheduled_actions (nullable mailbox_id for org/compliance/chat jobs -> fail closed on NULL,
--    and restrict setjoin_app strictly to mailbox action kinds so chat_send/org kinds cannot be forged)
ALTER TABLE public.scheduled_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scheduled_actions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS scheduled_actions_app_all ON public.scheduled_actions;
CREATE POLICY scheduled_actions_app_all ON public.scheduled_actions
  FOR ALL TO setjoin_app
  USING (
    mailbox_id IS NOT NULL
    AND public.rls_mailbox_in_scope(mailbox_id)
    AND action_kind IN ('send', 'snooze', 'remind', 'dsn', 'rules_retro')
  )
  WITH CHECK (
    mailbox_id IS NOT NULL
    AND public.rls_mailbox_in_scope(mailbox_id)
    AND action_kind IN ('send', 'snooze', 'remind', 'dsn', 'rules_retro')
  );

-- 9. migration_jobs
ALTER TABLE public.migration_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.migration_jobs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS migration_jobs_app_all ON public.migration_jobs;
CREATE POLICY migration_jobs_app_all ON public.migration_jobs
  FOR ALL TO setjoin_app
  USING (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint)
  WITH CHECK (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint);

-- 10. message_attachments (parent messages.mailbox_id)
ALTER TABLE public.message_attachments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.message_attachments FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS message_attachments_app_all ON public.message_attachments;
CREATE POLICY message_attachments_app_all ON public.message_attachments
  FOR ALL TO setjoin_app
  USING (public.rls_message_in_scope(message_id, received_at))
  WITH CHECK (public.rls_message_in_scope(message_id, received_at));

-- 11. read_receipts (parent messages.mailbox_id)
ALTER TABLE public.read_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.read_receipts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS read_receipts_app_all ON public.read_receipts;
CREATE POLICY read_receipts_app_all ON public.read_receipts
  FOR ALL TO setjoin_app
  USING (public.rls_message_in_scope(message_id, received_at))
  WITH CHECK (public.rls_message_in_scope(message_id, received_at));

-- 12. vote_responses (parent messages.mailbox_id)
ALTER TABLE public.vote_responses ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.vote_responses FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS vote_responses_app_all ON public.vote_responses;
CREATE POLICY vote_responses_app_all ON public.vote_responses
  FOR ALL TO setjoin_app
  USING (public.rls_message_in_scope(message_id, received_at))
  WITH CHECK (public.rls_message_in_scope(message_id, received_at));

-- 13. quarantined_messages
ALTER TABLE public.quarantined_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.quarantined_messages FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS quarantined_messages_app_all ON public.quarantined_messages;
CREATE POLICY quarantined_messages_app_all ON public.quarantined_messages
  FOR ALL TO setjoin_app
  USING (public.rls_mailbox_in_scope(mailbox_id))
  WITH CHECK (public.rls_mailbox_in_scope(mailbox_id));

-- 14. message_recalls (reclassified to user_scoped on recalled_by; NULL fails closed)
ALTER TABLE public.message_recalls ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.message_recalls FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS message_recalls_app_all ON public.message_recalls;
CREATE POLICY message_recalls_app_all ON public.message_recalls
  FOR ALL TO setjoin_app
  USING (
    recalled_by IS NOT NULL
    AND recalled_by = NULLIF(current_setting('app.current_user_id', true), '')::bigint
  )
  WITH CHECK (
    recalled_by IS NOT NULL
    AND recalled_by = NULLIF(current_setting('app.current_user_id', true), '')::bigint
  );

-- 15. mailbox_audit_log (partitioned parent FORCE RLS + revoke direct-leaf app access)
ALTER TABLE public.mailbox_audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.mailbox_audit_log FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS mailbox_audit_log_app_all ON public.mailbox_audit_log;
CREATE POLICY mailbox_audit_log_app_all ON public.mailbox_audit_log
  FOR ALL TO setjoin_app
  USING (mailbox_id = NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint)
  WITH CHECK (mailbox_id = NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint);

-- Block direct-leaf reads/writes to child partitions under setjoin_app;
-- via-parent queries against public.mailbox_audit_log remain governed by the
-- parent FORCE RLS policy above.
DO $$
DECLARE
  v_part regclass;
BEGIN
  FOR v_part IN
    SELECT inhrelid::regclass
      FROM pg_inherits
     WHERE inhparent = 'public.mailbox_audit_log'::regclass
  LOOP
    EXECUTE format('REVOKE ALL ON TABLE %s FROM setjoin_app', v_part);
  END LOOP;
END $$;

-- 16. user_sender_list
ALTER TABLE public.user_sender_list ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_sender_list FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS user_sender_list_app_all ON public.user_sender_list;
CREATE POLICY user_sender_list_app_all ON public.user_sender_list
  FOR ALL TO setjoin_app
  USING (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint)
  WITH CHECK (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint);

-- 17. user_spam_model
ALTER TABLE public.user_spam_model ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_spam_model FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS user_spam_model_app_all ON public.user_spam_model;
CREATE POLICY user_spam_model_app_all ON public.user_spam_model
  FOR ALL TO setjoin_app
  USING (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint)
  WITH CHECK (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint);

-- ── Embedded hardened & new Phase 546c reducers (upgrade parity) ────────────
-- upgrade.sh / mailctl schema apply runs V*.sql migrations directly without
-- reload-reducers.sh, so every reducer modified or added for V287 is embedded
-- here byte-for-byte with its canonical mailserver/sql/reducers/*.sql file.

CREATE OR REPLACE FUNCTION chat_schedule_message(
    p_user_id bigint, p_channel_id bigint, p_body text,
    p_parent_id bigint DEFAULT NULL, p_mentions bigint[] DEFAULT '{}',
    p_broadcast text DEFAULT NULL, p_fire_at timestamptz DEFAULT NULL
) RETURNS uuid AS $$
DECLARE
    v_payload jsonb;
    v_id      uuid;
BEGIN
    IF NOT public.rls_caller_is_privileged() THEN
        IF p_user_id IS NULL
           OR p_user_id IS DISTINCT FROM NULLIF(current_setting('app.current_user_id', true), '')::bigint THEN
            RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
        END IF;
    END IF;
    -- membership checked at ENQUEUE time (BZ163); the handler re-checks at
    -- FIRE time via chat_message_send itself (TOCTOU — a member kicked
    -- between now and fire_at must not silently post).
    PERFORM public.chat_require_role(p_channel_id, p_user_id);
    IF coalesce(btrim(p_body), '') = '' OR octet_length(p_body) > 65536 THEN
        RAISE EXCEPTION 'message body empty or over 64KiB'
            USING ERRCODE='BZ168', HINT='{"type":"invalidArguments"}';
    END IF;
    IF p_fire_at IS NULL OR p_fire_at <= now() THEN
        RAISE EXCEPTION 'fireAt must be a future timestamp'
            USING ERRCODE='BZ179', HINT='{"type":"invalidArguments","detail":"fireAt must be in the future"}';
    END IF;
    -- payload built server-side from p_user_id/p_channel_id/etc — never from
    -- a raw request-body pass-through (R2). mentions defaults to '{}' so a
    -- NULL array never round-trips as JSON null.
    v_payload := jsonb_build_object(
      'userId', p_user_id, 'channelId', p_channel_id, 'body', p_body,
      'parentId', p_parent_id, 'mentions', to_jsonb(COALESCE(p_mentions, '{}'::bigint[])),
      'broadcast', p_broadcast
    );
    v_id := public.enqueue_scheduled_action('chat_send', p_fire_at, v_payload, NULL);
    RETURN v_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

CREATE OR REPLACE FUNCTION chat_scheduled_list(p_user_id bigint) RETURNS jsonb AS $$
BEGIN
    IF NOT public.rls_caller_is_privileged() THEN
        IF p_user_id IS NULL
           OR p_user_id IS DISTINCT FROM NULLIF(current_setting('app.current_user_id', true), '')::bigint THEN
            RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
        END IF;
    END IF;
    RETURN COALESCE((
        SELECT jsonb_agg(jsonb_build_object(
                 'actionId', id, 'channelId', (payload->>'channelId')::bigint,
                 'body', payload->>'body', 'fireAt', fire_at, 'status', status,
                 'failureCode', payload->>'failureCode', 'lastError', last_error
               ) ORDER BY fire_at ASC)
          FROM public.scheduled_actions
         WHERE action_kind = 'chat_send'
           AND status IN ('pending', 'failed')
           AND payload->>'userId' = p_user_id::text
    ), '[]'::jsonb);
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public;

CREATE OR REPLACE FUNCTION chat_scheduled_cancel(
    p_user_id bigint, p_action_id uuid
) RETURNS void AS $$
DECLARE
    v_count int;
BEGIN
    IF NOT public.rls_caller_is_privileged() THEN
        IF p_user_id IS NULL
           OR p_user_id IS DISTINCT FROM NULLIF(current_setting('app.current_user_id', true), '')::bigint THEN
            RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
        END IF;
    END IF;
    WITH del AS (
        DELETE FROM public.scheduled_actions
         WHERE id = p_action_id
           AND action_kind = 'chat_send'
           AND status IN ('pending', 'failed')
           AND payload->>'userId' = p_user_id::text
        RETURNING 1
    )
    SELECT count(*) INTO v_count FROM del;
    IF v_count = 0 THEN
        RAISE EXCEPTION 'scheduled action not found or not cancellable'
            USING ERRCODE='BZ179', HINT='{"type":"invalidArguments","detail":"not pending/failed, not yours, or does not exist"}';
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

CREATE OR REPLACE FUNCTION directory_visible_users(
  p_mailbox_id BIGINT
) RETURNS TABLE(
  id            BIGINT,
  email         TEXT,
  display_name  TEXT,
  first_name    TEXT,
  last_name     TEXT,
  phone         TEXT,
  job_title     TEXT,
  department_id BIGINT,
  dept_name     TEXT,
  avatar_sha256 TEXT,
  is_manager    BOOLEAN,
  addresses     JSONB,
  address_blob  TEXT
) AS $$
BEGIN
  RETURN QUERY
  SELECT
    u.id, u.email, u.display_name, u.first_name, u.last_name,
    u.phone, u.job_title, u.department_id, d.name AS dept_name, u.avatar_sha256,
    EXISTS(SELECT 1 FROM users mu WHERE mu.manager_id = u.id AND mu.enabled = TRUE) AS is_manager,
    directory_address_set(u.id, u.email, u.ad_upn) AS addresses,
    (
      -- flat, lower-cased address set for case-insensitive substring matching
      SELECT string_agg(elem->>'email', ' ')
      FROM jsonb_array_elements(directory_address_set(u.id, u.email, u.ad_upn)) elem
    ) AS address_blob
  FROM users u
  LEFT JOIN departments d ON d.id = u.department_id
  WHERE u.enabled = TRUE
    -- Guest P7: guests are external collaborators, never org-directory
    -- principals. Exclude on discriminator presence, not lifecycle status, so
    -- invited/active/disabled/expired guests all remain invisible. This shared
    -- seam also feeds GAL search + CardDAV and keeps every end-user directory
    -- surface aligned. Use the RLS-safe SECURITY DEFINER helper: a raw
    -- guest_accounts NOT EXISTS would see zero rows under setjoin_app's
    -- self-read-only FORCE-RLS policy and fail open.
    AND NOT is_guest_account(u.id)
    -- hidden_from_gal (bug fix): a person's primary mailbox can opt out of the
    -- GAL/directory entirely — the column has existed since V001 but this seam
    -- never checked it (dead flag; retired-docs:superpowers/plans/archive/2026-07-08-gal-carddav-collection.md
    -- T1). Every seam consumer (directory_members/search/tree, gal_search, and
    -- the LDAP People search/base/Compare adapter) inherits the same rule.
    AND NOT EXISTS (SELECT 1 FROM mailboxes pm
                    WHERE pm.user_id = u.id AND pm.is_primary AND pm.hidden_from_gal)
    -- org-wide: NO domain filter (ADR-004). Caller-existence keeps an unknown
    -- mailbox from listing the org (fail-safe), without re-introducing scope.
    AND EXISTS (SELECT 1 FROM public.mailboxes cm WHERE cm.id = p_mailbox_id)
    AND (public.rls_caller_is_privileged() OR public.rls_mailbox_in_scope(p_mailbox_id));
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public;

CREATE OR REPLACE FUNCTION task_assignee_set_status(
  p_user_id BIGINT,
  p_task_id BIGINT,
  p_status  TEXT
) RETURNS JSONB AS $$
DECLARE
  v_row public.tasks%ROWTYPE;
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    IF p_user_id IS NULL
       OR p_user_id IS DISTINCT FROM NULLIF(current_setting('app.current_user_id', true), '')::bigint THEN
      RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
    END IF;
  END IF;

  IF p_status IS NULL OR p_status NOT IN ('needs-action', 'in-progress', 'completed', 'cancelled') THEN
    RAISE EXCEPTION 'invalid task status %', p_status
      USING ERRCODE = 'BZ133', HINT = '{"type":"invalidArguments","detail":"invalid status"}';
  END IF;

  UPDATE public.tasks SET
    status = p_status,
    completed_at = CASE
      WHEN p_status = 'completed' AND status != 'completed' THEN now()
      WHEN p_status != 'completed' AND status = 'completed' THEN NULL
      ELSE completed_at
    END,
    updated_at = now(),
    jmap_state = jmap_state + 1
  WHERE id = p_task_id
    AND assignee_user_id = p_user_id
    AND (list_id IS NULL OR public.task_list_role(list_id, p_user_id) IS NOT NULL)
  RETURNING * INTO v_row;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'task not found or not assigned to caller'
      USING ERRCODE = 'BZ132', HINT = '{"type":"notFound"}';
  END IF;

  INSERT INTO public.task_activity (task_id, mailbox_id, author_user_id, kind, meta)
  VALUES (p_task_id, v_row.mailbox_id, p_user_id, 'status_change',
          jsonb_build_object('old', NULL, 'new', v_row.status));

  -- The OWNER's personal view syncs via the task secondary seam (their own
  -- mailbox channel); a list task ALSO gets the list seam so every member's
  -- board re-fetches.
  PERFORM public.notify_task_state(v_row.mailbox_id, 'task_updated', p_task_id);
  IF v_row.list_id IS NOT NULL THEN
    PERFORM public.notify_task_list_state(v_row.list_id, 'task_updated', p_task_id);
  END IF;

  RETURN jsonb_build_object('id', v_row.id::TEXT, 'status', v_row.status);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

CREATE OR REPLACE FUNCTION create_monthly_partitions(p_months_ahead INT DEFAULT 1) RETURNS void AS $$
DECLARE
  v_tbl    TEXT;
  v_offset INT;
  v_start  DATE;
  v_end    DATE;
  v_name   TEXT;
BEGIN
  FOR v_tbl IN
    SELECT c.relname
    FROM pg_partitioned_table p
    JOIN pg_class     c ON c.oid = p.partrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_attribute a ON a.attrelid = p.partrelid AND a.attnum = p.partattrs[0]
    WHERE n.nspname = 'public'
      AND p.partstrat = 'r'                       -- RANGE only
      AND p.partnatts = 1                         -- single-column key (excludes expression keys: attnum 0 never joins)
      AND a.atttypid = 'timestamptz'::regtype     -- month-partitioned by time
    ORDER BY c.relname
  LOOP
    FOR v_offset IN 0..p_months_ahead LOOP
      v_start := date_trunc('month', now() + make_interval(months => v_offset))::DATE;
      v_end   := (v_start + INTERVAL '1 month')::DATE;
      v_name  := v_tbl || '_' || to_char(v_start, 'YYYY_MM');
      IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = v_name) THEN
        -- Per-table isolation: one table's failure must NOT abort the rest —
        -- the audit trio (no DEFAULT partition) is the safety-critical set.
        -- Known conflict: a table WITH a default partition already holding
        -- rows for the target month (e.g. future-dated scheduled/snoozed
        -- message_tags) raises 23514 on CREATE PARTITION — Postgres validates
        -- but does not move rows. Inserts still work via the default; only
        -- pruning granularity degrades. WARN and continue.
        BEGIN
          EXECUTE format('CREATE TABLE %I PARTITION OF %I FOR VALUES FROM (%L) TO (%L)',
            v_name, v_tbl, v_start, v_end);
          -- V287 defense-in-depth: revoke direct-leaf app grants on newly rolled
          -- mailbox_audit_log partitions (via-parent access stays governed by
          -- public.mailbox_audit_log's FORCE RLS policy).
          IF v_tbl = 'mailbox_audit_log' THEN
            EXECUTE format('REVOKE ALL ON TABLE public.%I FROM setjoin_app', v_name);
          END IF;
        EXCEPTION WHEN OTHERS THEN
          RAISE WARNING 'create_monthly_partitions: % skipped (%: %)', v_name, SQLSTATE, SQLERRM;
        END;
      END IF;
    END LOOP;
  END LOOP;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION rust_blob_register_metadata(
  p_sha256       TEXT,
  p_minio_ref    TEXT,
  p_size_bytes   BIGINT,
  p_content_type TEXT
) RETURNS VOID AS $$
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    IF NULLIF(current_setting('app.current_user_id', true), '') IS NULL
       AND NULLIF(current_setting('app.current_mailbox_id', true), '') IS NULL THEN
      RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
    END IF;
  END IF;

  IF p_sha256 IS NULL OR p_sha256 !~ '^[0-9a-f]{64}$'
     OR p_size_bytes IS NULL OR p_size_bytes < 0
     OR p_minio_ref IS NULL OR btrim(p_minio_ref) = ''
     OR p_content_type IS NULL OR btrim(p_content_type) = '' THEN
    RAISE EXCEPTION 'invalid blob metadata arguments' USING ERRCODE = '22023';
  END IF;

  INSERT INTO public.blobs (sha256, minio_ref, size_bytes, content_type, ref_count)
  VALUES (p_sha256, p_minio_ref, p_size_bytes, p_content_type, 0)
  ON CONFLICT (sha256) DO NOTHING;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

CREATE OR REPLACE FUNCTION rust_jmap_unsubscribe_record(
  p_user_id   BIGINT,
  p_target_id BIGINT,
  p_sender    TEXT
) RETURNS BIGINT AS $$
DECLARE
  v_count BIGINT;
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    IF p_user_id IS NULL
       OR p_user_id IS DISTINCT FROM NULLIF(current_setting('app.current_user_id', true), '')::bigint THEN
      RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
    END IF;
  END IF;

  PERFORM public.audit_write(
    p_user_id,
    'unsubscribe_newsletter',
    'message',
    p_target_id,
    NULL,
    NULL,
    NULL,
    'List-Unsubscribe POST',
    'routine'
  );
  v_count := 1;

  IF p_sender IS NOT NULL AND p_sender <> '' THEN
    INSERT INTO public.user_sender_list (user_id, sender, list_type)
    VALUES (p_user_id, p_sender, 'blocked')
    ON CONFLICT (user_id, sender, list_type) DO NOTHING;
  END IF;

  RETURN v_count;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

CREATE OR REPLACE FUNCTION rust_outbound_queue_enqueue(
  p_message_id TEXT,
  p_from_addr  TEXT,
  p_rcpt_addr  TEXT,
  p_raw_ref    TEXT
) RETURNS BIGINT AS $$
DECLARE
  v_id BIGINT;
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
  END IF;
  INSERT INTO public.outbound_queue (message_id, from_addr, rcpt_addrs, raw_ref, status)
  VALUES (p_message_id, p_from_addr, ARRAY[p_rcpt_addr], p_raw_ref, 'pending')
  RETURNING id INTO v_id;
  RETURN v_id;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

CREATE OR REPLACE FUNCTION rust_system_config_upsert_batch(
  p_keys        TEXT[],
  p_values      TEXT[],
  p_description TEXT
) RETURNS INT AS $$
DECLARE
  v_count INT;
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
  END IF;
  WITH w AS (
    INSERT INTO public.system_config (key, value, description)
    SELECT t.k, t.v::jsonb, p_description
      FROM unnest(p_keys, p_values) AS t(k, v)
    ON CONFLICT (key) DO UPDATE
      SET value = EXCLUDED.value,
          updated_at = now()
    RETURNING 1
  )
  SELECT count(*)::int INTO v_count FROM w;
  RETURN v_count;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

CREATE OR REPLACE FUNCTION rust_system_config_upsert(
  p_key       TEXT,
  p_value     TEXT,
  p_encrypted BOOLEAN
) RETURNS BIGINT AS $$
DECLARE
  v_count BIGINT;
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
  END IF;
  IF p_encrypted THEN
    WITH w AS (
      INSERT INTO public.system_config (key, value, encrypted)
      VALUES (p_key, p_value::jsonb, TRUE)
      ON CONFLICT (key) DO UPDATE
        SET value = EXCLUDED.value,
            encrypted = TRUE,
            updated_at = now()
      RETURNING 1
    )
    SELECT count(*)::bigint INTO v_count FROM w;
  ELSE
    WITH w AS (
      INSERT INTO public.system_config (key, value)
      VALUES (p_key, p_value::jsonb)
      ON CONFLICT (key) DO UPDATE
        SET value = EXCLUDED.value,
            updated_at = now()
      RETURNING 1
    )
    SELECT count(*)::bigint INTO v_count FROM w;
  END IF;
  RETURN v_count;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

CREATE OR REPLACE FUNCTION rust_system_config_delete(
  p_key TEXT
) RETURNS BIGINT AS $$
DECLARE
  v_count BIGINT;
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
  END IF;
  WITH d AS (
    DELETE FROM public.system_config
     WHERE key = p_key
    RETURNING 1
  )
  SELECT count(*)::bigint INTO v_count FROM d;
  RETURN v_count;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

CREATE OR REPLACE FUNCTION rust_user_external_sender_warning_set(
  p_user_id BIGINT,
  p_enabled BOOLEAN
) RETURNS BOOLEAN AS $$
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    IF p_user_id IS NULL
       OR p_user_id IS DISTINCT FROM NULLIF(current_setting('app.current_user_id', true), '')::bigint THEN
      RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
    END IF;
  END IF;
  UPDATE public.users
     SET external_sender_warning = p_enabled
   WHERE id = p_user_id;
  RETURN FOUND;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

-- Function ACLs + PG 15+ owner-safe worker ownership for embedded reducers
REVOKE ALL ON FUNCTION public.rust_outbound_queue_enqueue(text,text,text,text) FROM PUBLIC, setjoin_app;
GRANT EXECUTE ON FUNCTION public.rust_outbound_queue_enqueue(text,text,text,text) TO setjoin_worker;
REVOKE ALL ON FUNCTION public.rust_system_config_upsert_batch(text[],text[],text) FROM PUBLIC, setjoin_app;
GRANT EXECUTE ON FUNCTION public.rust_system_config_upsert_batch(text[],text[],text) TO setjoin_worker;
REVOKE ALL ON FUNCTION public.rust_system_config_upsert(text,text,boolean) FROM PUBLIC, setjoin_app;
GRANT EXECUTE ON FUNCTION public.rust_system_config_upsert(text,text,boolean) TO setjoin_worker;
REVOKE ALL ON FUNCTION public.rust_system_config_delete(text) FROM PUBLIC, setjoin_app;
GRANT EXECUTE ON FUNCTION public.rust_system_config_delete(text) TO setjoin_worker;
REVOKE ALL ON FUNCTION public.rust_blob_register_metadata(text,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.rust_blob_register_metadata(text,text,bigint,text) TO setjoin_app, setjoin_worker;
REVOKE ALL ON FUNCTION public.rust_jmap_unsubscribe_record(bigint,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.rust_jmap_unsubscribe_record(bigint,bigint,text) TO setjoin_app, setjoin_worker;
REVOKE ALL ON FUNCTION public.rust_user_external_sender_warning_set(bigint,boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.rust_user_external_sender_warning_set(bigint,boolean) TO setjoin_app, setjoin_worker;

DO $$
DECLARE
  v_granted_create boolean := false;
  v_fn regprocedure;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
    IF NOT has_schema_privilege('setjoin_worker', 'public', 'CREATE') THEN
      EXECUTE 'GRANT CREATE ON SCHEMA public TO setjoin_worker';
      v_granted_create := true;
    END IF;
  END IF;

  BEGIN
    FOREACH v_fn IN ARRAY ARRAY[
      'public.chat_schedule_message(bigint,bigint,text,bigint,bigint[],text,timestamp with time zone)'::regprocedure,
      'public.chat_scheduled_list(bigint)'::regprocedure,
      'public.chat_scheduled_cancel(bigint,uuid)'::regprocedure,
      'public.directory_visible_users(bigint)'::regprocedure,
      'public.task_assignee_set_status(bigint,bigint,text)'::regprocedure
    ] LOOP
      PERFORM public.apply_worker_ownership(v_fn);
    END LOOP;
  EXCEPTION WHEN OTHERS THEN
    IF v_granted_create THEN
      EXECUTE 'REVOKE CREATE ON SCHEMA public FROM setjoin_worker';
    END IF;
    RAISE;
  END;

  IF v_granted_create THEN
    EXECUTE 'REVOKE CREATE ON SCHEMA public FROM setjoin_worker';
  END IF;
END $$;

INSERT INTO public.schema_migrations (version, applied_at)
VALUES (287, now())
ON CONFLICT (version) DO NOTHING;

COMMIT;
