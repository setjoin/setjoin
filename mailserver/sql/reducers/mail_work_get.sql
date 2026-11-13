CREATE OR REPLACE FUNCTION mail_work_get(
  p_mailbox_id bigint,
  p_actor_user_id bigint,
  p_thread_ids text[] DEFAULT NULL
) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_state bigint; v_list jsonb;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.shared_mail_work'),false) THEN
    RAISE EXCEPTION 'shared mail work is disabled' USING ERRCODE='BZ300';
  END IF;
  SELECT jmap_mailwork_state INTO v_state FROM mailboxes
   WHERE id=p_mailbox_id AND user_id IS NULL AND mail_work_can_read(id,p_actor_user_id);
  IF v_state IS NULL THEN RAISE EXCEPTION 'shared mailbox not found' USING ERRCODE='BZ006'; END IF;
  IF p_thread_ids IS NOT NULL AND cardinality(p_thread_ids)>256 THEN
    RAISE EXCEPTION 'too many mail-work ids' USING ERRCODE='BZ301';
  END IF;

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
    'id',w.thread_id,'threadId',w.thread_id,'status',w.status,
    'assigneeUserId',CASE WHEN w.assignee_user_id IS NULL THEN NULL ELSE w.assignee_user_id::text END,
    'dueAt',w.due_at,'slaMinutes',w.sla_minutes,
    'generation',w.generation::text,'firstActivityAt',w.first_activity_at,
    'firstResponseAt',w.first_response_at,'lastActivityAt',w.last_activity_at,
    'completedAt',w.completed_at,'slaBreachedAt',w.sla_breached_at,'lastEventId',w.last_event_id
  ) ORDER BY w.last_activity_at DESC,w.thread_id),'[]'::jsonb)
  INTO v_list FROM mail_thread_work w
   WHERE w.mailbox_id=p_mailbox_id
     AND (p_thread_ids IS NULL OR w.thread_id=ANY(p_thread_ids));

  RETURN jsonb_build_object(
    'accountId',p_mailbox_id::text,'state',v_state::text,'list',v_list,
    'notFound',CASE WHEN p_thread_ids IS NULL THEN '[]'::jsonb ELSE
      COALESCE((SELECT jsonb_agg(x) FROM unnest(p_thread_ids) x
        WHERE NOT EXISTS(SELECT 1 FROM mail_thread_work w
          WHERE w.mailbox_id=p_mailbox_id AND w.thread_id=x)),'[]'::jsonb) END
  );
END $$;

ALTER FUNCTION mail_work_get(bigint,bigint,text[]) OWNER TO setjoin_worker;
