CREATE OR REPLACE FUNCTION mail_comment_get(
  p_mailbox_id bigint,
  p_actor_user_id bigint,
  p_thread_id text,
  p_before timestamptz DEFAULT NULL,
  p_limit integer DEFAULT 100
) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_state bigint; v_list jsonb;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.shared_mail_comments'),false) THEN
    RAISE EXCEPTION 'shared mail comments are disabled' USING ERRCODE='BZ300';
  END IF;
  IF p_thread_id IS NULL OR octet_length(p_thread_id) NOT BETWEEN 1 AND 256
     OR p_limit NOT BETWEEN 1 AND 100 THEN
    RAISE EXCEPTION 'invalid mail-comment query' USING ERRCODE='BZ301';
  END IF;
  SELECT jmap_mailwork_state INTO v_state FROM mailboxes
   WHERE id=p_mailbox_id AND user_id IS NULL AND mail_work_can_read(id,p_actor_user_id);
  IF v_state IS NULL THEN RAISE EXCEPTION 'shared mailbox not found' USING ERRCODE='BZ006'; END IF;

  SELECT COALESCE(jsonb_agg(item ORDER BY occurred_at,kind_order,id),'[]'::jsonb) INTO v_list FROM (
    SELECT c.created_at AS occurred_at,1 AS kind_order,c.id::text AS id,jsonb_build_object(
      'kind','comment','id',c.id,'threadId',c.thread_id,
      'authorUserId',CASE WHEN c.author_user_id IS NULL THEN NULL ELSE c.author_user_id::text END,
      'authorDisplay',c.author_display_snapshot,
      'body',CASE WHEN c.tombstoned_at IS NULL THEN c.body ELSE NULL END,
      'edited',c.replaces_comment_id IS NOT NULL,'tombstoned',c.tombstoned_at IS NOT NULL,
      'createdAt',c.created_at,
      'mentions',COALESCE((SELECT jsonb_agg(jsonb_build_object(
        'userId',m.user_id::text,'capability',m.capability) ORDER BY m.user_id)
        FROM mail_thread_comment_mentions m WHERE m.comment_id=c.id),'[]'::jsonb)
    ) AS item FROM mail_thread_comments c
     WHERE c.mailbox_id=p_mailbox_id AND c.thread_id=p_thread_id
       AND (p_before IS NULL OR c.created_at<p_before)
    UNION ALL
    SELECT e.occurred_at,0,e.id::text,jsonb_build_object(
      'kind','event','id',e.id,'threadId',e.thread_id,'eventType',e.event_type,
      'actorUserId',CASE WHEN e.actor_user_id IS NULL THEN NULL ELSE e.actor_user_id::text END,
      'actorDisplay',e.actor_display_snapshot,'reason',e.reason,'occurredAt',e.occurred_at,
      'generation',e.generation::text
    ) FROM mail_thread_work_events e
     WHERE e.mailbox_id=p_mailbox_id AND e.thread_id=p_thread_id
       AND (p_before IS NULL OR e.occurred_at<p_before)
    ORDER BY occurred_at DESC,kind_order DESC,id DESC LIMIT p_limit
  ) stream;
  RETURN jsonb_build_object('accountId',p_mailbox_id::text,'state',v_state::text,
    'threadId',p_thread_id,'list',v_list,'hasMore',jsonb_array_length(v_list)=p_limit);
END $$;

ALTER FUNCTION mail_comment_get(bigint,bigint,text,timestamptz,integer) OWNER TO setjoin_worker;
