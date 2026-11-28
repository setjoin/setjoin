CREATE OR REPLACE FUNCTION mail_work_metrics_rebuild(
  p_mailbox_id bigint,
  p_actor_user_id bigint,
  p_from date,
  p_to date,
  p_policy_version integer DEFAULT 1
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_rows integer;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.shared_mail_analytics'),false) THEN
    RAISE EXCEPTION 'shared mail analytics are disabled' USING ERRCODE='BZ300';
  END IF;
  IF p_from IS NULL OR p_to IS NULL OR p_to<p_from OR p_to-p_from>366 OR p_policy_version<1 THEN
    RAISE EXCEPTION 'invalid metric rebuild range' USING ERRCODE='BZ301';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM mailbox_delegates WHERE mailbox_id=p_mailbox_id
    AND user_id=p_actor_user_id AND permission='full_access') THEN
    RAISE EXCEPTION 'full access is required for aggregate analytics' USING ERRCODE='BZ005';
  END IF;
  DELETE FROM mail_work_metric_daily WHERE mailbox_id=p_mailbox_id
    AND metric_day BETWEEN p_from AND p_to AND policy_version=p_policy_version;
  DELETE FROM mail_work_metric_conversations WHERE mailbox_id=p_mailbox_id
    AND metric_day BETWEEN p_from AND p_to AND policy_version=p_policy_version;
  DELETE FROM mail_work_metric_actors WHERE mailbox_id=p_mailbox_id
    AND metric_day BETWEEN p_from AND p_to AND policy_version=p_policy_version;
  INSERT INTO mail_work_metric_conversations(mailbox_id,metric_day,policy_version,thread_id)
  SELECT p_mailbox_id,(e.occurred_at AT TIME ZONE COALESCE(w.sla_policy_snapshot->>'timezone','UTC'))::date,
    p_policy_version,e.thread_id
  FROM mail_thread_work_events e
  JOIN mail_thread_work w ON w.mailbox_id=e.mailbox_id AND w.thread_id=e.thread_id
  WHERE e.mailbox_id=p_mailbox_id AND e.occurred_at>=p_from
    AND e.occurred_at<p_to+2
    AND (e.occurred_at AT TIME ZONE COALESCE(w.sla_policy_snapshot->>'timezone','UTC'))::date BETWEEN p_from AND p_to
  GROUP BY (e.occurred_at AT TIME ZONE COALESCE(w.sla_policy_snapshot->>'timezone','UTC'))::date,e.thread_id;
  INSERT INTO mail_work_metric_actors(mailbox_id,metric_day,policy_version,actor_user_id)
  SELECT p_mailbox_id,(e.occurred_at AT TIME ZONE COALESCE(w.sla_policy_snapshot->>'timezone','UTC'))::date,
    p_policy_version,e.actor_user_id
  FROM mail_thread_work_events e
  JOIN mail_thread_work w ON w.mailbox_id=e.mailbox_id AND w.thread_id=e.thread_id
  WHERE e.mailbox_id=p_mailbox_id AND e.occurred_at>=p_from
    AND e.occurred_at<p_to+2 AND e.actor_user_id IS NOT NULL
    AND (e.occurred_at AT TIME ZONE COALESCE(w.sla_policy_snapshot->>'timezone','UTC'))::date BETWEEN p_from AND p_to
  GROUP BY (e.occurred_at AT TIME ZONE COALESCE(w.sla_policy_snapshot->>'timezone','UTC'))::date,e.actor_user_id;
  INSERT INTO mail_work_metric_daily(mailbox_id,metric_day,policy_version,conversation_count,
    first_response_count,first_response_seconds,completed_count,breached_count,actor_cohort_count)
  SELECT p_mailbox_id,d::date,p_policy_version,
    count(DISTINCT e.thread_id)::integer,
    count(*) FILTER(WHERE e.event_type='first_response')::integer,
    COALESCE(sum(mail_work_business_seconds(e.first_activity_at,e.occurred_at,e.sla_policy_snapshot))
      FILTER(WHERE e.event_type='first_response'),0)::bigint,
    count(*) FILTER(WHERE e.event_type='completed')::integer,
    count(*) FILTER(WHERE e.event_type='sla_breached')::integer,
    count(DISTINCT e.actor_user_id) FILTER(WHERE e.actor_user_id IS NOT NULL)::integer
  FROM generate_series(p_from,p_to,interval '1 day') d
  LEFT JOIN (
    SELECT event.*,work.first_activity_at,work.sla_policy_snapshot,
      (event.occurred_at AT TIME ZONE COALESCE(work.sla_policy_snapshot->>'timezone','UTC'))::date AS local_day
    FROM mail_thread_work_events event
    JOIN mail_thread_work work ON work.mailbox_id=event.mailbox_id AND work.thread_id=event.thread_id
    WHERE event.mailbox_id=p_mailbox_id
  ) e ON e.local_day=d::date
  GROUP BY d;
  GET DIAGNOSTICS v_rows=ROW_COUNT;
  RETURN jsonb_build_object('accountId',p_mailbox_id::text,'from',p_from,'to',p_to,
    'policyVersion',p_policy_version,'daysRebuilt',v_rows);
END $$;

ALTER FUNCTION mail_work_metrics_rebuild(bigint,bigint,date,date,integer) OWNER TO setjoin_worker;
