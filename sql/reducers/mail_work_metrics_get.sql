CREATE OR REPLACE FUNCTION mail_work_metrics_get(
  p_mailbox_id bigint,
  p_actor_user_id bigint,
  p_from date,
  p_to date,
  p_policy_version integer DEFAULT 1
) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_actors integer; v_conversations integer; v_rows jsonb;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.shared_mail_analytics'),false) THEN
    RAISE EXCEPTION 'shared mail analytics are disabled' USING ERRCODE='BZ300';
  END IF;
  IF p_from IS NULL OR p_to IS NULL OR p_to<p_from OR p_to-p_from>366 OR p_policy_version<1 THEN
    RAISE EXCEPTION 'invalid metric range' USING ERRCODE='BZ301';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM mailbox_delegates WHERE mailbox_id=p_mailbox_id
    AND user_id=p_actor_user_id AND permission='full_access') THEN
    RAISE EXCEPTION 'full access is required for aggregate analytics' USING ERRCODE='BZ005';
  END IF;
  SELECT COALESCE(max(actor_cohort_count),0),COALESCE(sum(conversation_count),0)
    INTO v_actors,v_conversations FROM mail_work_metric_daily
    WHERE mailbox_id=p_mailbox_id AND metric_day BETWEEN p_from AND p_to AND policy_version=p_policy_version;
  IF v_actors<5 OR v_conversations<20 THEN
    RETURN jsonb_build_object('accountId',p_mailbox_id::text,'available',false,
      'reason','cohort_floor','minimumActors',5,'minimumConversations',20);
  END IF;
  SELECT COALESCE(jsonb_agg(to_jsonb(m)-'mailbox_id' ORDER BY metric_day),'[]'::jsonb) INTO v_rows
    FROM mail_work_metric_daily m WHERE mailbox_id=p_mailbox_id
      AND metric_day BETWEEN p_from AND p_to AND policy_version=p_policy_version;
  RETURN jsonb_build_object('accountId',p_mailbox_id::text,'available',true,'list',v_rows,
    'policyVersion',p_policy_version);
END $$;

ALTER FUNCTION mail_work_metrics_get(bigint,bigint,date,date,integer) OWNER TO setjoin_worker;
