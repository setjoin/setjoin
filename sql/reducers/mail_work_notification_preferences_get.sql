CREATE OR REPLACE FUNCTION mail_work_notification_preferences_get(
  p_mailbox_id bigint,
  p_actor_user_id bigint
) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.shared_mail_notifications'),false) THEN
    RAISE EXCEPTION 'shared mail notifications are disabled' USING ERRCODE='BZ300';
  END IF;
  IF NOT mail_work_can_read(p_mailbox_id,p_actor_user_id) THEN
    RAISE EXCEPTION 'shared mailbox not found' USING ERRCODE='BZ006';
  END IF;
  RETURN jsonb_build_object('accountId',p_mailbox_id::text,'list',(
    SELECT jsonb_agg(jsonb_build_object('category',d.category,
      'delivery',COALESCE(p.delivery,d.default_delivery),'timezone',COALESCE(p.timezone,'UTC'),
      'digestHour',COALESCE(p.digest_hour,9),'generation',COALESCE(p.generation,0)::text)
      ORDER BY d.ordinal)
    FROM (VALUES
      ('assignment','immediate',1),('handoff','immediate',2),('mention','immediate',3),
      ('comment','immediate',4),('due','digest',5),('breach','digest',6),
      ('priority','digest',7),('mailbox_rule','digest',8)
    ) d(category,default_delivery,ordinal)
    LEFT JOIN mail_work_notification_preferences p ON p.mailbox_id=p_mailbox_id
      AND p.user_id=p_actor_user_id AND p.category=d.category
  ));
END $$;

ALTER FUNCTION mail_work_notification_preferences_get(bigint,bigint) OWNER TO setjoin_worker;
