CREATE OR REPLACE FUNCTION mail_work_sla_policy_get(
  p_mailbox_id bigint,
  p_actor_user_id bigint
) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_policy jsonb; v_can_manage boolean;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.shared_mail_work'),false) THEN
    RAISE EXCEPTION 'shared mail work is disabled' USING ERRCODE='BZ300';
  END IF;
  IF NOT mail_work_can_read(p_mailbox_id,p_actor_user_id) THEN
    RAISE EXCEPTION 'shared mailbox not found' USING ERRCODE='BZ006';
  END IF;
  v_can_manage:=EXISTS(SELECT 1 FROM mailbox_delegates
    WHERE mailbox_id=p_mailbox_id AND user_id=p_actor_user_id AND permission='full_access');
  v_policy:=mail_work_sla_policy_snapshot(p_mailbox_id);
  RETURN jsonb_build_object('accountId',p_mailbox_id::text,'canManage',v_can_manage,
    'policy',v_policy,'updatedAt',(SELECT updated_at FROM mail_work_sla_policies WHERE mailbox_id=p_mailbox_id),
    'updatedBy',CASE WHEN (SELECT updated_by FROM mail_work_sla_policies WHERE mailbox_id=p_mailbox_id) IS NULL
      THEN NULL ELSE (SELECT updated_by::text FROM mail_work_sla_policies WHERE mailbox_id=p_mailbox_id) END);
END $$;

ALTER FUNCTION mail_work_sla_policy_get(bigint,bigint) OWNER TO setjoin_worker;
