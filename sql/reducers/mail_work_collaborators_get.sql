CREATE OR REPLACE FUNCTION mail_work_collaborators_get(
  p_mailbox_id bigint,p_actor_user_id bigint,p_query text DEFAULT NULL,p_limit integer DEFAULT 20
) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_list jsonb;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.shared_mail_work'),false) THEN
    RAISE EXCEPTION 'shared mail work is disabled' USING ERRCODE='BZ300';
  END IF;
  IF NOT mail_work_can_read(p_mailbox_id,p_actor_user_id) THEN
    RAISE EXCEPTION 'shared mailbox not found' USING ERRCODE='BZ006';
  END IF;
  IF p_limit NOT BETWEEN 1 AND 50 OR COALESCE(octet_length(p_query),0)>128 THEN
    RAISE EXCEPTION 'invalid collaborator query' USING ERRCODE='BZ301';
  END IF;
  SELECT COALESCE(jsonb_agg(item ORDER BY display_name,email,user_id),'[]'::jsonb) INTO v_list FROM (
    SELECT u.id AS user_id,COALESCE(NULLIF(u.display_name,''),u.email) AS display_name,u.email,
      jsonb_build_object('id',u.id::text,'displayName',COALESCE(NULLIF(u.display_name,''),u.email),
        'email',u.email,'capability',CASE WHEN bool_or(d.permission IN ('full_access','send_as','send_on_behalf'))
          THEN 'comment' ELSE 'view_only' END) AS item
    FROM mailbox_delegates d JOIN users u ON u.id=d.user_id
    WHERE d.mailbox_id=p_mailbox_id AND u.enabled
      AND (NULLIF(btrim(p_query),'') IS NULL OR position(lower(btrim(p_query)) IN
        lower(COALESCE(u.display_name,'')||' '||u.email))>0)
    GROUP BY u.id,u.display_name,u.email LIMIT p_limit
  ) collaborators;
  RETURN jsonb_build_object('accountId',p_mailbox_id::text,'list',v_list);
END $$;

ALTER FUNCTION mail_work_collaborators_get(bigint,bigint,text,integer) OWNER TO setjoin_worker;
