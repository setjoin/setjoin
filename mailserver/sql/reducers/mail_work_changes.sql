CREATE OR REPLACE FUNCTION mail_work_changes(
  p_mailbox_id bigint,
  p_actor_user_id bigint,
  p_since_state text,
  p_max_changes integer DEFAULT NULL
) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_since bigint; v_current bigint; v_limit integer; v_page_max bigint;
  v_has_more boolean; v_min bigint;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.shared_mail_work'),false) THEN
    RAISE EXCEPTION 'shared mail work is disabled' USING ERRCODE='BZ300';
  END IF;
  BEGIN v_since:=p_since_state::bigint; EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'invalid mail-work state' USING ERRCODE='BZ011';
  END;
  IF v_since<0 THEN RAISE EXCEPTION 'invalid mail-work state' USING ERRCODE='BZ011'; END IF;
  SELECT jmap_mailwork_state INTO v_current FROM mailboxes
   WHERE id=p_mailbox_id AND user_id IS NULL AND mail_work_can_read(id,p_actor_user_id);
  IF v_current IS NULL THEN RAISE EXCEPTION 'shared mailbox not found' USING ERRCODE='BZ006'; END IF;
  v_limit:=LEAST(GREATEST(COALESCE(p_max_changes,256),1),256);
  SELECT min(state_seq) INTO v_min FROM mail_work_changes WHERE mailbox_id=p_mailbox_id;
  IF v_since<v_current AND v_min IS NOT NULL AND v_since<v_min-1 THEN
    RAISE EXCEPTION 'mail-work changes no longer available' USING ERRCODE='BZ011';
  END IF;

  WITH page AS (
    SELECT * FROM mail_work_changes WHERE mailbox_id=p_mailbox_id AND state_seq>v_since
     ORDER BY state_seq LIMIT v_limit
  ) SELECT max(state_seq) INTO v_page_max FROM page;
  v_page_max:=COALESCE(v_page_max,v_since);
  v_has_more:=v_page_max<v_current;

  RETURN jsonb_build_object(
    'accountId',p_mailbox_id::text,'oldState',v_since::text,
    'newState',(CASE WHEN v_has_more THEN v_page_max ELSE v_current END)::text,
    'hasMoreChanges',v_has_more,
    'created',COALESCE((SELECT jsonb_agg(object_id ORDER BY state_seq) FROM mail_work_changes
      WHERE mailbox_id=p_mailbox_id AND state_seq>v_since AND state_seq<=v_page_max AND op='created'),'[]'::jsonb),
    'updated',COALESCE((SELECT jsonb_agg(object_id ORDER BY state_seq) FROM mail_work_changes
      WHERE mailbox_id=p_mailbox_id AND state_seq>v_since AND state_seq<=v_page_max AND op='updated'),'[]'::jsonb),
    'destroyed',COALESCE((SELECT jsonb_agg(object_id ORDER BY state_seq) FROM mail_work_changes
      WHERE mailbox_id=p_mailbox_id AND state_seq>v_since AND state_seq<=v_page_max AND op='destroyed'),'[]'::jsonb)
  );
END $$;

ALTER FUNCTION mail_work_changes(bigint,bigint,text,integer) OWNER TO setjoin_worker;
