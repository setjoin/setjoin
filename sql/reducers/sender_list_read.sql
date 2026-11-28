-- Generation-bound sender-list projection for compatibility settings clients.

CREATE OR REPLACE FUNCTION sender_list_read(p_user_id bigint) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
  SELECT jsonb_build_object(
    'safe',COALESCE(jsonb_agg(sender ORDER BY sender) FILTER(WHERE list_type='safe'),'[]'::jsonb),
    'blocked',COALESCE(jsonb_agg(sender ORDER BY sender) FILTER(WHERE list_type='blocked'),'[]'::jsonb),
    'generation',(SELECT generation::text FROM sender_control_state WHERE user_id=p_user_id))
  FROM user_sender_list WHERE user_id=p_user_id
$$;

ALTER FUNCTION sender_list_read(bigint) OWNER TO setjoin_worker;
