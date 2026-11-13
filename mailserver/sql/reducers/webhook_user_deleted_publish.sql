-- Enroll one approved user.deleted fact inside the owning delete transaction.
-- Subject identity is selected from database authority, never accepted from an
-- unverified request shape. OFF is an exact no-op for rolling compatibility.
CREATE OR REPLACE FUNCTION webhook_user_deleted_publish(
  p_actor_user_id bigint,
  p_subject_user_id bigint
) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE
  v_subject_user_id bigint;
  v_event_id text;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles
                    WHERE key='feature.webhook_publication_outbox'),false) THEN
    RETURN false;
  END IF;

  IF p_actor_user_id IS NULL OR NOT admin_can_manage(p_actor_user_id,p_subject_user_id) THEN
    RAISE EXCEPTION 'webhook publication subject is not manageable'
      USING ERRCODE='BZ001';
  END IF;

  SELECT id INTO v_subject_user_id
    FROM users WHERE id=p_subject_user_id FOR UPDATE;
  IF v_subject_user_id IS NULL THEN
    RETURN false;
  END IF;

  v_event_id := 'usrdel-' || gen_random_uuid()::text;
  INSERT INTO webhook_publications(
    event_id,event_type,source,audience,subject_user_id,payload)
  VALUES(
    v_event_id,'user.deleted','mailserver/auth','user',v_subject_user_id,
    jsonb_build_object('user_id',v_subject_user_id)
  );
  RETURN true;
END $$;

ALTER FUNCTION webhook_user_deleted_publish(bigint,bigint) OWNER TO setjoin_worker;
REVOKE ALL ON FUNCTION webhook_user_deleted_publish(bigint,bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION webhook_user_deleted_publish(bigint,bigint) FROM setjoin_app;
GRANT EXECUTE ON FUNCTION webhook_user_deleted_publish(bigint,bigint) TO setjoin_worker;
