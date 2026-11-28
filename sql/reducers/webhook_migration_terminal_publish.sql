-- Enroll one migration terminal fact in the same transaction as its status
-- transition. The target mailbox is accepted only when database ownership binds
-- it to the job user; otherwise the fact deliberately falls back to user audience.
CREATE OR REPLACE FUNCTION webhook_migration_terminal_publish(
  p_job_id bigint,
  p_event_type text
) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE
  v_user_id bigint;
  v_mailbox_id bigint;
  v_status text;
  v_audience text;
  v_event_id text;
BEGIN
  IF p_event_type NOT IN ('migration.completed','migration.failed') THEN
    RAISE EXCEPTION 'unsupported migration webhook event type'
      USING ERRCODE='BZ301';
  END IF;
  IF NOT COALESCE((SELECT enabled FROM feature_toggles
                    WHERE key='feature.webhook_publication_outbox'),false) THEN
    RETURN false;
  END IF;

  SELECT j.user_id,j.target_mailbox_id,j.status
    INTO v_user_id,v_mailbox_id,v_status
    FROM migration_jobs j WHERE j.id=p_job_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Migration job not found' USING ERRCODE='BZ049';
  END IF;
  IF (p_event_type='migration.completed' AND v_status<>'completed')
     OR (p_event_type='migration.failed' AND v_status<>'failed') THEN
    RAISE EXCEPTION 'migration webhook event does not match terminal status'
      USING ERRCODE='BZ301';
  END IF;

  IF v_mailbox_id IS NOT NULL AND EXISTS (
    SELECT 1 FROM mailboxes WHERE id=v_mailbox_id AND user_id=v_user_id
  ) THEN
    v_audience := 'mailbox';
  ELSE
    v_audience := 'user';
    v_mailbox_id := NULL;
  END IF;
  v_event_id := 'migration-' || p_job_id::text || '-'
                || replace(p_event_type,'migration.','');

  INSERT INTO webhook_publications(
    event_id,event_type,source,audience,subject_user_id,subject_mailbox_id,payload)
  VALUES(
    v_event_id,p_event_type,'mailserver/gateway',v_audience,v_user_id,v_mailbox_id,
    jsonb_build_object('job_id',p_job_id)
  ) ON CONFLICT(event_id) DO NOTHING;
  RETURN true;
END $$;

ALTER FUNCTION webhook_migration_terminal_publish(bigint,text) OWNER TO setjoin_worker;
REVOKE ALL ON FUNCTION webhook_migration_terminal_publish(bigint,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION webhook_migration_terminal_publish(bigint,text) FROM setjoin_app;
GRANT EXECUTE ON FUNCTION webhook_migration_terminal_publish(bigint,text) TO setjoin_worker;
