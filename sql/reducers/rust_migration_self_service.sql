-- rust_migration_self_service.sql — Wave 1.8d (#546d)
-- Owning mailboxes/migration_jobs self-service reducers retiring direct
-- cross-domain writes from identity/src/self_service.rs. Enforces strict
-- p_user_id <-> app.current_user_id GUC binding for non-privileged callers.

CREATE OR REPLACE FUNCTION rust_migration_history_delete(
  p_user_id BIGINT
) RETURNS BIGINT AS $$
DECLARE
  v_count BIGINT;
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    IF p_user_id IS NULL
       OR p_user_id IS DISTINCT FROM NULLIF(current_setting('app.current_user_id', true), '')::bigint THEN
      RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
    END IF;
  END IF;

  WITH d AS (
    DELETE FROM public.migration_jobs
     WHERE user_id = p_user_id
       AND status IN ('completed', 'cancelled', 'failed')
    RETURNING id
  )
  SELECT count(*)::bigint INTO v_count FROM d;
  RETURN v_count;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

CREATE OR REPLACE FUNCTION rust_migration_job_insert(
  p_user_id           BIGINT,
  p_source_type       TEXT,
  p_source_config_enc BYTEA,
  p_target_mailbox_id BIGINT,
  p_conflict_strategy TEXT
) RETURNS BIGINT AS $$
DECLARE
  v_id BIGINT;
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    IF p_user_id IS NULL
       OR p_user_id IS DISTINCT FROM NULLIF(current_setting('app.current_user_id', true), '')::bigint THEN
      RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
    END IF;
  END IF;

  INSERT INTO public.migration_jobs (
    user_id, source_type, source_config_enc, target_mailbox_id, conflict_strategy, status
  )
  SELECT p_user_id, p_source_type, p_source_config_enc, p_target_mailbox_id, p_conflict_strategy, 'pending'
   WHERE EXISTS (
     SELECT 1
       FROM public.mailboxes
      WHERE id = p_target_mailbox_id
        AND user_id = p_user_id
   )
  RETURNING id INTO v_id;

  RETURN v_id;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;
