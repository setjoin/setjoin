-- rust_jmap_unsubscribe_record.sql — Wave 1.8c (#546c)
-- Owning reducer for the unsubscribe audit row + sender block write (retiring
-- jmap's direct cross-domain INSERT into user_sender_list).
-- Enforces fail-closed app.current_user_id GUC binding BEFORE audit_write for
-- non-privileged callers.

CREATE OR REPLACE FUNCTION rust_jmap_unsubscribe_record(
  p_user_id   BIGINT,
  p_target_id BIGINT,
  p_sender    TEXT
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

  PERFORM public.audit_write(
    p_user_id,
    'unsubscribe_newsletter',
    'message',
    p_target_id,
    NULL,
    NULL,
    NULL,
    'List-Unsubscribe POST',
    'routine'
  );
  v_count := 1;

  IF p_sender IS NOT NULL AND p_sender <> '' THEN
    INSERT INTO public.user_sender_list (user_id, sender, list_type)
    VALUES (p_user_id, p_sender, 'blocked')
    ON CONFLICT (user_id, sender, list_type) DO NOTHING;
  END IF;

  RETURN v_count;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;
