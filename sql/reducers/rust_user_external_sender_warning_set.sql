-- rust_user_external_sender_warning_set.sql — Wave 1.8c (#546c)
-- Owning reducer for updating a user's external_sender_warning preference
-- (retiring mail-security's direct cross-domain UPDATE on users).
-- Enforces fail-closed app.current_user_id GUC binding for non-privileged callers.

CREATE OR REPLACE FUNCTION rust_user_external_sender_warning_set(
  p_user_id BIGINT,
  p_enabled BOOLEAN
) RETURNS BOOLEAN AS $$
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    IF p_user_id IS NULL
       OR p_user_id IS DISTINCT FROM NULLIF(current_setting('app.current_user_id', true), '')::bigint THEN
      RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
    END IF;
  END IF;
  UPDATE public.users
     SET external_sender_warning = p_enabled
   WHERE id = p_user_id;
  RETURN FOUND;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;
