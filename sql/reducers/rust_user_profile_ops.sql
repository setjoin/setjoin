-- rust_user_profile_ops.sql — Wave 1.8d (#546d)
-- Owning identity (users) self-service profile/view_prefs reducers retiring
-- direct cross-domain UPDATE users statements from user-settings. Enforces
-- strict p_user_id <-> app.current_user_id GUC binding for non-privileged callers.

CREATE OR REPLACE FUNCTION rust_user_profile_update(
  p_user_id      BIGINT,
  p_display_name TEXT
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

  WITH written AS (
    UPDATE public.users
       SET display_name = p_display_name,
           updated_at = now()
     WHERE id = p_user_id
    RETURNING 1
  )
  SELECT count(*)::bigint INTO v_count FROM written;
  RETURN v_count;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

CREATE OR REPLACE FUNCTION rust_user_view_prefs_set(
  p_user_id    BIGINT,
  p_view_prefs TEXT
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

  WITH written AS (
    UPDATE public.users
       SET view_prefs = p_view_prefs::jsonb
     WHERE id = p_user_id
    RETURNING 1
  )
  SELECT count(*)::bigint INTO v_count FROM written;
  RETURN v_count;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

CREATE OR REPLACE FUNCTION rust_user_view_prefs_merge(
  p_user_id BIGINT,
  p_patch   TEXT
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

  WITH written AS (
    UPDATE public.users
       SET view_prefs = COALESCE(view_prefs, '{}'::jsonb) || p_patch::jsonb
     WHERE id = p_user_id
    RETURNING 1
  )
  SELECT count(*)::bigint INTO v_count FROM written;
  RETURN v_count;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;
