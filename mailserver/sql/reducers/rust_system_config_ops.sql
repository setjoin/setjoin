-- rust_system_config_ops.sql — Wave 1.8c (#546c)
-- Owning reducers for system_config mutations (retiring direct cross-domain
-- writes from mail-security and mailboxes). Strictly worker/admin-only:
-- fail closed (42501) unless called from a privileged role, and revoked from
-- PUBLIC and setjoin_app (restated in scripts/provision-roles.sql exact_worker).

CREATE OR REPLACE FUNCTION rust_system_config_upsert_batch(
  p_keys        TEXT[],
  p_values      TEXT[],
  p_description TEXT
) RETURNS INT AS $$
DECLARE
  v_count INT;
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
  END IF;
  WITH w AS (
    INSERT INTO public.system_config (key, value, description)
    SELECT t.k, t.v::jsonb, p_description
      FROM unnest(p_keys, p_values) AS t(k, v)
    ON CONFLICT (key) DO UPDATE
      SET value = EXCLUDED.value,
          updated_at = now()
    RETURNING 1
  )
  SELECT count(*)::int INTO v_count FROM w;
  RETURN v_count;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

REVOKE ALL ON FUNCTION public.rust_system_config_upsert_batch(text[],text[],text) FROM PUBLIC, setjoin_app;
GRANT EXECUTE ON FUNCTION public.rust_system_config_upsert_batch(text[],text[],text) TO setjoin_worker;

CREATE OR REPLACE FUNCTION rust_system_config_upsert(
  p_key       TEXT,
  p_value     TEXT,
  p_encrypted BOOLEAN
) RETURNS BIGINT AS $$
DECLARE
  v_count BIGINT;
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
  END IF;
  IF p_encrypted THEN
    WITH w AS (
      INSERT INTO public.system_config (key, value, encrypted)
      VALUES (p_key, p_value::jsonb, TRUE)
      ON CONFLICT (key) DO UPDATE
        SET value = EXCLUDED.value,
            encrypted = TRUE,
            updated_at = now()
      RETURNING 1
    )
    SELECT count(*)::bigint INTO v_count FROM w;
  ELSE
    WITH w AS (
      INSERT INTO public.system_config (key, value)
      VALUES (p_key, p_value::jsonb)
      ON CONFLICT (key) DO UPDATE
        SET value = EXCLUDED.value,
            updated_at = now()
      RETURNING 1
    )
    SELECT count(*)::bigint INTO v_count FROM w;
  END IF;
  RETURN v_count;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

REVOKE ALL ON FUNCTION public.rust_system_config_upsert(text,text,boolean) FROM PUBLIC, setjoin_app;
GRANT EXECUTE ON FUNCTION public.rust_system_config_upsert(text,text,boolean) TO setjoin_worker;

CREATE OR REPLACE FUNCTION rust_system_config_delete(
  p_key TEXT
) RETURNS BIGINT AS $$
DECLARE
  v_count BIGINT;
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
  END IF;
  WITH d AS (
    DELETE FROM public.system_config
     WHERE key = p_key
    RETURNING 1
  )
  SELECT count(*)::bigint INTO v_count FROM d;
  RETURN v_count;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

REVOKE ALL ON FUNCTION public.rust_system_config_delete(text) FROM PUBLIC, setjoin_app;
GRANT EXECUTE ON FUNCTION public.rust_system_config_delete(text) TO setjoin_worker;
