-- rust_webhook_self_ops.sql — Wave 1.8d (#546d)
-- Owning platform (webhook_subscriptions) self-service reducers retiring
-- direct cross-domain writes from identity/src/self_service.rs. Enforces
-- strict p_user_id <-> app.current_user_id GUC binding for non-privileged callers.

CREATE OR REPLACE FUNCTION rust_webhook_self_create(
  p_user_id       BIGINT,
  p_url           TEXT,
  p_event_types   TEXT,
  p_secret_enc    BYTEA,
  p_secret_key_id TEXT
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

  INSERT INTO public.webhook_subscriptions (
    user_id, url, event_types, scope, secret_enc, secret_key_id
  )
  VALUES (
    p_user_id, p_url, p_event_types::jsonb, 'self', p_secret_enc, p_secret_key_id
  )
  RETURNING id INTO v_id;

  RETURN v_id;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

CREATE OR REPLACE FUNCTION rust_webhook_self_delete(
  p_user_id BIGINT,
  p_id      BIGINT
) RETURNS BOOLEAN AS $$
DECLARE
  v_id BIGINT;
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    IF p_user_id IS NULL
       OR p_user_id IS DISTINCT FROM NULLIF(current_setting('app.current_user_id', true), '')::bigint THEN
      RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
    END IF;
  END IF;

  DELETE FROM public.webhook_subscriptions
   WHERE id = p_id
     AND user_id = p_user_id
  RETURNING id INTO v_id;

  RETURN v_id IS NOT NULL;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;
