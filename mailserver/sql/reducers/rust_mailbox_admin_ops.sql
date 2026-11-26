-- rust_mailbox_admin_ops.sql — Wave 1.8d (#546d)
-- Owning mailboxes/aliases reducers retiring direct cross-domain writes from
-- admin-identity and identity. Strictly worker/admin-only: fail closed (42501)
-- unless called from a privileged role, and revoked from PUBLIC and setjoin_app
-- (restated in scripts/provision-roles.sql exact_worker).

CREATE OR REPLACE FUNCTION rust_mailbox_admin_set_quota(
  p_user_id           BIGINT,
  p_domain_scope      BIGINT,
  p_quota_bytes       BIGINT,
  p_sending_quota_day INTEGER
) RETURNS BIGINT AS $$
DECLARE
  v_count BIGINT;
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
  END IF;
  WITH updated AS (
    UPDATE public.mailboxes
       SET quota_bytes = COALESCE(p_quota_bytes, quota_bytes),
           sending_quota_day = COALESCE(p_sending_quota_day, sending_quota_day),
           updated_at = now()
     WHERE user_id = p_user_id
       AND is_primary = TRUE
       AND (p_domain_scope = 0 OR domain_id = p_domain_scope)
    RETURNING 1
  )
  SELECT count(*)::bigint INTO v_count FROM updated;
  RETURN v_count;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

REVOKE ALL ON FUNCTION public.rust_mailbox_admin_set_quota(bigint,bigint,bigint,integer) FROM PUBLIC, setjoin_app;
GRANT EXECUTE ON FUNCTION public.rust_mailbox_admin_set_quota(bigint,bigint,bigint,integer) TO setjoin_worker;

CREATE OR REPLACE FUNCTION rust_mailbox_alias_add(
  p_mailbox_id     BIGINT,
  p_user_id        BIGINT,
  p_domain_scope   BIGINT,
  p_email          TEXT,
  p_enforce_domain BOOLEAN
) RETURNS BIGINT AS $$
DECLARE
  v_id BIGINT;
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
  END IF;
  IF p_enforce_domain THEN
    INSERT INTO public.aliases (mailbox_id, email, domain_id)
    SELECT m.id, p_email, m.domain_id
      FROM public.mailboxes m
     WHERE m.id = p_mailbox_id
       AND m.user_id = p_user_id
       AND m.is_primary = TRUE
       AND (
         p_domain_scope = 0
         OR (
           m.domain_id = p_domain_scope
           AND EXISTS (
             SELECT 1
               FROM public.domains d
              WHERE d.id = m.domain_id
                AND lower(d.name) = lower(split_part(p_email, '@', 2))
           )
         )
       )
    RETURNING id INTO v_id;
  ELSE
    INSERT INTO public.aliases (mailbox_id, email, domain_id)
    SELECT m.id, p_email, m.domain_id
      FROM public.mailboxes m
     WHERE m.id = p_mailbox_id
       AND m.user_id = p_user_id
       AND m.is_primary = TRUE
       AND (p_domain_scope = 0 OR m.domain_id = p_domain_scope)
    RETURNING id INTO v_id;
  END IF;
  RETURN v_id;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

REVOKE ALL ON FUNCTION public.rust_mailbox_alias_add(bigint,bigint,bigint,text,boolean) FROM PUBLIC, setjoin_app;
GRANT EXECUTE ON FUNCTION public.rust_mailbox_alias_add(bigint,bigint,bigint,text,boolean) TO setjoin_worker;

CREATE OR REPLACE FUNCTION rust_mailbox_alias_remove(
  p_alias_id     BIGINT,
  p_user_id      BIGINT,
  p_domain_scope BIGINT
) RETURNS BIGINT AS $$
DECLARE
  v_count BIGINT;
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
  END IF;
  WITH removed AS (
    DELETE FROM public.aliases
     WHERE id = p_alias_id
       AND mailbox_id IN (
         SELECT id
           FROM public.mailboxes
          WHERE user_id = p_user_id
            AND is_primary = TRUE
            AND (p_domain_scope = 0 OR domain_id = p_domain_scope)
       )
    RETURNING 1
  )
  SELECT count(*)::bigint INTO v_count FROM removed;
  RETURN v_count;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

REVOKE ALL ON FUNCTION public.rust_mailbox_alias_remove(bigint,bigint,bigint) FROM PUBLIC, setjoin_app;
GRANT EXECUTE ON FUNCTION public.rust_mailbox_alias_remove(bigint,bigint,bigint) TO setjoin_worker;

CREATE OR REPLACE FUNCTION rust_mailbox_ensure_primary(
  p_user_id BIGINT
) RETURNS VOID AS $$
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
  END IF;
  INSERT INTO public.mailboxes (user_id, domain_id, email, display_name, type, is_primary)
  SELECT u.id, u.domain_id, u.email, u.display_name, 'personal', TRUE
    FROM public.users u
   WHERE u.id = p_user_id
  ON CONFLICT DO NOTHING;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

REVOKE ALL ON FUNCTION public.rust_mailbox_ensure_primary(bigint) FROM PUBLIC, setjoin_app;
GRANT EXECUTE ON FUNCTION public.rust_mailbox_ensure_primary(bigint) TO setjoin_worker;
