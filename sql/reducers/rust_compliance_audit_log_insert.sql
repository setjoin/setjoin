-- rust_compliance_audit_log_insert.sql — Wave 1.8d (#546d)
-- Owning compliance (audit_log) insert reducer retiring direct cross-domain
-- INSERT into audit_log from identity/src/impersonation.rs. Enforces strict
-- p_user_id <-> app.current_user_id GUC binding for non-privileged callers.

CREATE OR REPLACE FUNCTION rust_compliance_audit_log_insert(
  p_user_id    BIGINT,
  p_source_ip  TEXT,
  p_event_type TEXT,
  p_metadata   TEXT
) RETURNS VOID AS $$
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    IF p_user_id IS NULL
       OR p_user_id IS DISTINCT FROM NULLIF(current_setting('app.current_user_id', true), '')::bigint THEN
      RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
    END IF;
  END IF;

  INSERT INTO public.audit_log (user_id, source_ip, event_type, metadata)
  VALUES (p_user_id, NULLIF(p_source_ip, '')::inet, p_event_type, p_metadata::jsonb);
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;
