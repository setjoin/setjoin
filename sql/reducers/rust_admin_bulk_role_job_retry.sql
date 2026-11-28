-- rust_admin_bulk_role_job_retry.sql — Wave 1.8d (#546d)
-- Owning admin-identity (bulk_role_jobs) retry reducer retiring direct
-- cross-domain UPDATE from platform/src/jobs.rs. Writes core audit_write in the
-- same transaction when a job transitions error -> queued (compatible with
-- SqlAuditPosture::ReducerWritesCoreAudit). Strictly worker/admin-only.

CREATE OR REPLACE FUNCTION rust_admin_bulk_role_job_retry(
  p_actor  BIGINT,
  p_job_id BIGINT,
  p_ip     TEXT
) RETURNS BOOLEAN AS $$
DECLARE
  v_id BIGINT;
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
  END IF;

  UPDATE public.bulk_role_jobs
     SET status = 'queued',
         error = NULL,
         updated_at = now()
   WHERE id = p_job_id
     AND status = 'error'
  RETURNING id INTO v_id;

  IF v_id IS NULL THEN
    RETURN FALSE;
  END IF;

  PERFORM public.audit_write(
    p_actor,
    'bulk_role_job_retry',
    'bulk_role_job',
    v_id,
    NULL,
    NULL,
    NULLIF(p_ip, '')::inet,
    '',
    'core'
  );
  RETURN TRUE;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;

REVOKE ALL ON FUNCTION public.rust_admin_bulk_role_job_retry(bigint,bigint,text) FROM PUBLIC, setjoin_app;
GRANT EXECUTE ON FUNCTION public.rust_admin_bulk_role_job_retry(bigint,bigint,text) TO setjoin_worker;
