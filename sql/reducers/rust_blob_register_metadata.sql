-- rust_blob_register_metadata.sql — Wave 1.8c (#546c)
-- Owning reducer for content-addressed blob metadata registration (retiring
-- chat's direct cross-domain INSERT into blobs).
-- Validates input invariants (22023) and requires an active tenant scope GUC
-- for non-privileged callers (42501).

CREATE OR REPLACE FUNCTION rust_blob_register_metadata(
  p_sha256       TEXT,
  p_minio_ref    TEXT,
  p_size_bytes   BIGINT,
  p_content_type TEXT
) RETURNS VOID AS $$
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    IF NULLIF(current_setting('app.current_user_id', true), '') IS NULL
       AND NULLIF(current_setting('app.current_mailbox_id', true), '') IS NULL THEN
      RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
    END IF;
  END IF;

  IF p_sha256 IS NULL OR p_sha256 !~ '^[0-9a-f]{64}$'
     OR p_size_bytes IS NULL OR p_size_bytes < 0
     OR p_minio_ref IS NULL OR btrim(p_minio_ref) = ''
     OR p_content_type IS NULL OR btrim(p_content_type) = '' THEN
    RAISE EXCEPTION 'invalid blob metadata arguments' USING ERRCODE = '22023';
  END IF;

  PERFORM public.blob_gc_register_and_reactivate(
    p_sha256,
    p_minio_ref,
    p_size_bytes,
    p_content_type
  );
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, public;
