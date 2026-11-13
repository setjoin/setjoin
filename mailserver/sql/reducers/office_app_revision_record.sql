-- N-1 compatibility shim. V225 atomically commits revision plus operation state
-- through office_app_install_commit; the split V224 mutation is fail closed.
CREATE OR REPLACE FUNCTION office_app_revision_record(
  p_operation_id uuid,
  p_expected_generation bigint,
  p_executor_id text,
  p_lease_id uuid,
  p_image_reference text,
  p_image_digest text,
  p_artifact_receipt jsonb,
  p_runtime_config jsonb
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
BEGIN
  RAISE EXCEPTION 'split managed Office revision commit is retired' USING ERRCODE='BZ324',
    HINT='{"type":"stateMismatch","detail":"upgrade the app runner and retry recovery"}';
END;
$$;
SELECT apply_worker_ownership('office_app_revision_record(uuid,bigint,text,uuid,text,text,jsonb,jsonb)'::regprocedure);
