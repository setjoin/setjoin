CREATE OR REPLACE FUNCTION exchange_assessment_delete_finalize(
  p_request_id bigint, p_subject_digest text, p_receipt jsonb,
  p_signature_algorithm text, p_signing_key_id text, p_signature bytea
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE
  v_request exchange_assessment_deletion_requests%ROWTYPE;
  v_receipt exchange_assessment_receipts%ROWTYPE;
  v_artifact exchange_assessment_artifacts%ROWTYPE;
BEGIN
  SELECT * INTO v_request FROM exchange_assessment_deletion_requests
  WHERE id=p_request_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Exchange assessment deletion request not found' USING ERRCODE='BZ317';
  END IF;
  IF p_subject_digest !~ '^[0-9a-f]{64}$' OR p_receipt IS NULL
     OR jsonb_typeof(p_receipt)<>'object' OR octet_length(p_receipt::text)>262144
     OR p_receipt#>>'{claims,subjectSha256}'<>p_subject_digest
     OR p_receipt#>>'{claims,kind}'<>'deletion'
     OR p_receipt#>>'{claims,disposition}'<>'backup_expiry_pending'
     OR p_signature_algorithm<>'ed25519' OR octet_length(p_signing_key_id) NOT BETWEEN 1 AND 128
     OR octet_length(p_signature)<>64 THEN
    RAISE EXCEPTION 'Invalid Exchange assessment deletion receipt' USING ERRCODE='BZ316';
  END IF;
  SELECT * INTO v_receipt FROM exchange_assessment_receipts
  WHERE kind='deletion' AND subject_digest=p_subject_digest;
  IF FOUND THEN
    IF v_request.state='backup_pending' THEN
      RETURN to_jsonb(v_request)||jsonb_build_object('replayed',true,'receiptId',v_receipt.id);
    END IF;
    RAISE EXCEPTION 'Conflicting Exchange assessment deletion receipt' USING ERRCODE='BZ319';
  END IF;
  IF v_request.state<>'requested' THEN
    RAISE EXCEPTION 'Exchange assessment deletion request is not executable' USING ERRCODE='BZ319';
  END IF;

  INSERT INTO exchange_assessment_receipts(run_id,kind,subject_digest,receipt,
    signature_algorithm,signing_key_id,signature,created_by)
  VALUES(v_request.run_id,'deletion',p_subject_digest,p_receipt,
    p_signature_algorithm,p_signing_key_id,p_signature,v_request.requested_by)
  RETURNING * INTO v_receipt;

  FOR v_artifact IN
    SELECT a.* FROM exchange_assessment_artifacts a
    JOIN exchange_assessment_runs r ON r.id=a.run_id
    WHERE (v_request.scope='artifact' AND a.id=v_request.artifact_id)
       OR (v_request.scope='run' AND a.run_id=v_request.run_id)
       OR (v_request.scope='project' AND r.project_id=v_request.project_id)
    FOR UPDATE OF a
  LOOP
    UPDATE exchange_assessment_artifacts SET disposition='backup_expiry_pending',
      deleted_at=COALESCE(deleted_at,statement_timestamp()) WHERE id=v_artifact.id;
    INSERT INTO exchange_assessment_tombstones(artifact_digest,run_id,disposition,
      requested_by,receipt_id)
    VALUES(v_artifact.sha256,v_artifact.run_id,'backup_expiry_pending',
      v_request.requested_by,(p_receipt#>>'{claims,receiptId}')||'-'||v_artifact.id::text)
    ON CONFLICT(run_id,artifact_digest) DO NOTHING;
  END LOOP;

  UPDATE exchange_assessment_deletion_requests SET state='backup_pending',
    updated_at=statement_timestamp() WHERE id=v_request.id;
  PERFORM audit_write(v_request.requested_by,'exchange.assessment.delete.active_store',
    'exchange_assessment_project',v_request.project_id,NULL,
    jsonb_build_object('requestId',v_request.id,'receiptId',v_receipt.id,
      'disposition','backup_expiry_pending'),NULL,v_request.reason,'core');
  PERFORM app_notify('exchange_assessment',jsonb_build_object('event','deletion.backup_pending',
    'projectId',v_request.project_id,'requestId',v_request.id)::text);
  RETURN to_jsonb(v_request)||jsonb_build_object('state','backup_pending',
    'receiptId',v_receipt.id,'disposition','backup_expiry_pending');
END;
$$;
SELECT apply_worker_ownership('exchange_assessment_delete_finalize(bigint,text,jsonb,text,text,bytea)'::regprocedure);
