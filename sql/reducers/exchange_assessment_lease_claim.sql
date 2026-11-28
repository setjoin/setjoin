-- Worker/BYPASSRLS claim seam. A monotonically increasing fencing token makes
-- a resumed worker reject writes from an expired predecessor.
CREATE OR REPLACE FUNCTION exchange_assessment_lease_claim(
  p_run_id bigint, p_lease_owner text, p_ttl_seconds integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE
SET search_path=pg_catalog,public AS $$
DECLARE v_lease exchange_assessment_leases%ROWTYPE;
BEGIN
  IF p_lease_owner IS NULL OR octet_length(p_lease_owner) NOT BETWEEN 1 AND 128
     OR p_ttl_seconds NOT BETWEEN 5 AND 300 THEN
    RAISE EXCEPTION 'Invalid Exchange assessment lease' USING ERRCODE='BZ316', HINT='{"type":"invalidArguments"}';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM exchange_assessment_runs WHERE id=p_run_id AND state IN ('created','preflight','uploading','validating','processing','partial','blocked')) THEN
    RAISE EXCEPTION 'Exchange assessment run not found' USING ERRCODE='BZ317', HINT='{"type":"notFound"}';
  END IF;
  INSERT INTO exchange_assessment_leases(run_id,lease_owner,fencing_token,expires_at)
  VALUES(p_run_id,p_lease_owner,1,statement_timestamp()+make_interval(secs=>p_ttl_seconds))
  ON CONFLICT(run_id) DO UPDATE SET
    lease_owner=excluded.lease_owner,
    fencing_token=exchange_assessment_leases.fencing_token+1,
    expires_at=excluded.expires_at,
    updated_at=statement_timestamp()
  WHERE exchange_assessment_leases.expires_at<=statement_timestamp()
     OR exchange_assessment_leases.lease_owner=excluded.lease_owner
  RETURNING * INTO v_lease;
  IF NOT FOUND THEN RAISE EXCEPTION 'Exchange assessment lease is held' USING ERRCODE='BZ318', HINT='{"type":"stateMismatch"}'; END IF;
  RETURN to_jsonb(v_lease);
END;
$$;
