CREATE OR REPLACE FUNCTION office_provider_policy_set(
  p_user_id bigint,p_provider_id text,p_enabled boolean,p_draining boolean,
  p_entitlement_state text,p_build_id text,p_config jsonb DEFAULT '{}'::jsonb,
  p_reason text DEFAULT NULL
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
BEGIN
  RAISE EXCEPTION 'legacy Office policy mutation is retired' USING ERRCODE='BZ324',
    HINT='{"type":"stateMismatch","detail":"use configure, qualify, activate, drain, or remove"}';
END;
$$;
SELECT apply_worker_ownership('office_provider_policy_set(bigint,text,boolean,boolean,text,text,jsonb,text)'::regprocedure);
