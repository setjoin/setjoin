-- Mailbox Lifecycle & Retention authority: mailbox_purge_blockers.

CREATE OR REPLACE FUNCTION mailbox_purge_blockers(p_mailbox_id bigint)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_domain record; v_result jsonb:='[]'::jsonb; v_domain_result jsonb;
BEGIN
  FOR v_domain IN SELECT * FROM mailbox_retention_domains WHERE enabled ORDER BY domain_key LOOP
    BEGIN
      IF v_domain.contract_version<>1 OR to_regprocedure(format('%I(bigint)',v_domain.blocker_function)) IS NULL THEN
        v_result:=v_result||jsonb_build_array(jsonb_build_object(
          'domain',v_domain.domain_key,'kind','domain_contract_unavailable','count',1));
        CONTINUE;
      END IF;
      EXECUTE format('SELECT %I($1)',v_domain.blocker_function)
        INTO v_domain_result USING p_mailbox_id;
      IF v_domain_result IS NULL OR jsonb_typeof(v_domain_result)<>'array' THEN
        v_result:=v_result||jsonb_build_array(jsonb_build_object(
          'domain',v_domain.domain_key,'kind','domain_result_invalid','count',1));
      ELSE
        SELECT COALESCE(jsonb_agg(value||jsonb_build_object('domain',v_domain.domain_key)),'[]'::jsonb)
          INTO v_domain_result FROM jsonb_array_elements(v_domain_result);
        v_result:=v_result||v_domain_result;
      END IF;
    EXCEPTION WHEN OTHERS THEN
      v_result:=v_result||jsonb_build_array(jsonb_build_object(
        'domain',v_domain.domain_key,'kind','domain_evaluation_failed','count',1));
    END;
  END LOOP;
  RETURN v_result;
END $$;

INSERT INTO mailbox_retention_domains(domain_key,blocker_function,contract_version,owner_component)
VALUES('core','mailbox_core_retention_blockers',1,'mailbox_lifecycle')
ON CONFLICT(domain_key) DO NOTHING;

ALTER FUNCTION mailbox_purge_blockers(bigint) OWNER TO setjoin_worker;
