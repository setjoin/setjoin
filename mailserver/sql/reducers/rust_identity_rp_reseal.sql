-- #340 startup-only write side of the locked, audited-crypto reseal seam.
-- Caller holds these deployment-owned rows FOR UPDATE through crypto/COMMIT.
CREATE OR REPLACE FUNCTION rust_identity_rp_reseal(p_changes jsonb)
RETURNS integer LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_change jsonb;v_count integer:=0;
BEGIN
    FOR v_change IN SELECT value FROM jsonb_array_elements(p_changes) LOOP
        UPDATE system_config
           SET value=jsonb_set(value,'{client_secret}',v_change->'sealed'),encrypted=true,updated_at=now()
         WHERE key=v_change->>'key' AND key LIKE 'oidc_provider_%_config'
           AND value=v_change->'before' AND encrypted=(v_change->>'encrypted')::boolean;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'OIDC startup configuration changed during reseal'
                USING ERRCODE='BZ228',HINT='{"type":"identity_source_invalid"}';
        END IF;
        v_count:=v_count+1;
    END LOOP;
    RETURN v_count;
END;
$$;
