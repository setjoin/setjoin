-- Boot-only organization configuration update. The caller holds the candidate
-- rows FOR UPDATE, authenticates every existing envelope before any change,
-- and supplies freshly sealed EK01 JSON. Invoker privileges, never SET ROLE.
-- Connector and named-key batches remain separate transactions, as in Go.
CREATE OR REPLACE FUNCTION boot_config_secret_apply(p_changes JSONB)
RETURNS INTEGER AS $$
DECLARE
  v_change RECORD;
  v_updated INTEGER := 0;
  v_count INTEGER;
BEGIN
  FOR v_change IN
    SELECT * FROM jsonb_to_recordset(p_changes)
      AS change(key TEXT, value JSONB, replace BOOLEAN)
  LOOP
    IF v_change.replace THEN
      UPDATE system_config
         SET value = v_change.value, encrypted = TRUE, updated_at = now()
       WHERE key = v_change.key;
    ELSE
      UPDATE system_config
         SET encrypted = TRUE, updated_at = now()
       WHERE key = v_change.key;
    END IF;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    v_updated := v_updated + v_count;
  END LOOP;
  RETURN v_updated;
END;
$$ LANGUAGE plpgsql;
