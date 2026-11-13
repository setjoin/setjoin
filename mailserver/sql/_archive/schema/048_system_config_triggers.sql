-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- 048: system_config CRUD functions + NOTIFY trigger.
-- Provides get/set accessors for the system_config key-value store
-- so the gateway can read/write config without raw SQL, and live-reload
-- on changes via PostgreSQL NOTIFY.

-- get_system_config(p_key TEXT DEFAULT NULL) -> JSONB
--   NULL (default): returns all keys as {"key1": value1, ...}
--   specific key:   returns that key's value as JSONB, or SQL NULL if missing
CREATE OR REPLACE FUNCTION get_system_config(p_key TEXT DEFAULT NULL)
RETURNS JSONB AS $$
DECLARE
  v_result JSONB;
BEGIN
  IF p_key IS NULL THEN
    SELECT jsonb_object_agg(key, value) INTO v_result FROM system_config;
    RETURN COALESCE(v_result, '{}'::JSONB);
  ELSE
    SELECT value INTO v_result FROM system_config WHERE key = p_key;
    RETURN v_result;
  END IF;
END;
$$ LANGUAGE plpgsql STABLE;

-- set_system_config(p_key TEXT, p_value JSONB, p_encrypted BOOL, p_updated_by BIGINT)
--   Upserts a config key.  The AFTER trigger fires pg_notify so the
--   gateway can hot-reload.  Returns the full row as a record.
CREATE OR REPLACE FUNCTION set_system_config(
  p_key        TEXT,
  p_value      JSONB,
  p_encrypted  BOOL   DEFAULT FALSE,
  p_updated_by BIGINT DEFAULT NULL
)
RETURNS SETOF system_config AS $$
BEGIN
  RETURN QUERY
    INSERT INTO system_config (key, value, encrypted, updated_by, updated_at)
    VALUES (p_key, p_value, p_encrypted, p_updated_by, now())
    ON CONFLICT (key) DO UPDATE SET
      value      = EXCLUDED.value,
      encrypted  = EXCLUDED.encrypted,
      updated_by = EXCLUDED.updated_by,
      updated_at = now()
    RETURNING *;
END;
$$ LANGUAGE plpgsql;

-- NOTIFY trigger: fires pg_notify('config_changed', ...) on any insert or update.
-- Follows the same pattern as trg_feature_notify and trg_auth_methods_notify.
CREATE OR REPLACE FUNCTION trg_system_config_notify() RETURNS TRIGGER AS $$
BEGIN
  PERFORM pg_notify('config_changed',
    json_build_object('key', NEW.key, 'encrypted', NEW.encrypted)::text);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_system_config_notify ON system_config;
CREATE TRIGGER trg_system_config_notify
  AFTER INSERT OR UPDATE ON system_config
  FOR EACH ROW EXECUTE FUNCTION trg_system_config_notify();
