-- Frozen Go's admin TLS writes (admin.TLSPolicyHandler.PutTLSPolicy and admin.TLSHandler.SetConfig)
-- as reducers. Go commits each statement on its own (policy: three upserts, then the
-- config_changed notification; config: the upsert batch, then the audit row); here each is one
-- transaction. Authority is the caller's security.write grant, checked by the gateway before
-- the call; system_config is global, so there is no tenant column to filter.
CREATE OR REPLACE FUNCTION rust_mailsec_tls_policy_set(p_enforce jsonb, p_skip jsonb, p_mode jsonb)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
BEGIN
 INSERT INTO system_config (key, value, updated_at) VALUES ('outbound_tls_enforce_domains', p_enforce, now())
  ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now();
 INSERT INTO system_config (key, value, updated_at) VALUES ('outbound_tls_skip_domains', p_skip, now())
  ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now();
 INSERT INTO system_config (key, value, updated_at) VALUES ('outbound_tls_global_mode', p_mode, now())
  ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now();
 PERFORM pg_notify('config_changed', '{"key":"outbound_tls_policy","enabled":true}');
 RETURN true;
END;
$$;

-- ConfigStore.BatchSet for tls_* keys (values already sealed by the caller where secret) and the
-- tls_config_set audit row Go writes after the commit. An empty key list writes only the audit row.
CREATE OR REPLACE FUNCTION rust_mailsec_tls_config_set(
  p_keys text[], p_values text[], p_encrypted boolean[], p_actor bigint, p_ip text, p_after jsonb, p_notes text)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
BEGIN
 INSERT INTO system_config (key, value, encrypted, description, updated_at)
  SELECT t.k, t.v::jsonb, t.e, 'TLS configuration', now()
    FROM unnest(p_keys, p_values, p_encrypted) AS t(k, v, e)
  ON CONFLICT (key) DO UPDATE
    SET value = EXCLUDED.value, encrypted = EXCLUDED.encrypted, updated_at = now();
 PERFORM audit_write(p_actor, 'tls_config_set', 'system_config', NULL, NULL, p_after,
                     NULLIF(p_ip, '')::inet, p_notes, 'core');
 RETURN true;
END;
$$;
