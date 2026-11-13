-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- System config: key-value store for all server settings.
-- Sensitive values (passwords, keys, keytabs) stored AES-encrypted.
CREATE TABLE system_config (
  key             TEXT        PRIMARY KEY,
  value           JSONB       NOT NULL,
  encrypted       BOOL        NOT NULL DEFAULT FALSE,
  description     TEXT,
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_by      BIGINT      REFERENCES users(id) ON DELETE SET NULL
);

-- Example keys (inserted by first-run wizard):
--   identity_source      : "local" | "ad" | "ldap"
--   auth_ldap_bind       : {host, port, use_tls, bind_dn_template, ...}
--   auth_kerberos        : {enabled, spn, realm, kdc, keytab_enc}  <- keytab encrypted
--   auth_saml            : {enabled, idp_metadata_url, sp_entity_id, ...}
--   auth_oidc            : {enabled, provider, tenant_id, client_id, ...}
--   ad_config            : {host, port, bind_dn, base_dn, page_size, sync_interval_s}
--   ad_last_usn          : 12345   <- USNChanged watermark for incremental sync
--   minio_config         : {endpoint, bucket, access_key, secret_key_enc}
--   smtp_relay           : {host, port, use_tls, username, password_enc}
--   spam_threshold       : 5.0
--   kms_provider         : "env" | "aws_kms" | "vault" | "file"
--   antiphish.name_similarity_threshold  : 0.85  (pg_trgm threshold for display-name fuzzy matching)
--   antiphish.protected_domains          : []    (JSON array of high-value domains for lookalike detection)
-- Note: The master encryption key is sourced externally (env var / KMS),
-- never stored in this table. See docs/SECURITY.md.

-- Crash events: append-only audit of crashes and recovery actions.
CREATE TABLE crash_events (
  id              BIGSERIAL   PRIMARY KEY,
  occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  component       TEXT        NOT NULL,  -- 'postgresql','gateway','patroni','minio'
  severity        TEXT        NOT NULL CHECK (severity IN ('warn','error','fatal')),
  description     TEXT        NOT NULL,
  previous_state  JSONB,
  recovery_action TEXT,
  recovered_at    TIMESTAMPTZ,
  admin_notified  BOOL        NOT NULL DEFAULT FALSE,
  notes           TEXT
);

-- Append-only enforcement: only admin_notified may be updated.
CREATE OR REPLACE FUNCTION trg_crash_events_immutable() RETURNS TRIGGER AS $$
BEGIN
  IF NEW.admin_notified IS DISTINCT FROM OLD.admin_notified THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'crash_events is append-only except for admin_notified'
    USING ERRCODE = 'BZ016', HINT = '{"type":"append_only","table":"crash_events"}';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER crash_events_no_update
  BEFORE UPDATE OR DELETE ON crash_events
  FOR EACH ROW EXECUTE FUNCTION trg_crash_events_immutable();

-- Health check history: rolling window of component health status.
CREATE TABLE health_history (
  id              BIGSERIAL   PRIMARY KEY,
  checked_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  check_name      TEXT        NOT NULL,
  status          TEXT        NOT NULL CHECK (status IN ('ok','warn','error')),
  value           NUMERIC,
  threshold       NUMERIC,
  details         TEXT CHECK (length(details) <= 4000)
);

CREATE INDEX health_history_name_idx ON health_history(check_name, checked_at DESC);
-- Keep only 7 days of health history (Go cron worker prunes the rest)

-- Auth methods: admin-configurable enable/disable and priority for the gateway auth chain.
CREATE TABLE auth_methods (
  id          BIGSERIAL PRIMARY KEY,
  slug        TEXT NOT NULL UNIQUE,
  name        TEXT NOT NULL,
  enabled     BOOL NOT NULL DEFAULT FALSE,
  priority    INT NOT NULL DEFAULT 0,
  config_json JSONB NOT NULL DEFAULT '{}',
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO auth_methods (slug, name, enabled, priority, config_json) VALUES
  ('jwt_bearer', 'JWT Bearer Token', TRUE, 10, '{}'),
  ('kerberos',   'Kerberos / SPNEGO', FALSE, 20, '{}'),
  ('saml',       'SAML 2.0', FALSE, 30, '{}'),
  ('oidc',       'OpenID Connect', FALSE, 40, '{}'),
  ('webauthn',   'WebAuthn / FIDO2', FALSE, 50, '{}')
ON CONFLICT (slug) DO NOTHING;

CREATE INDEX auth_methods_priority_idx ON auth_methods(priority) WHERE enabled = TRUE;

-- NOTIFY trigger: fires on auth method changes so the gateway chain can live-reload
CREATE OR REPLACE FUNCTION trg_auth_methods_notify() RETURNS TRIGGER AS $$
BEGIN
  PERFORM pg_notify('config_changed',
    json_build_object('key', 'auth_methods', 'slug', COALESCE(NEW.slug, OLD.slug),
                      'enabled', COALESCE(NEW.enabled, OLD.enabled))::text);
  RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_auth_methods_notify
  AFTER INSERT OR UPDATE OR DELETE ON auth_methods
  FOR EACH ROW EXECUTE FUNCTION trg_auth_methods_notify();

-- Health alerts: tracks alert state to suppress duplicate notifications.
CREATE TABLE health_alerts (
  check_name      TEXT        PRIMARY KEY,
  alert_sent_at   TIMESTAMPTZ,
  suppressed      BOOL        NOT NULL DEFAULT FALSE,
  acknowledged_at TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
