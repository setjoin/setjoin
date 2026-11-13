-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- 038: Feature toggle system (Phase 30) — shared between auth server and mail gateway.
-- Enables live-reload config with no-restart toggle via PostgreSQL NOTIFY.

-- IF NOT EXISTS: feature_toggles is shared with the auth server, whose schema
-- (authserver/sql/schema/014_feature_toggles_extend.sql) defensively creates the
-- same base table and, in the shared cluster, loads before this migration (V015).
-- The two definitions share identical base columns; this file remains the
-- canonical one that installs the NOTIFY trigger and the full default seed set.
CREATE TABLE IF NOT EXISTS feature_toggles (
  key         TEXT        PRIMARY KEY,
  enabled     BOOL        NOT NULL DEFAULT TRUE,
  description TEXT,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- NOTIFY trigger fires pg_notify('config_changed', ...) on any toggle change.
-- The Go toggle package subscribes to this channel for < 1ms hot-reload.
CREATE OR REPLACE FUNCTION trg_feature_notify() RETURNS TRIGGER AS $$
BEGIN
  PERFORM pg_notify('config_changed',
    json_build_object('key', NEW.key, 'enabled', NEW.enabled)::text);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_feature_notify
  AFTER INSERT OR UPDATE ON feature_toggles
  FOR EACH ROW EXECUTE FUNCTION trg_feature_notify();

-- Seed production-safe defaults.  All existing features are enabled.
-- Auth extension features (Kerberos, SAML, OIDC, AD sync) are disabled by default
-- and can be enabled via env var override or admin UI.
INSERT INTO feature_toggles (key, enabled, description) VALUES
  ('feature.kerberos',   FALSE, 'Kerberos / SPNEGO authentication'),
  ('feature.saml',       FALSE, 'SAML 2.0 service provider'),
  ('feature.oidc',       FALSE, 'OpenID Connect relying party'),
  ('feature.ad_sync',    FALSE, 'Active Directory sync engine'),
  ('feature.imap',       TRUE,  'IMAP4rev2 server on ports 143 and 993'),
  ('feature.smtp_inbound',  TRUE, 'SMTP inbound MTA on port 25'),
  ('feature.smtp_submission', TRUE, 'SMTP submission MSA on port 587'),
  ('feature.ldap_gal',   TRUE,  'LDAP GAL server on port 389'),
  ('feature.caldav',     TRUE,  'CalDAV bridge'),
  ('feature.carddav',    TRUE,  'CardDAV bridge'),
  ('feature.require_mfa', TRUE, 'Require MFA for all users'),
  ('feature.auth_log_bcrypt',       TRUE,  'Log bcrypt authentication events'),
  ('feature.auth_log_app_password', TRUE,  'Log app password authentication events'),
  ('feature.auth_log_kerberos',     TRUE,  'Log Kerberos/SPNEGO authentication events'),
  ('feature.auth_log_jwt',          TRUE,  'Log JWT issuance events'),
  ('feature.auth_log_basic',        FALSE, 'Log HTTP Basic auth events (high volume — off by default)'),
  ('feature.link_protect_rewrite',      TRUE,  'Master toggle: rewrite URLs in inbound email bodies through /link-protect proxy'),
  ('feature.link_protect_safebrowsing', TRUE,  'Google Safe Browsing API v5 scanner for link protection'),
  ('feature.link_protect_spamhaus',     TRUE,  'Spamhaus DBL scanner for link protection'),
  ('feature.link_protect_strict_mode',  FALSE, 'Treat unknown verdicts as malicious (block instead of warn)'),
  ('feature.dnssec',                    TRUE,  'Enable DNSSEC validation for DNS lookups and TLSA record generation'),
  ('feature.dane',                      TRUE,  'Enable DANE (RFC 7672) outbound SMTP TLSA validation after STARTTLS'),
  ('feature.cert_rollout',              FALSE, 'Enable 2×TLSA rolling rollout for cert changes (default: stable key reuse via TLS_AUTOCERT_KEY_FILE)'),
  ('feature.antiphish_display_name',   TRUE,  'Display-name spoofing detector (fuzzy match against internal users)'),
  ('feature.antiphish_lookalike',      TRUE,  'Lookalike domain detector (homoglyph + Levenshtein against protected domains)'),
  ('feature.antiphish_contact_graph',  TRUE,  'Contact graph impersonation detector (novel sender with known display name)'),
  ('feature.antiphish_strict_mode',    FALSE, 'Treat Warn as Reject for all anti-phishing detectors'),
  ('feature.journaling',             TRUE,  'BCC-style journaling: archive a copy of every message to a designated journal mailbox')
ON CONFLICT (key) DO NOTHING;
