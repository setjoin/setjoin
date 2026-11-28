-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Schema 014: Feature toggle seeds for threat detection features.
-- All default to TRUE (gateable per-deployment via admin UI or env vars).
--
-- feature_toggles is shared between auth server and mail gateway. Its canonical
-- definition lives in mailserver/sql/schema/038_feature_toggles.sql, but in the
-- shared cluster that mailserver migration (V015) runs AFTER the authserver
-- migrations, so this seed previously aborted with "relation feature_toggles
-- does not exist". Defensively create the table (matching the 038 base columns)
-- so the authserver schema is self-sufficient regardless of load order; the
-- NOTIFY trigger and full seed set are still installed by 038 when it loads.
CREATE TABLE IF NOT EXISTS feature_toggles (
  key         TEXT        PRIMARY KEY,
  enabled     BOOL        NOT NULL DEFAULT TRUE,
  description TEXT,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO feature_toggles (key, enabled, description) VALUES
    ('feature.threat_feed',  TRUE, 'Spamhaus DROP threat feed blocking'),
    ('feature.geo_block',    TRUE, 'MaxMind GeoIP2 country-level geo-blocking'),
    ('feature.spray_detect', TRUE, 'Password spray attack detection'),
    ('feature.captcha',      TRUE, 'Math CAPTCHA challenge on repeated failures'),
    ('feature.tarpit',       TRUE, 'Connection delay for suspicious clients')
ON CONFLICT (key) DO NOTHING;
