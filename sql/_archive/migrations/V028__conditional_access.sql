-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V028: Conditional Access Engine — policy tables, geo tiers, managed devices, device_registry trust_tier.
-- Adds feature toggle + 5 default disabled policies.

-- Mirror conditional access tables from authserver schema
CREATE TABLE IF NOT EXISTS conditional_access_policies (
    id          BIGSERIAL   PRIMARY KEY,
    priority    INT         NOT NULL DEFAULT 0,
    name        TEXT        NOT NULL,
    description TEXT        NOT NULL DEFAULT '',
    enabled     BOOL        NOT NULL DEFAULT TRUE,
    scope_type  TEXT        NOT NULL DEFAULT 'global'
                            CHECK (scope_type IN ('global', 'user', 'group')),
    scope_target TEXT       NOT NULL DEFAULT '',
    conditions  JSONB       NOT NULL DEFAULT '{}',
    actions     JSONB       NOT NULL DEFAULT '{"action":"allow"}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS ca_policies_priority_unique_idx
    ON conditional_access_policies (priority) WHERE enabled;

CREATE INDEX IF NOT EXISTS ca_policies_priority_idx ON conditional_access_policies (priority ASC);

CREATE TABLE IF NOT EXISTS managed_devices (
    device_hash      TEXT        PRIMARY KEY,
    user_id          BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_name      TEXT        NOT NULL DEFAULT '',
    os_type          TEXT        NOT NULL DEFAULT ''
                                  CHECK (os_type IN ('', 'ios', 'android', 'macos', 'windows', 'linux')),
    os_version       TEXT        NOT NULL DEFAULT '',
    enrolled_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_checkin_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    compliance_status TEXT       NOT NULL DEFAULT 'compliant'
                                  CHECK (compliance_status IN ('compliant', 'non_compliant', 'unknown'))
);

CREATE INDEX IF NOT EXISTS managed_devices_user_idx ON managed_devices (user_id);

CREATE TABLE IF NOT EXISTS geo_country_tiers (
    country_code TEXT PRIMARY KEY CHECK (length(country_code) = 2 AND country_code = upper(country_code)),
    tier         TEXT NOT NULL DEFAULT 'low'
                 CHECK (tier IN ('low', 'medium', 'high', 'critical')),
    reason       TEXT NOT NULL DEFAULT '',
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Seed country tiers
INSERT INTO geo_country_tiers (country_code, tier, reason) VALUES
    ('KP', 'critical', 'OFAC comprehensive sanctions (DPRK)'),
    ('IR', 'critical', 'OFAC comprehensive sanctions (Iran)'),
    ('CU', 'critical', 'OFAC comprehensive sanctions (Cuba)'),
    ('SY', 'critical', 'OFAC comprehensive sanctions (Syria)'),
    ('RU', 'high', 'Sectoral sanctions + elevated cyber threat (Russia)'),
    ('CN', 'high', 'Elevated cyber threat (China)'),
    ('BY', 'high', 'Sanctions + cyber threat (Belarus)'),
    ('VE', 'high', 'Sectoral sanctions (Venezuela)'),
    ('MM', 'high', 'Sanctions (Myanmar)'),
    ('SD', 'high', 'Sanctions (Sudan)')
ON CONFLICT (country_code) DO NOTHING;

-- Feature toggle (disabled by default)
INSERT INTO feature_toggles (key, enabled) VALUES ('feature.conditional_access', FALSE)
ON CONFLICT (key) DO NOTHING;

-- Default policies (all disabled — admins configure before enabling)
INSERT INTO conditional_access_policies (priority, name, description, enabled, scope_type, conditions, actions) VALUES
(10, 'Block critical countries', 'Block authentication from critical-risk countries', FALSE, 'global',
 '{"geo_risk_tier":"critical"}',
 '{"action":"block","reason":"Authentication from critical-risk country is blocked"}'),
(20, 'Step-up high-risk + unknown device', 'Require MFA when signing in from high-risk country with unknown device', FALSE, 'global',
 '{"geo_risk_tier":"high","device_trust":"unknown"}',
 '{"action":"step_up","reason":"MFA required for high-risk country sign-in with unknown device","methods":["totp","webauthn"]}'),
(30, 'Step-up risky device', 'Require MFA when using a risky device', FALSE, 'global',
 '{"device_trust":"risky"}',
 '{"action":"step_up","reason":"MFA required for unrecognized device","methods":["totp","webauthn","push"]}'),
(40, 'Block medium IP risk + critical country', 'Block when medium IP reputation from critical country', FALSE, 'global',
 '{"ip_reputation":"medium","geo_risk_tier":"critical"}',
 '{"action":"block","reason":"Suspicious IP from critical-risk country"}'),
(50, 'Notify high IP risk', 'Send admin alert when high IP risk score detected', FALSE, 'global',
 '{"ip_reputation":"high"}',
 '{"action":"notify","reason":"High IP risk score detected","channels":["admin_alert","audit"]}')
ON CONFLICT DO NOTHING;

-- Add trust_tier to device_registry
ALTER TABLE device_registry
    ADD COLUMN IF NOT EXISTS trust_tier TEXT NOT NULL DEFAULT 'unknown'
    CHECK (trust_tier IN ('managed', 'known', 'unknown', 'risky'));
