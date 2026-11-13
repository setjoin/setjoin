-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Schema 022: Country risk tiers — maps ISO 3166-1 alpha-2 country codes to
-- risk tiers for conditional access geo-tier policies.
-- Generalises the binary BLOCK_COUNTRIES env var into four tiers.
-- Seed data covers OFAC-sanctioned and high-risk jurisdictions.

CREATE TABLE geo_country_tiers (
    country_code TEXT PRIMARY KEY CHECK (length(country_code) = 2 AND country_code = upper(country_code)),
    tier         TEXT NOT NULL DEFAULT 'low'
                 CHECK (tier IN ('low', 'medium', 'high', 'critical')),
    reason       TEXT NOT NULL DEFAULT '',
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Seed: critical-tier countries (comprehensive sanctions / state sponsors of terrorism)
INSERT INTO geo_country_tiers (country_code, tier, reason) VALUES
    ('KP', 'critical', 'OFAC comprehensive sanctions (DPRK)'),
    ('IR', 'critical', 'OFAC comprehensive sanctions (Iran)'),
    ('CU', 'critical', 'OFAC comprehensive sanctions (Cuba)'),
    ('SY', 'critical', 'OFAC comprehensive sanctions (Syria)')
ON CONFLICT (country_code) DO NOTHING;

-- Seed: high-tier countries (sectoral sanctions / elevated cyber threat)
INSERT INTO geo_country_tiers (country_code, tier, reason) VALUES
    ('RU', 'high', 'Sectoral sanctions + elevated cyber threat (Russia)'),
    ('CN', 'high', 'Elevated cyber threat (China)'),
    ('BY', 'high', 'Sanctions + cyber threat (Belarus)'),
    ('VE', 'high', 'Sectoral sanctions (Venezuela)'),
    ('MM', 'high', 'Sanctions (Myanmar)'),
    ('SD', 'high', 'Sanctions (Sudan)')
ON CONFLICT (country_code) DO NOTHING;
