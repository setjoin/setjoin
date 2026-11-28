-- V111: seed the GAL-CardDAV collection toggle (read-only org directory at
-- /carddav/gal/). ON by default — parity with feature.ldap_gal; exposes only
-- what /directory already shows every authenticated user.
INSERT INTO feature_toggles (key, enabled, description)
VALUES ('feature.gal_carddav', true,
        'Org directory (GAL) as a read-only CardDAV addressbook at /carddav/gal/ — Apple Contacts / Outlook directory sync')
ON CONFLICT (key) DO NOTHING;

-- ── Schema migration record ──────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (111, now())
    ON CONFLICT (version) DO NOTHING;
