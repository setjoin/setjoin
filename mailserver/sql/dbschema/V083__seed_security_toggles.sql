-- V083: seed every DEFAULT-OFF security-family toggle row explicitly.
--
-- toggle.RequireSeeded (startup, both servers) now refuses boot when any of
-- these rows is missing — a drifted DB must fail loudly instead of running
-- with silently-defaulted security gates (the split-brain read of
-- feature.conditional_access — IsEnabled absent→ENGAGED in policy.go vs
-- IsEnabledDefault(false)→OFF in device_trust_gate.go — was live).
-- ON CONFLICT DO NOTHING: existing installs keep whatever they deliberately
-- flipped; only truly-absent rows are created, OFF.

INSERT INTO feature_toggles (key, enabled, description) VALUES
  ('feature.conditional_access',       false, 'Conditional Access policy engine (CA-1). Security-family: seeded OFF; flip deliberately.'),
  ('feature.device_trust_enforcement', false, 'Device-trust enforcement chain (DeviceClaim + RequireDeviceCompliance). Security-family: seeded OFF.'),
  ('feature.device_lockdown',          false, 'CA-2 strict device gate (403 unenrolled/unbound). Security-family: seeded OFF.'),
  ('dengbao.sod_mode',                 false, '等保三级 Separation-of-Duties regime. Security-family: seeded OFF; flip only via the gated endpoint.'),
  ('feature.cae_runtime',              false, 'Per-request CA re-evaluation + live session revocation. Security-family: seeded OFF.'),
  ('feature.token_binding',            false, 'Sender-constrained access tokens (DPoP / mTLS cnf). Security-family: seeded OFF.'),
  ('feature.user_risk',                false, 'Local deterministic user-risk scorer + Risk claim. Security-family: seeded OFF.')
ON CONFLICT (key) DO NOTHING;

INSERT INTO schema_migrations (version, applied_at) VALUES (83, now()) ON CONFLICT DO NOTHING;
