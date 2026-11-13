-- V137__seed_spam_ml_detectors_toggle.sql — arch review #A5: wire the
-- built-but-unused shared/spam detector suite into live delivery as
-- ADDITIVE signal, behind a new DEFAULT-OFF toggle.
--
-- No schema change — the seam lives entirely in Go (internal/smtp
-- deliver()). This migration only seeds the gating row: off (the
-- registryDefault, and this seeded row) means detectorSignal() never runs
-- and the live scoring path is byte-for-byte what it is today.

INSERT INTO feature_toggles (key, enabled, description) VALUES
  ('feature.spam_ml_detectors', false,
   'Runs the shared/spam deterministic detector suite (sender-mismatch, forged-recipients, mixed-charset, fake-HTML) as ADDITIVE signal alongside the live per-user FTRL model. Seeded OFF — enable + tune (thresholds, false-positive validation on real mail) is a separate follow-up.')
ON CONFLICT (key) DO NOTHING;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (137, now()) ON CONFLICT DO NOTHING;
