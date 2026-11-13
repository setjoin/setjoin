-- V258__seed_spam_model_batch_load_toggle.sql — owner decision A6 (SPAM-007):
-- per-delivery-batch model loading for the per-user FTRL spam classifier.
--
-- No schema change — the seam lives entirely in Go (internal/smtp
-- applyPerUserSpam -> internal/spam BatchScorer). This migration only seeds
-- the gating row, mirroring the V137 pattern: the seeded value matches the
-- compiled registry default so the admin feature-toggles surface shows an
-- explicit stored row instead of a defaulted absence.
--
-- ON is the OWNER-DIRECTED DEFAULT: one model load per bounded scoring batch
-- (50 scored deliveries) instead of load/score/discard per recipient per
-- message. THE TRADE IS MEMORY: with feature.ml_spam on, models for the batch
-- are held resident (~24 MB per user model at DefaultFeatureSize 2^20 x 3
-- float64 tables, up to batch-size models per active inbound connection), and
-- a model trained mid-batch is seen by scoring only after the batch boundary.
-- OFF restores the exact previous per-call behavior. Both the startup
-- resolution and every enabling config_changed flip emit the
-- memory-footprint warning log; the admin spam dashboard surfaces the current
-- resident-model count/bytes.

INSERT INTO feature_toggles (key, enabled, description) VALUES
  ('feature.spam_model_batch_load', true,
   'Loads each user''s FTRL spam model once per bounded delivery-scoring batch (50 scored deliveries) instead of per recipient per message. DEFAULT ON (owner decision A6) — WARNING: increases memory footprint (batch models held resident, ~24 MB per user model); disable to restore per-message loads.')
ON CONFLICT (key) DO NOTHING;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (258, now()) ON CONFLICT DO NOTHING;
