-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V070: Seed the feature.assist toggle (B4 — AI assist), default off.
-- The assist provider package (shared/assist) lands in a later wave; this row
-- gates the compose Assist panel and ops copilot, and is read by the
-- effective-capabilities resolver. Default off per design decision R3.
INSERT INTO feature_toggles (key, enabled, description) VALUES
  ('feature.assist', FALSE, 'AI assist: compose draft/polish/translate and admin ops copilot (pluggable provider)')
ON CONFLICT (key) DO NOTHING;
