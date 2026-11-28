-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- 049_external_sender_flags.sql — External sender warning banner columns + feature toggles.
-- Depends on: 006_messages.sql, 038_feature_toggles.sql
--
-- Adds per-message annotation columns that the SMTP inbound pipeline populates
-- and the JMAP Email/get response exposes. Webmail renders banners based on these
-- flags via the EmailAnnotations framework component.
--
-- Three-tier severity model (Stage 1.6):
--   1. First-time sender — green/neutral pill, informational
--   2. External sender — amber banner, always shown
--   3. Name-spoofing — amber banner + red pill, escalated warning

-- vote_response: the X-Mailserver-Vote-Response header value extracted at delivery.
-- Existing Go code already passes this; add the column so it is persisted.
ALTER TABLE messages ADD COLUMN IF NOT EXISTS vote_response TEXT;

-- is_external: TRUE when the sender's domain is NOT a local domain (domains WHERE is_local = TRUE).
ALTER TABLE messages ADD COLUMN IF NOT EXISTS is_external BOOL NOT NULL DEFAULT FALSE;

-- sender_display_name: the display name parsed from the From header.
-- Used for name-spoofing detection in the webmail UI.
ALTER TABLE messages ADD COLUMN IF NOT EXISTS sender_display_name TEXT;

-- is_name_spoof: TRUE when sender_display_name matches an internal user's display_name
-- but the sender domain is external (classic CEO-fraud pattern).
ALTER TABLE messages ADD COLUMN IF NOT EXISTS is_name_spoof BOOL NOT NULL DEFAULT FALSE;

-- is_first_time: TRUE when this is the first message from this from_addr to this mailbox.
-- Computed in the deliver() reducer; defaults to TRUE for safety.
ALTER TABLE messages ADD COLUMN IF NOT EXISTS is_first_time BOOL NOT NULL DEFAULT TRUE;

-- Seed feature toggles so they are enabled by default.
-- Admins can disable individual tiers via the admin console or SQL.
INSERT INTO feature_toggles (key, enabled, description) VALUES
  ('feature.external_sender_warn',       TRUE, 'Show amber warning banner on messages from external senders'),
  ('feature.external_sender_name_spoof', TRUE, 'Escalate banner to red pill when display name matches internal user'),
  ('feature.external_sender_first_time', TRUE, 'Show green first-time-sender notice for unknown senders')
ON CONFLICT (key) DO NOTHING;
