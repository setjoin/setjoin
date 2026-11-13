-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V025: Link Protection — audit table and feature toggles (Stage 1.3)
-- Time-of-click URL rewriting with Safe Browsing API + Spamhaus DBL threat checking.

CREATE TABLE link_protect_audit (
  id          BIGSERIAL    PRIMARY KEY,
  url_hash    TEXT         NOT NULL,  -- SHA-256 hex of original URL
  verdict     TEXT         NOT NULL,  -- safe/malicious/unknown
  scanner     TEXT         NOT NULL,  -- scanner name (e.g. "safebrowsing", "spamhaus")
  message_id  BIGINT       NOT NULL,  -- FK to messages table
  mailbox_id  BIGINT       NOT NULL,  -- FK to mailboxes table
  client_ip   TEXT,                   -- clicker's IP address
  created_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Support audit queries: filter by date range, lookup by URL hash
CREATE INDEX idx_link_protect_audit_created_at ON link_protect_audit (created_at);
CREATE INDEX idx_link_protect_audit_url_hash   ON link_protect_audit (url_hash);

-- Feature toggles for per-scanner control and strict mode
INSERT INTO feature_toggles (key, enabled, description) VALUES
  ('feature.link_protect_rewrite',      TRUE,  'Master toggle: rewrite URLs in inbound email bodies through /link-protect proxy'),
  ('feature.link_protect_safebrowsing', TRUE,  'Google Safe Browsing API v5 scanner for link protection'),
  ('feature.link_protect_spamhaus',     TRUE,  'Spamhaus DBL scanner for link protection'),
  ('feature.link_protect_strict_mode',  FALSE, 'Treat unknown verdicts as malicious (block instead of warn)')
ON CONFLICT (key) DO NOTHING;
-- V025: Attachment sandbox configuration (Stage 1.4)
-- Per-domain sandbox settings + extended quarantined_messages reason_type.

ALTER TABLE domains ADD COLUMN IF NOT EXISTS sandbox_enabled  BOOL NOT NULL DEFAULT FALSE;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS sandbox_action   TEXT NOT NULL DEFAULT 'quarantine'
    CHECK (sandbox_action IN ('reject', 'quarantine'));
ALTER TABLE domains ADD COLUMN IF NOT EXISTS sandbox_file_types TEXT NOT NULL DEFAULT '*'
    CHECK (sandbox_file_types <> '');

ALTER TABLE quarantined_messages DROP CONSTRAINT IF EXISTS quarantined_messages_reason_type_check;
ALTER TABLE quarantined_messages ADD CONSTRAINT quarantined_messages_reason_type_check
    CHECK (reason_type IN ('virus', 'dlp', 'admin', 'sandbox'));

CREATE INDEX IF NOT EXISTS quarantined_sandbox_idx ON quarantined_messages(reason_type)
    WHERE reason_type = 'sandbox' AND released_at IS NULL AND rejected_at IS NULL;
-- V025: Message lifecycle — pinned_at, unified timer_type, process_message_timers
-- Depends on: Phase 17 tags, V007 compose features, pg_cron

-- 1. Add pinned_at column for pin-to-top feature
ALTER TABLE messages ADD COLUMN IF NOT EXISTS pinned_at TIMESTAMPTZ;

-- Partial index: only pinned rows are indexed
CREATE INDEX IF NOT EXISTS messages_pinned_idx
    ON messages(mailbox_id, pinned_at) WHERE pinned_at IS NOT NULL;

-- 2. Rename tags.timer to tags.timer_type and extend CHECK to include undo_send
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'tags' AND column_name = 'timer'
    ) THEN
        ALTER TABLE tags RENAME COLUMN timer TO timer_type;
    END IF;
END$$;

ALTER TABLE tags DROP CONSTRAINT IF EXISTS tags_timer_check;

ALTER TABLE tags ADD CONSTRAINT tags_timer_check
    CHECK (timer_type IN ('snooze','schedule','undo_send'));

-- 3. Update the create_system_tags function to use timer_type
CREATE OR REPLACE FUNCTION create_system_tags(p_mailbox_id BIGINT) RETURNS VOID AS $$
DECLARE
    v_uid_validity BIGINT := EXTRACT(EPOCH FROM now())::BIGINT;
    v_type         TEXT;
    v_inbox_id     BIGINT;
BEGIN
    SELECT type INTO v_type FROM mailboxes WHERE id = p_mailbox_id;

    IF v_type = 'journal' THEN
        INSERT INTO tags (mailbox_id, name, tag_type, exclusive_group, is_default, sort_order,
                          imap_uid_validity, imap_expose)
        VALUES (p_mailbox_id, 'Inbox', 'system', 'location', TRUE, 0, v_uid_validity, TRUE)
        ON CONFLICT (mailbox_id, name) DO NOTHING;
        RETURN;
    END IF;

    INSERT INTO tags (mailbox_id, name, tag_type, exclusive_group, is_default,
                      icon, color, sort_order, imap_uid_validity, imap_expose, imap_name)
    VALUES
        (p_mailbox_id, 'Inbox',     'system', 'location', TRUE,
         'inbox',    '#7C8DB5', 0,  v_uid_validity, TRUE,  NULL)
    ON CONFLICT (mailbox_id, name) DO NOTHING
    RETURNING id INTO v_inbox_id;

    INSERT INTO tags (mailbox_id, name, tag_type, exclusive_group,
                      icon, color, sort_order, imap_uid_validity, imap_expose, imap_name)
    VALUES
        (p_mailbox_id, 'Sent',      'system', 'location',
         'send',     '#5CB85C', 10, v_uid_validity, TRUE,  NULL),
        (p_mailbox_id, 'Drafts',    'system', 'location',
         'edit',     '#F0AD4E', 20, v_uid_validity, TRUE,  NULL),
        (p_mailbox_id, 'Trash',     'system', 'location',
         'delete',   '#D9534F', 30, v_uid_validity, TRUE,  '[Gmail]/Trash'),
        (p_mailbox_id, 'Spam',      'system', 'location',
         'warning',  '#D9534F', 40, v_uid_validity, TRUE,  '[Gmail]/Spam'),
        (p_mailbox_id, 'Starred',   'system', NULL,
         'star',     '#F5A623', 50, v_uid_validity, TRUE,  NULL),
        (p_mailbox_id, 'Snoozed',   'system', 'snooze',
         'clock',    '#9B59B6', 60, v_uid_validity, FALSE, NULL),
        (p_mailbox_id, 'Scheduled', 'system', 'snooze',
         'calendar', '#3498DB', 70, v_uid_validity, TRUE,  '[Gmail]/Scheduled'),
        (p_mailbox_id, 'Important', 'system', NULL,
         'priority', '#E74C3C', 80, v_uid_validity, FALSE, NULL),
        (p_mailbox_id, 'Muted',     'system', NULL,
         'volume_off', '#888888', 90, v_uid_validity, FALSE, NULL)
    ON CONFLICT (mailbox_id, name) DO NOTHING;

    UPDATE tags SET timer_type = 'snooze'   WHERE mailbox_id = p_mailbox_id AND name = 'Snoozed';
    UPDATE tags SET timer_type = 'schedule' WHERE mailbox_id = p_mailbox_id AND name = 'Scheduled';
END;
$$ LANGUAGE plpgsql;

-- 4. Replace separate cron jobs with unified process-message-timers
-- [pg_cron→Go cron worker] SELECT cron.unschedule('process-snoozed');
-- [pg_cron→Go cron worker] SELECT cron.unschedule('process-scheduled');
-- [pg_cron→Go cron worker] SELECT cron.schedule('process-message-timers', '* * * * *',
--     $$ SELECT count(*) FROM process_message_timers(); $$
-- );
-- V025: External sender warning banners (Stage 1.6).
-- Adds annotation columns to messages and seeds feature toggles.
\i ../schema/049_external_sender_flags.sql
