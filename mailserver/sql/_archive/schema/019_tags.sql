-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- 019_tags.sql: Gmail-style multi-label tag system.
-- Tags replace the old single-folder-per-message model.
-- System tags (Inbox, Sent, Drafts, Trash, Spam, Starred, Snoozed,
-- Scheduled, Important) are created automatically per mailbox.
-- User tags are free-form labels with optional nesting.
-- Exclusive groups enforce mutual exclusivity.

CREATE TABLE IF NOT EXISTS tags (
    id              BIGSERIAL   PRIMARY KEY,
    mailbox_id      BIGINT      NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    parent_id       BIGINT      REFERENCES tags(id) ON DELETE CASCADE,

    name            TEXT        NOT NULL,
    color           TEXT,
    icon            TEXT,
    sort_order      INT         NOT NULL DEFAULT 0,

    tag_type        TEXT        NOT NULL DEFAULT 'user'
                        CHECK (tag_type IN ('system','user','smart')),

    exclusive_group TEXT
                        CHECK (exclusive_group IN ('location','snooze')),

    is_default      BOOL        NOT NULL DEFAULT FALSE,

    -- timer_type is the V025 side-channel; later DROPPED by V080 (A6 — Scheduled
    -- Actions). Kept here because V025 (which runs after V001) depends on the
    -- column existing; V080 removes it after the backfill, so a fresh load ends
    -- with the column gone.
    timer_type      TEXT
                        CHECK (timer_type IN ('snooze','schedule','undo_send')),

    total_count     INT         NOT NULL DEFAULT 0 CHECK (total_count >= 0),
    unread_count    INT         NOT NULL DEFAULT 0 CHECK (unread_count >= 0),
    size_bytes      BIGINT      NOT NULL DEFAULT 0 CHECK (size_bytes >= 0),

    imap_expose     BOOL        NOT NULL DEFAULT TRUE,
    imap_name       TEXT,

    imap_uid_validity   BIGINT  NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::BIGINT),
    imap_uid_next       BIGINT  NOT NULL DEFAULT 1,
    imap_modseq         BIGINT  NOT NULL DEFAULT 1,

    jmap_state      BIGINT      NOT NULL DEFAULT 0,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (mailbox_id, name)
);

CREATE INDEX IF NOT EXISTS tags_mailbox_idx    ON tags(mailbox_id);
CREATE INDEX IF NOT EXISTS tags_parent_idx     ON tags(parent_id) WHERE parent_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS tags_exclusive_idx  ON tags(mailbox_id, exclusive_group) WHERE exclusive_group IS NOT NULL;
CREATE INDEX IF NOT EXISTS tags_type_idx       ON tags(mailbox_id, tag_type);
CREATE INDEX IF NOT EXISTS tags_default_idx    ON tags(mailbox_id) WHERE is_default;

-- Per-user IMAP visibility settings
CREATE TABLE IF NOT EXISTS user_imap_settings (
    user_id             BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    expose_all          BOOL NOT NULL DEFAULT FALSE,
    exposed_tag_ids     BIGINT[] NOT NULL DEFAULT '{}',
    folder_separator    TEXT NOT NULL DEFAULT '/',
    show_subscribed_only BOOL NOT NULL DEFAULT TRUE
);

-- Add jmap_tag_state to mailboxes for JMAP tag state tracking.
ALTER TABLE mailboxes ADD COLUMN IF NOT EXISTS jmap_tag_state BIGINT NOT NULL DEFAULT 0;

-- Create default system tags for a newly provisioned mailbox.
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

-- Auto-create system tags when a mailbox is inserted.
CREATE OR REPLACE FUNCTION trg_mailbox_tag_after_insert() RETURNS TRIGGER AS $$
BEGIN
    PERFORM create_system_tags(NEW.id);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS mailbox_create_tags ON mailboxes;
DROP TRIGGER IF EXISTS mailbox_create_tags ON mailboxes;
CREATE TRIGGER mailbox_create_tags
    AFTER INSERT ON mailboxes
    FOR EACH ROW EXECUTE FUNCTION trg_mailbox_tag_after_insert();

-- Apply configurable quota defaults from system_config when a new mailbox is
-- created — but ONLY for columns the caller left at the schema default. An
-- explicit quota_bytes / sending_quota_day (e.g. admin CSV import or
-- provision_account's p_quota_bytes) must survive; this trigger fills in the
-- org default only when the INSERT did not override it. (Previously it
-- unconditionally clobbered any caller-supplied quota — a silent data-loss bug.)
CREATE OR REPLACE FUNCTION trg_mailbox_quota_defaults() RETURNS TRIGGER AS $$
DECLARE
    v_default_quota  BIGINT;
    v_default_send   INT;
BEGIN
    SELECT (value #>> '{}')::BIGINT INTO v_default_quota
    FROM system_config WHERE key = 'default_quota_bytes';
    SELECT (value #>> '{}')::INT INTO v_default_send
    FROM system_config WHERE key = 'default_sending_quota_day';

    UPDATE mailboxes SET
        -- Only override the storage default when the caller left it untouched
        -- (= the column's own DEFAULT). An explicit value is preserved.
        quota_bytes       = CASE WHEN NEW.quota_bytes = 53687091200
                                 THEN COALESCE(v_default_quota, 53687091200)
                                 ELSE NEW.quota_bytes END,
        sending_quota_day = CASE WHEN NEW.sending_quota_day = 500
                                 THEN COALESCE(v_default_send, 500)
                                 ELSE NEW.sending_quota_day END
    WHERE id = NEW.id;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS mailbox_quota_defaults ON mailboxes;
DROP TRIGGER IF EXISTS mailbox_quota_defaults ON mailboxes;
CREATE TRIGGER mailbox_quota_defaults
    AFTER INSERT ON mailboxes
    FOR EACH ROW EXECUTE FUNCTION trg_mailbox_quota_defaults();
