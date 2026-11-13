-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Folders: nested folder tree per mailbox. Roles map to JMAP/IMAP well-known names.
CREATE TABLE folders (
  id              BIGSERIAL   PRIMARY KEY,
  mailbox_id      BIGINT      NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
  parent_id       BIGINT      REFERENCES folders(id) ON DELETE CASCADE,
  name            TEXT        NOT NULL,
  role            TEXT        CHECK (role IN ('inbox','trash','spam','junk','sent','drafts','archive','templates','outbox')),
  path            TEXT        NOT NULL, -- materialized: 'INBOX/Work/Projects'
  sort_order      INT         NOT NULL DEFAULT 0,
  total_count     INT         NOT NULL DEFAULT 0 CHECK (total_count >= 0),
  unread_count    INT         NOT NULL DEFAULT 0 CHECK (unread_count >= 0),
  size_bytes      BIGINT      NOT NULL DEFAULT 0 CHECK (size_bytes >= 0),

  -- IMAP compatibility
  imap_uid_validity   BIGINT  NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::BIGINT),
  imap_uid_next       BIGINT  NOT NULL DEFAULT 1,
  imap_modseq         BIGINT  NOT NULL DEFAULT 1,

  subscribed      BOOL        NOT NULL DEFAULT TRUE,  -- IMAP SUBSCRIBE state

  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

  UNIQUE (mailbox_id, path)
);

CREATE INDEX folders_mailbox_idx    ON folders(mailbox_id);
CREATE INDEX folders_parent_idx     ON folders(parent_id) WHERE parent_id IS NOT NULL;
CREATE INDEX folders_role_idx       ON folders(mailbox_id, role) WHERE role IS NOT NULL;

-- Create system folders for a newly provisioned mailbox.
CREATE OR REPLACE FUNCTION create_system_folders(p_mailbox_id BIGINT) RETURNS VOID AS $$
DECLARE
  v_uid_validity BIGINT := EXTRACT(EPOCH FROM now())::BIGINT;
  v_type         TEXT;
BEGIN
  SELECT type INTO v_type FROM mailboxes WHERE id = p_mailbox_id;

  -- Journal mailboxes only need Inbox
  IF v_type = 'journal' THEN
    INSERT INTO folders (mailbox_id, name, role, path, sort_order, imap_uid_validity) VALUES
      (p_mailbox_id, 'Inbox', 'inbox', 'INBOX', 0, v_uid_validity);
    RETURN;
  END IF;

  INSERT INTO folders (mailbox_id, name, role, path, sort_order, imap_uid_validity) VALUES
    (p_mailbox_id, 'Inbox',     'inbox',    'INBOX',              0,  v_uid_validity),
    (p_mailbox_id, 'Sent',      'sent',     'INBOX/Sent',         10, v_uid_validity),
    (p_mailbox_id, 'Drafts',    'drafts',   'INBOX/Drafts',       20, v_uid_validity),
    (p_mailbox_id, 'Trash',     'trash',    'INBOX/Trash',        30, v_uid_validity),
    (p_mailbox_id, 'Spam',      'spam',     'INBOX/Spam',         40, v_uid_validity),
    (p_mailbox_id, 'Archive',   'archive',  'INBOX/Archive',      50, v_uid_validity),
    (p_mailbox_id, 'Templates', 'templates','INBOX/Templates',    60, v_uid_validity);
END;
$$ LANGUAGE plpgsql;

-- Auto-create system folders when a mailbox is inserted.
CREATE OR REPLACE FUNCTION trg_mailbox_after_insert() RETURNS TRIGGER AS $$
BEGIN
  PERFORM create_system_folders(NEW.id);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER mailbox_create_folders
  AFTER INSERT ON mailboxes
  FOR EACH ROW EXECUTE FUNCTION trg_mailbox_after_insert();
