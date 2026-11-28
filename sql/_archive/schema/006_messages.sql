-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Messages: partitioned by received_at for performance.
-- Raw RFC 5322 bytes live in MinIO; we store envelope + parsed fields here.
CREATE TABLE messages (
  id              BIGSERIAL       NOT NULL,
  mailbox_id      BIGINT          NOT NULL REFERENCES mailboxes(id),
  folder_id       BIGINT          NOT NULL,  -- primary tag ID for IMAP backward compat (synced by trigger)

  -- RFC 5322 envelope
  message_id      TEXT            NOT NULL,   -- Message-ID header value
  subject         TEXT,
  from_addr       TEXT            NOT NULL,
  from_name       TEXT,
  to_addrs        JSONB           NOT NULL DEFAULT '[]',  -- [{email,name},...]
  cc_addrs        JSONB           NOT NULL DEFAULT '[]',
  bcc_addrs       JSONB           NOT NULL DEFAULT '[]',
  reply_to        TEXT,
  in_reply_to     TEXT,
  references_hdr  TEXT,

  -- Content
  body_text       TEXT,
  body_html       TEXT,

  -- Full-text search vectors (updated by trigger)
  body_tsv        TSVECTOR,
  subject_tsv     TSVECTOR,
  from_tsv        TSVECTOR,

  -- Size
  size_bytes      BIGINT          NOT NULL DEFAULT 0,
  has_attachments BOOL            NOT NULL DEFAULT FALSE,

  -- IMAP flags
  is_read         BOOL            NOT NULL DEFAULT FALSE,
  is_flagged      BOOL            NOT NULL DEFAULT FALSE,
  is_answered     BOOL            NOT NULL DEFAULT FALSE,
  is_draft        BOOL            NOT NULL DEFAULT FALSE,
  is_deleted      BOOL            NOT NULL DEFAULT FALSE, -- soft delete; purged by expunge

  -- Outlook-style categories/labels
  categories      TEXT[]          NOT NULL DEFAULT '{}',

  -- Threading (computed from Message-ID + References chain)
  thread_id       TEXT            NOT NULL,

  -- IMAP
  imap_uid        BIGINT,
  imap_modseq     BIGINT,

  -- Security scoring
  spam_score      REAL,
  spam_headers    JSONB,
  spf_result      TEXT CHECK (spf_result IN ('pass','fail','softfail','neutral','none','permerror','temperror')),
  dkim_result     TEXT CHECK (dkim_result IN ('pass','fail','none','policy','neutral','temperror','permerror')),
  dmarc_result    TEXT CHECK (dmarc_result IN ('pass','fail','none','temperror','permerror')),

  -- Raw message ref (MinIO object path — full RFC 5322 bytes)
  raw_ref         TEXT            NOT NULL,

  -- Litigation hold snapshot (copied from mailbox at delivery; immutable thereafter)
  held            BOOL            NOT NULL DEFAULT FALSE,

  -- Dates
  sent_at         TIMESTAMPTZ,
  received_at     TIMESTAMPTZ     NOT NULL DEFAULT now(),

  PRIMARY KEY (id, received_at)
) PARTITION BY RANGE (received_at);

-- Partitions: one per month. pg_cron creates future partitions automatically.
-- Seeds for first year — migration creates these.
CREATE TABLE messages_default PARTITION OF messages DEFAULT; -- catch-all until first partition

-- Full-text search trigger (skip if app.skip_fts session var is set)
CREATE OR REPLACE FUNCTION trg_messages_tsv() RETURNS TRIGGER AS $$
BEGIN
  IF current_setting('app.skip_fts', true) = 'true' THEN
    RETURN NEW;
  END IF;
  NEW.body_tsv    := to_tsvector('simple', coalesce(NEW.body_text, ''));
  NEW.subject_tsv := to_tsvector('simple', coalesce(NEW.subject, ''));
  NEW.from_tsv    := to_tsvector('simple',
                       coalesce(NEW.from_addr, '') || ' ' || coalesce(NEW.from_name, ''));
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER messages_tsv_update
  BEFORE INSERT OR UPDATE OF body_text, subject, from_addr, from_name
  ON messages FOR EACH ROW EXECUTE FUNCTION trg_messages_tsv();

-- Litigation hold: prevent DELETE on held messages
CREATE OR REPLACE FUNCTION trg_messages_hold_check() RETURNS TRIGGER AS $$
BEGIN
  IF OLD.held THEN
    RAISE EXCEPTION 'Cannot delete message % — mailbox is under litigation hold', OLD.id
      USING ERRCODE = 'BZ015', HINT = jsonb_build_object('type', 'litigation_hold', 'message_id', OLD.id)::TEXT;
  END IF;
  RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER messages_hold_check
  BEFORE DELETE ON messages
  FOR EACH ROW EXECUTE FUNCTION trg_messages_hold_check();

-- Indexes (on each partition automatically via inheritance)
CREATE INDEX messages_mailbox_folder_idx ON messages(mailbox_id, folder_id, received_at DESC);
CREATE INDEX messages_thread_idx         ON messages(mailbox_id, thread_id);
CREATE INDEX messages_message_id_idx     ON messages(message_id);
CREATE INDEX messages_is_read_idx        ON messages(mailbox_id, folder_id) WHERE NOT is_read;
CREATE INDEX messages_is_flagged_idx     ON messages(mailbox_id) WHERE is_flagged;
CREATE INDEX messages_body_tsv_idx       ON messages USING GIN(body_tsv);
CREATE INDEX messages_subject_tsv_idx    ON messages USING GIN(subject_tsv);
CREATE INDEX messages_from_tsv_idx       ON messages USING GIN(from_tsv);
CREATE INDEX messages_categories_idx     ON messages USING GIN(categories);
CREATE INDEX messages_received_at_idx    ON messages(received_at DESC);
CREATE INDEX messages_held_idx           ON messages(mailbox_id) WHERE held;
CREATE INDEX messages_is_deleted_idx     ON messages(mailbox_id, folder_id) WHERE is_deleted;
CREATE INDEX messages_sent_at_idx        ON messages(sent_at) WHERE sent_at IS NOT NULL;
CREATE INDEX messages_spam_score_idx     ON messages(spam_score) WHERE spam_score IS NOT NULL;
CREATE INDEX messages_from_addr_idx      ON messages(from_addr);
CREATE INDEX messages_in_reply_to_idx    ON messages(in_reply_to) WHERE in_reply_to IS NOT NULL;
CREATE INDEX messages_references_idx     ON messages(references_hdr) WHERE references_hdr IS NOT NULL;
