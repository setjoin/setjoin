-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Blobs: content-addressed store of unique file content in MinIO.
-- Same file attached to 1000 messages = 1 blob row, 1 MinIO object.
CREATE TABLE blobs (
  sha256          TEXT        PRIMARY KEY,
  minio_ref       TEXT        NOT NULL UNIQUE, -- MinIO path: bucket/sha256[0:2]/sha256
  size_bytes      BIGINT      NOT NULL,
  content_type    TEXT,
  ref_count       INT         NOT NULL DEFAULT 1 CHECK (ref_count >= 0),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Attachment metadata: one row per attachment per message.
CREATE TABLE message_attachments (
  id              BIGSERIAL   PRIMARY KEY,
  message_id      BIGINT      NOT NULL,
  received_at     TIMESTAMPTZ NOT NULL,        -- needed for partition lookup
  blob_sha256     TEXT        NOT NULL REFERENCES blobs(sha256),
  filename        TEXT,
  content_id      TEXT,                        -- for inline images (cid: refs)
  content_type    TEXT        NOT NULL,
  disposition     TEXT        NOT NULL DEFAULT 'attachment'
                    CHECK (disposition IN ('attachment','inline')),
  size_bytes      BIGINT      NOT NULL,
  FOREIGN KEY (message_id, received_at) REFERENCES messages(id, received_at) ON DELETE CASCADE
);

CREATE INDEX attachments_message_idx   ON message_attachments(message_id, received_at);
CREATE INDEX attachments_blob_idx      ON message_attachments(blob_sha256);
CREATE INDEX attachments_cid_idx       ON message_attachments(content_id) WHERE content_id IS NOT NULL;

-- Decrement ref_count when an attachment row is deleted.
CREATE OR REPLACE FUNCTION trg_attachment_deleted() RETURNS TRIGGER AS $$
BEGIN
  UPDATE blobs SET ref_count = ref_count - 1 WHERE sha256 = OLD.blob_sha256;
  RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER attachment_blob_refcount
  AFTER DELETE ON message_attachments
  FOR EACH ROW EXECUTE FUNCTION trg_attachment_deleted();

-- Enqueue blob for deferred cleanup when ref_count drops to 0.
-- Uses a 5-minute delay to guard against rollback-after-decrement races.
CREATE OR REPLACE FUNCTION trg_blob_refcount_zero() RETURNS TRIGGER AS $$
BEGIN
  IF NEW.ref_count = 0 THEN
    INSERT INTO blob_cleanup_queue (blob_sha256, scheduled_at)
    VALUES (NEW.sha256, now())
    ON CONFLICT (blob_sha256) DO UPDATE SET scheduled_at = now();
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER blob_refcount_cleanup
  AFTER UPDATE OF ref_count ON blobs
  FOR EACH ROW EXECUTE FUNCTION trg_blob_refcount_zero();
