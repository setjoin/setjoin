-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V022: Spam auto-purge + per-mailbox retention overrides.

-- 1. Add per-mailbox purge override columns
ALTER TABLE mailboxes ADD COLUMN IF NOT EXISTS deleted_purge_days INT;
ALTER TABLE mailboxes ADD COLUMN IF NOT EXISTS spam_purge_days INT;

-- 2. Seed spam purge config (default 30 days, 0 = disable)
INSERT INTO system_config (key, value, description, updated_at)
VALUES ('spam_purge_days', '30',
        'Number of days before spam-tagged messages are permanently purged. 0 = disable.', now())
ON CONFLICT (key) DO NOTHING;

-- 3. purge_spam_messages: auto-delete spam-tagged messages older than configured days.
-- Mirrors purge_deleted_messages() but operates on the Spam tag instead of is_deleted.
CREATE OR REPLACE FUNCTION purge_spam_messages()
RETURNS INT AS $$
DECLARE
  v_row    RECORD;
  v_count  INT := 0;
  v_shared INT;
  v_purge_days INT;
  v_mb_purge_days INT;
BEGIN
  SELECT NULLIF((value #>> '{}')::INT, 0) INTO v_purge_days
  FROM system_config WHERE key = 'spam_purge_days';
  IF v_purge_days IS NULL THEN
    v_purge_days := 30;
  END IF;

  FOR v_row IN
    SELECT m.id, m.received_at, m.raw_ref, m.mailbox_id
    FROM messages m
    JOIN message_tags mt ON mt.message_id = m.id AND mt.received_at = m.received_at
    JOIN tags t ON t.id = mt.tag_id AND t.name = 'Spam'
    WHERE NOT m.is_deleted
      AND m.received_at < NOW() - (v_purge_days || ' days')::INTERVAL
  LOOP
    BEGIN
      -- Per-mailbox override: NULL = use global, 0 = skip this mailbox
      SELECT COALESCE(mb.spam_purge_days, v_purge_days) INTO v_mb_purge_days
      FROM mailboxes mb WHERE mb.id = v_row.mailbox_id;
      IF v_mb_purge_days = 0 THEN
        CONTINUE;
      END IF;
      IF v_row.received_at > NOW() - (v_mb_purge_days || ' days')::INTERVAL THEN
        CONTINUE;
      END IF;

      -- Deduplication-safe blob cleanup
      SELECT COUNT(*) INTO v_shared
      FROM messages
      WHERE raw_ref = v_row.raw_ref
        AND (id != v_row.id OR received_at != v_row.received_at);

      IF v_shared = 0 THEN
        INSERT INTO orphaned_message_blobs(raw_ref)
        VALUES (v_row.raw_ref)
        ON CONFLICT DO NOTHING;
      END IF;

      DELETE FROM messages
      WHERE id = v_row.id AND received_at = v_row.received_at;

      v_count := v_count + 1;
    EXCEPTION WHEN OTHERS THEN
      -- Held messages raise BZ015 from trg_messages_hold_check; skip.
      CONTINUE;
    END;
  END LOOP;

  RETURN v_count;
END;
$$ LANGUAGE plpgsql;

-- 4. Register pg_cron job (runs daily at 03:15)
-- [pg_cron→Go cron worker] SELECT cron.schedule(
--   'purge-spam-messages',
--   '15 3 * * *',
--   $$ SELECT purge_spam_messages(); $$
-- ) WHERE NOT EXISTS (
--   SELECT 1 FROM cron.job WHERE jobname = 'purge-spam-messages'
-- );
