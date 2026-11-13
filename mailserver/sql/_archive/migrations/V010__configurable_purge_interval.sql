-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V010: Make deleted-items auto-purge interval configurable via admin portal.

-- 1. Seed default purge interval (30 days)
INSERT INTO system_config (key, value, description, updated_at)
VALUES ('deleted_items_purge_days', '30',
        'Number of days before soft-deleted emails are permanently purged. 0 = disable auto-purge.', now())
ON CONFLICT (key) DO NOTHING;

-- 2. Update purge_deleted_messages() to read the configured interval
CREATE OR REPLACE FUNCTION purge_deleted_messages()
RETURNS INT AS $$
DECLARE
  v_row RECORD;
  v_count INT := 0;
  v_shared INT;
  v_purge_days INT;
BEGIN
  -- Read configured interval; default to 30 if missing or invalid
  SELECT NULLIF((value #>> '{}')::INT, 0) INTO v_purge_days
  FROM system_config WHERE key = 'deleted_items_purge_days';
  IF v_purge_days IS NULL THEN
    v_purge_days := 30;
  END IF;

  FOR v_row IN
    SELECT id, received_at, raw_ref, mailbox_id
    FROM messages
    WHERE is_deleted AND deleted_at < NOW() - (v_purge_days || ' days')::INTERVAL
  LOOP
    BEGIN
      -- Deduplication check
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
      CONTINUE;
    END;
  END LOOP;

  RETURN v_count;
END;
$$ LANGUAGE plpgsql;
