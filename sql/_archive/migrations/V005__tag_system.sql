-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V005: Multi-folder tag system (Gmail label model).
-- Adds tags table, message_tags junction, snooze/schedule timers,
-- and backfills existing folder data into the tag system.

-- 1. Create the tags table and message_tags junction.
\i ../schema/019_tags.sql
\i ../schema/030_message_tags.sql
\i ../schema/031_snooze.sql

-- Load tag-aware utility functions (depends on tags table above).
\i ../reducers/utils_tags.sql

-- 2. Seed system tags for all existing mailboxes.
DO $$
DECLARE
    v_mb RECORD;
BEGIN
    FOR v_mb IN SELECT id FROM mailboxes LOOP
        PERFORM create_system_tags(v_mb.id);
    END LOOP;
END;
$$;

-- 3. Backfill: map existing folder_id to corresponding tag_id by name/mailbox.
INSERT INTO message_tags (message_id, received_at, tag_id, added_by, is_primary)
SELECT m.id, m.received_at, t.id, 'migration', TRUE
FROM messages m
JOIN folders f ON f.id = m.folder_id
JOIN tags t ON t.mailbox_id = f.mailbox_id AND t.name = f.name
WHERE NOT m.is_deleted
ON CONFLICT DO NOTHING;

-- 4. pg_cron: process snoozed messages every minute.
-- [pg_cron→Go cron worker] SELECT cron.schedule('process-snoozed', '* * * * *',
--     $$ SELECT count(*) FROM process_snoozed_messages(); $$
-- );

-- 5. pg_cron: process scheduled sends every minute.
-- [pg_cron→Go cron worker] SELECT cron.schedule('process-scheduled', '* * * * *',
--     $$ SELECT count(*) FROM process_scheduled_messages(); $$
-- );

-- 6. pg_cron: create next month's message_tags partitions.
-- [pg_cron→Go cron worker] SELECT cron.schedule('create-message-tags-partitions', '0 0 25 * *',
--     $job$
--     DO $inner$DECLARE
--         v_next   DATE := date_trunc('month', now() + interval '1 month');
--         v_end    DATE := v_next + interval '1 month';
--         v_suffix TEXT := to_char(v_next, 'YYYY_MM');
--     BEGIN
--         EXECUTE format(
--             'CREATE TABLE IF NOT EXISTS message_tags_%s PARTITION OF message_tags
--              FOR VALUES FROM (%L) TO (%L)',
--             v_suffix, v_next, v_end);
--     END$inner$;
--     $job$
-- );

-- 7. Update tag counters for all existing messages (one-time).
DO $$
DECLARE
    v_tag RECORD;
BEGIN
    FOR v_tag IN SELECT id FROM tags LOOP
        UPDATE tags SET
            total_count  = (SELECT COUNT(*) FROM message_tags WHERE tag_id = v_tag.id),
            unread_count = (SELECT COUNT(*) FROM message_tags mt
                            JOIN messages m ON m.id = mt.message_id AND m.received_at = mt.received_at
                            WHERE mt.tag_id = v_tag.id AND NOT m.is_read),
            size_bytes   = COALESCE((SELECT SUM(m.size_bytes) FROM message_tags mt
                            JOIN messages m ON m.id = mt.message_id AND m.received_at = mt.received_at
                            WHERE mt.tag_id = v_tag.id), 0)
        WHERE id = v_tag.id;
    END LOOP;
END;
$$;
