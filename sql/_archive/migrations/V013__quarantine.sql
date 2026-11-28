-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V013: Quarantine system schema + seed Quarantined tag per mailbox
\i ../schema/033_quarantine.sql

-- Seed Quarantined system tag for all existing mailboxes
INSERT INTO tags (mailbox_id, name, tag_type, exclusive_group, sort_order, imap_expose, imap_uid_validity)
SELECT m.id, 'Quarantined', 'system', 'quarantine', 900, FALSE, EXTRACT(EPOCH FROM now())::BIGINT
FROM mailboxes m
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE mailbox_id = m.id AND name = 'Quarantined');
