-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Remove archive mailbox type and archive_after_days column.
-- No code ever created rows with type='archive' or used archive_after_days,
-- so this is a safe DDL-only migration.
ALTER TABLE mailboxes DROP CONSTRAINT IF EXISTS mailboxes_type_check;
ALTER TABLE mailboxes ADD CONSTRAINT mailboxes_type_check
  CHECK (type IN ('personal','shared','resource','distribution','journal'));
ALTER TABLE mailboxes DROP COLUMN IF EXISTS archive_after_days;
