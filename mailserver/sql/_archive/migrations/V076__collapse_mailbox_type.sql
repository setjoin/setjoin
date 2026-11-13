-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V076: Collapse mailboxes.type to 'personal' only.
--
-- Background: prior to this migration, the type column encoded mailbox role
-- as 'personal', 'distribution', or 'shared'. However, role was already
-- driven by satellite tables: distribution groups via distribution_groups,
-- shared mailboxes via mailbox_delegates (user_id IS NULL), and rooms/equipment
-- via mailboxes.resource_type + calendars.resource_type. The type column was
-- redundant and brittle.
--
-- This migration:
--   1. Migrates all non-personal rows to 'personal' (their satellite rows
--      already carry the role — no data is lost).
--   2. Drops the stale mailboxes_type_check constraint (which allowed
--      'personal','distribution','shared' per V020__simplify_mailbox_types.sql).
--   3. Re-adds mailboxes_type_check allowing only 'personal'.
--
-- After this migration, role is derived via:
--   - distribution: EXISTS (SELECT 1 FROM distribution_groups WHERE mailbox_id = ...)
--   - resource (room/equipment): mailboxes.resource_type IS NOT NULL
--   - shared: user_id IS NULL AND EXISTS (SELECT 1 FROM mailbox_delegates WHERE mailbox_id = ...)
--   - personal: everything else
--
-- The derived role is available via mailbox_effective_type(p_mailbox_id)
-- (reducers/mailbox_effective_type.sql, added in Task 5 of this refactor).
--
-- This is idempotent: re-running on an already-migrated database is a no-op
-- (UPDATE WHERE type <> 'personal' affects 0 rows; DROP CONSTRAINT IF EXISTS
-- succeeds vacuously; ADD CONSTRAINT is idempotent if the constraint already
-- exists with the same definition).

-- 1. Migrate existing distribution/shared rows to personal.
--    Their satellite rows (distribution_groups, mailbox_delegates) remain intact.
UPDATE mailboxes SET type = 'personal' WHERE type <> 'personal';

-- 2. Drop the stale 3-value constraint from V020.
ALTER TABLE mailboxes DROP CONSTRAINT IF EXISTS mailboxes_type_check;

-- 3. Add the new personal-only constraint.
ALTER TABLE mailboxes ADD CONSTRAINT mailboxes_type_check
  CHECK (type IN ('personal'));
