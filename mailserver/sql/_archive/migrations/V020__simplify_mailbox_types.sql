-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Simplify mailbox types: retain 'personal', 'distribution', 'shared'.
-- 'resource' → personal + resource_type IS NOT NULL
-- 'journal' → module config, not a mailbox type
-- NOTE: 'distribution' is required by deliver() group expansion and SCIM provisioning.
-- NOTE: 'shared' is required by shared-mailbox delegate access.

-- 1. Update obsolete types (resource, journal) to 'personal'
UPDATE mailboxes SET type = 'personal' WHERE type NOT IN ('personal','distribution','shared');

-- 2. Set is_primary = FALSE for mailboxes with no owning user
UPDATE mailboxes SET is_primary = FALSE WHERE user_id IS NULL AND is_primary AND type = 'personal';

-- 3. Drop CHECK, re-add with allowed types
ALTER TABLE mailboxes DROP CONSTRAINT IF EXISTS mailboxes_type_check;
ALTER TABLE mailboxes ADD CONSTRAINT mailboxes_type_check
  CHECK (type IN ('personal','distribution','shared'));
