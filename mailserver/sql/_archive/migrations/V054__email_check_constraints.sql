-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V054__email_check_constraints.sql
-- Adds CHECK constraints for email format, non-empty names, and domain format.
-- All constraints are added as NOT VALID first, then validated, to avoid
-- locking issues with existing data.

-- ============================================================================
-- 1a — users.email CHECK constraint
-- ============================================================================
ALTER TABLE users ADD CONSTRAINT users_email_check
  CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
  NOT VALID;
ALTER TABLE users VALIDATE CONSTRAINT users_email_check;

-- ============================================================================
-- 1b — aliases.email CHECK + case-insensitive UNIQUE
-- ============================================================================

-- Drop the case-sensitive unique constraint (implicit index from UNIQUE on column)
ALTER TABLE aliases DROP CONSTRAINT IF EXISTS aliases_email_key;

-- Add case-insensitive unique index (same pattern as users_email_lower_idx)
CREATE UNIQUE INDEX IF NOT EXISTS aliases_email_lower_idx ON aliases(lower(email));

-- Add format CHECK
ALTER TABLE aliases ADD CONSTRAINT aliases_email_check
  CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
  NOT VALID;
ALTER TABLE aliases VALIDATE CONSTRAINT aliases_email_check;

-- ============================================================================
-- 1c — contacts.emails JSONB CHECK
-- ============================================================================
-- contacts_emails_check: PostgreSQL CHECK constraints cannot use subqueries,
-- so we only enforce that emails is a JSON array at the constraint level.
-- Deep validation (non-null addresses) is enforced in the application layer.
ALTER TABLE contacts ADD CONSTRAINT contacts_emails_check CHECK (
  emails IS NULL OR jsonb_typeof(emails) = 'array'
) NOT VALID;
ALTER TABLE contacts VALIDATE CONSTRAINT contacts_emails_check;

-- ============================================================================
-- 1d — Non-empty CHECKs for name/display_name/username columns
-- ============================================================================

ALTER TABLE departments ADD CONSTRAINT departments_name_check
  CHECK (name <> '')
  NOT VALID;
ALTER TABLE departments VALIDATE CONSTRAINT departments_name_check;

ALTER TABLE folders ADD CONSTRAINT folders_name_check
  CHECK (name <> '')
  NOT VALID;
ALTER TABLE folders VALIDATE CONSTRAINT folders_name_check;

ALTER TABLE tags ADD CONSTRAINT tags_name_check
  CHECK (name <> '')
  NOT VALID;
ALTER TABLE tags VALIDATE CONSTRAINT tags_name_check;

ALTER TABLE users ADD CONSTRAINT users_username_check
  CHECK (username <> '')
  NOT VALID;
ALTER TABLE users VALIDATE CONSTRAINT users_username_check;

ALTER TABLE users ADD CONSTRAINT users_display_name_check
  CHECK (display_name <> '')
  NOT VALID;
ALTER TABLE users VALIDATE CONSTRAINT users_display_name_check;

-- ============================================================================
-- 1e — domains.name format CHECK
-- ============================================================================
ALTER TABLE domains ADD CONSTRAINT domains_name_check
  CHECK (name ~* '^([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}$')
  NOT VALID;
ALTER TABLE domains VALIDATE CONSTRAINT domains_name_check;
