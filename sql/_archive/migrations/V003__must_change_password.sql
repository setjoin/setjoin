-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V003: Add must_change_password flag to users table.
-- Allows admins to force a password change on next login.

ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOL NOT NULL DEFAULT FALSE;
