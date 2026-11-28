-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V006: Add jmap_email_set_create for Email/set create support.
-- This function was added to sql/reducers/jmap_email.sql in the main codebase.
-- For existing deployments, apply this migration to add the function.

\i ../reducers/jmap_email.sql
