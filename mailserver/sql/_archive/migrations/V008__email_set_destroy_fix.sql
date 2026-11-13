-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V008: Fix jmap_email_set_destroy to actually delete emails and return string IDs.
-- Reload the updated reducer which includes the fixed destroy function.
\i ../reducers/jmap_email.sql
