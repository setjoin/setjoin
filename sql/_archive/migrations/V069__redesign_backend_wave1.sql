-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V069: Redesign backend wave 1 — B1 snooze set-path, B2 scheduled-send
-- listing/cancel, B3 tag-on-send. Reloads the affected reducers idempotently.
-- No schema changes: message_snooze/jmap_email_submission_* reuse the existing
-- tags, message_tags, and timer pipeline (process_message_timers, V005/V025).

-- B1: snooze set-path reducer (new file).
\i ../reducers/message_snooze.sql

-- B2 + B3: submission read reducers + sendAt/onSuccessUpdateEmail set path.
\i ../reducers/jmap_email_submission.sql
