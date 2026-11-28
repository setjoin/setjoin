-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V030: Add journal_report_ref column to journal_queue for storing
-- the MinIO blob reference to the structured MIME journal report.
-- The Go side (InboundServer.maybeJournal) generates the RFC-compliant
-- multipart/mixed report and stores it in MinIO under the journal/ prefix;
-- this column tracks the blob key for retrieval and audit.

ALTER TABLE journal_queue ADD COLUMN IF NOT EXISTS journal_report_ref VARCHAR;
