-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- 037: Migration jobs table for self-service IMAP/ICS/VCF import (Phase 18)
CREATE TABLE migration_jobs (
  id                BIGSERIAL   PRIMARY KEY,
  user_id           BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  source_type       TEXT        NOT NULL,       -- imap, ics, vcf, or pipe-delimited combinations e.g. 'imap|ics|vcf'
  source_config_enc BYTEA,                      -- AES-256-GCM encrypted IMAP config; NULLed on completion
  target_mailbox_id BIGINT      REFERENCES mailboxes(id) ON DELETE SET NULL,
  conflict_strategy TEXT        NOT NULL DEFAULT 'skip'
                                  CHECK (conflict_strategy IN ('skip','overwrite','rename')),
  status            TEXT        NOT NULL DEFAULT 'pending'
                                  CHECK (status IN ('pending','testing','fetching','importing','paused','completed','cancelled','failed')),
  progress          JSONB       NOT NULL DEFAULT '{}',
  error_log         JSONB       NOT NULL DEFAULT '[]',
  resume_cursor     TEXT,
  started_at        TIMESTAMPTZ,
  completed_at      TIMESTAMPTZ,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX migration_one_active_per_user
  ON migration_jobs(user_id)
  WHERE status = ANY(ARRAY['pending','testing','fetching','importing','paused']);

CREATE INDEX migration_jobs_status_idx ON migration_jobs(status);

-- Add parent_event_uid to link RECURRENCE-ID exception events to their master
ALTER TABLE calendar_events ADD COLUMN IF NOT EXISTS parent_event_uid TEXT;
