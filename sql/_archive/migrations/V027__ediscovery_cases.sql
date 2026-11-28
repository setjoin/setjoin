-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V027__ediscovery_cases.sql
-- eDiscovery case management: group related searches into cases,
-- track case lifecycle (active/closed), and link searches to cases.

CREATE TABLE ediscovery_cases (
  id              BIGSERIAL   PRIMARY KEY,
  name            TEXT        NOT NULL,
  description     TEXT,
  status          TEXT        NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active','closed')),
  created_by      BIGINT      NOT NULL REFERENCES users(id) ON DELETE SET NULL,
  closed_at       TIMESTAMPTZ,
  closed_by       BIGINT      REFERENCES users(id) ON DELETE SET NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ediscovery_cases_status_idx ON ediscovery_cases(status);

-- Add case_id to existing ediscovery_searches table
ALTER TABLE ediscovery_searches ADD COLUMN IF NOT EXISTS case_id BIGINT
  REFERENCES ediscovery_cases(id) ON DELETE SET NULL;

CREATE INDEX ediscovery_searches_case_idx ON ediscovery_searches(case_id);
