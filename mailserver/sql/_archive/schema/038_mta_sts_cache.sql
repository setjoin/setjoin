-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- 038_mta_sts_cache.sql — LOGGED MTA-STS policy cache.
-- Survives restarts: fetched policies are persisted and loaded into
-- an in-memory map on startup. Warm cache = no HTTPS fetch on restart.
CREATE TABLE IF NOT EXISTS mta_sts_policies (
  domain      TEXT        PRIMARY KEY,
  policy_json JSONB       NOT NULL,
  fetched_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
