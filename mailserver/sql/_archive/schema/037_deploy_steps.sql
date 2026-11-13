-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- 037_deploy_steps.sql — HA Deployment wizard step persistence.
-- Each step of the multi-step deployment wizard is recorded here so progress
-- survives gateway restarts. Steps are upserted on each transition.
CREATE TABLE IF NOT EXISTS deployment_steps (
  step_name     TEXT    PRIMARY KEY,
  status        TEXT    NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending','running','done','failed')),
  output        TEXT,
  error         TEXT,
  started_at    TIMESTAMPTZ,
  completed_at  TIMESTAMPTZ
);
