-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Schema 015: Rate limit counters — unlogged for speed.
-- Shared with gateway; IF NOT EXISTS avoids conflict.
CREATE UNLOGGED TABLE IF NOT EXISTS rate_limit_counters (
    key             TEXT        PRIMARY KEY,
    count           INT         NOT NULL DEFAULT 0,
    window_start    TIMESTAMPTZ NOT NULL DEFAULT now(),
    blocked_until   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS rate_limit_block_idx ON rate_limit_counters(blocked_until)
    WHERE blocked_until IS NOT NULL;
