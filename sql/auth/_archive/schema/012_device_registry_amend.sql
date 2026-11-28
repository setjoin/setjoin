-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Schema 012 addendum: Add trust_tier column to device_registry for conditional access.
-- Managed > known > unknown > risky. Default is 'unknown' for existing records.

ALTER TABLE device_registry
    ADD COLUMN IF NOT EXISTS trust_tier TEXT NOT NULL DEFAULT 'unknown'
    CHECK (trust_tier IN ('managed', 'known', 'unknown', 'risky'));
