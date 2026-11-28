-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Schema 001: Extensions needed by auth server.
-- Run inside the shared PostgreSQL cluster; must be idempotent.
CREATE EXTENSION IF NOT EXISTS pgcrypto;
