-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Schema 016: Used SAML assertions — replay detection (OASIS Core §2.5.1).
-- On ACS, assertion ID is INSERTed; duplicate causes ON CONFLICT DO NOTHING.
-- The handler checks for existing row before inserting to detect replay.
--
-- IF NOT EXISTS: in the shared cluster the mailserver compliance schema
-- (mailserver/sql/schema/015_compliance.sql) also creates used_saml_assertions
-- and loads first, so a bare CREATE TABLE aborted with "relation already exists".
-- Only assertion_id is read/written by the SAML ACS handler
-- (authserver/internal/handlers/auth.go), so the timestamp-column name
-- difference between the two definitions is immaterial.
CREATE TABLE IF NOT EXISTS used_saml_assertions (
    assertion_id TEXT PRIMARY KEY,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
