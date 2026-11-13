-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Schema 002: Directory connectors — per-identity-source configuration.
-- One row per configured identity source (Active Directory, local PG, custom LDAP).
CREATE TABLE directory_connectors (
    id              BIGSERIAL   PRIMARY KEY,
    connector_type  TEXT        NOT NULL CHECK (connector_type IN ('ad','local','ldap')),
    name            TEXT        NOT NULL,
    enabled         BOOL        NOT NULL DEFAULT TRUE,
    -- TRIAGE FENCE (D-AUTHSERVER-SQL--ARCHIVE-006, 2026-09): this column is
    -- the one sibling WITHOUT an encrypt-at-rest contract — its comment invites
    -- storing bind_password and other directory credentials as plaintext
    -- JSONB. No writer ever shipped, so no exposure exists, but any live
    -- successor of this table MUST hold secrets only as cryptokey AES-256-GCM
    -- _enc envelopes (like every sibling secret column and signing_keys) and
    -- must treat a missing/unopenable credential as a loud error, never a
    -- soft-skip. Do not cite this archived shape as credential-storage
    -- precedent.
    config          JSONB       NOT NULL DEFAULT '{}',   -- host, port, bind_dn, base_dn, etc.
    attribute_map   JSONB       NOT NULL DEFAULT '{}',   -- external_attr → local_field mapping
    sync_cursor     TEXT,                                -- last synced cursor (e.g., uSNChanged for AD)
    sync_interval_s INT         NOT NULL DEFAULT 900,    -- 15 min default
    last_sync_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX dir_connectors_type_idx ON directory_connectors(connector_type);
