-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Schema 006: SAML Service Provider registrations (multi-IdP support).
-- Extracted from gateway env config into a database table.
CREATE TABLE saml_sp_registrations (
    id              BIGSERIAL   PRIMARY KEY,
    idp_entity_id   TEXT        NOT NULL,
    idp_metadata_url TEXT,
    idp_sso_url     TEXT        NOT NULL,
    idp_cert_enc    BYTEA       NOT NULL,                -- AES-256-GCM encrypted IdP signing cert
    sp_entity_id    TEXT        NOT NULL,
    sp_acs_url      TEXT        NOT NULL,
    attribute_map   JSONB       NOT NULL DEFAULT '{}',
    jit_enabled     BOOL        NOT NULL DEFAULT FALSE,   -- just-in-time provisioning
    group_attribute TEXT        DEFAULT 'memberOf',       -- SAML attribute for group membership
    group_mappings  JSONB,                                -- map IdP group names to local group IDs
    enabled         BOOL        NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX saml_sp_idp_idx ON saml_sp_registrations(idp_entity_id);
