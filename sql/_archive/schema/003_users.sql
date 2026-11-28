-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Users: identity records. Mail-specific data lives in mailboxes.
-- Supports built-in auth, AD/LDAP sync, Kerberos, SAML, OIDC.
CREATE TABLE users (
  id                      BIGSERIAL   PRIMARY KEY,
  username                TEXT        NOT NULL,
  domain_id               BIGINT      NOT NULL REFERENCES domains(id),
  email                   TEXT        NOT NULL,
  display_name            TEXT        NOT NULL,
  first_name              TEXT,
  last_name               TEXT,
  job_title               TEXT,
  phone                   TEXT,
  manager_id              BIGINT      REFERENCES users(id) ON DELETE SET NULL,
  department_id           BIGINT      REFERENCES departments(id) ON DELETE SET NULL,
	avatar_sha256           TEXT,                         -- FK to blobs added in 018_fk_and_extensions after blobs table exists

  -- Built-in auth
  password_hash           TEXT,                          -- bcrypt; NULL if AD-only user
  must_change_password    BOOL        NOT NULL DEFAULT FALSE, -- admin reset forces change on next login
  is_local_admin          BOOL        NOT NULL DEFAULT FALSE, -- bypasses AD; always bcrypt

  -- AD / LDAP sync identity
  ad_object_guid          UUID        UNIQUE,            -- AD objectGUID (stable across renames)
  ad_usn_changed          BIGINT,                        -- AD uSNChanged for incremental sync
  ad_sam_account          TEXT,                          -- sAMAccountName
  ad_upn                  TEXT,                          -- userPrincipalName
  sync_source             TEXT        NOT NULL DEFAULT 'local'
                            CHECK (sync_source IN ('local','ad','ldap','scim','sso')),
  local_overrides         JSONB       NOT NULL DEFAULT '{}', -- fields that survive AD sync
  last_synced_at          TIMESTAMPTZ,

  -- Kerberos
  krb5_principal          TEXT,                          -- e.g. user@COMPANY.COM

  -- SAML
  saml_name_id            TEXT,                          -- NameID from IdP assertion
  saml_session_index      TEXT,
  saml_idp_entity_id      TEXT,                          -- IdP entity ID (stable matching)

  -- OIDC
  oidc_subject            TEXT,                          -- sub claim from id_token
  oidc_issuer             TEXT,                          -- iss claim from id_token (stable matching)
  oidc_provider           TEXT,                          -- 'azure_ad' | provider name

  -- WebAuthn / Passkeys
  webauthn_credentials    JSONB       NOT NULL DEFAULT '[]',
  webauthn_user_handle    BYTEA,                         -- random opaque handle per WebAuthn spec

  -- TOTP (fallback MFA)
  totp_secret_enc         TEXT,                          -- AES-encrypted TOTP secret
  totp_enabled            BOOL        NOT NULL DEFAULT FALSE,
  totp_enabled_at         TIMESTAMPTZ,                   -- when TOTP was last enabled (NULL if never enabled)
  last_totp_used_at       TIMESTAMPTZ,                   -- prevents OTP replay within 30s window
  totp_failed_attempts    INT         NOT NULL DEFAULT 0,
  totp_locked_until       TIMESTAMPTZ,                   -- account locked after 5 consecutive failures
  mfa_exempt              BOOL        NOT NULL DEFAULT FALSE,  -- exempt from org-wide MFA enforcement

  -- Account state
  enabled                 BOOL        NOT NULL DEFAULT TRUE,
  is_admin                BOOL        NOT NULL DEFAULT FALSE,
  last_login_at           TIMESTAMPTZ,
  last_login_ip           INET,

  created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),

  UNIQUE (username, domain_id)
);

CREATE INDEX users_email_idx         ON users(email);
CREATE INDEX users_domain_idx        ON users(domain_id);
CREATE INDEX users_department_idx    ON users(department_id);
CREATE INDEX users_ad_guid_idx       ON users(ad_object_guid) WHERE ad_object_guid IS NOT NULL;
CREATE INDEX users_ad_usn_idx        ON users(ad_usn_changed)  WHERE ad_usn_changed  IS NOT NULL;
CREATE INDEX users_enabled_idx       ON users(enabled);
CREATE UNIQUE INDEX users_email_lower_idx ON users(lower(email));
CREATE INDEX users_manager_idx       ON users(manager_id) WHERE manager_id IS NOT NULL;
CREATE INDEX users_avatar_idx        ON users(avatar_sha256) WHERE avatar_sha256 IS NOT NULL;
CREATE UNIQUE INDEX users_oidc_subject_idx
  ON users(oidc_issuer, oidc_subject) WHERE oidc_subject IS NOT NULL AND oidc_issuer IS NOT NULL;
CREATE UNIQUE INDEX users_saml_name_id_idx
  ON users(saml_idp_entity_id, saml_name_id) WHERE saml_name_id IS NOT NULL AND saml_idp_entity_id IS NOT NULL;
