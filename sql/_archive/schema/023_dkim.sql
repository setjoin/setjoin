-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- DKIM: DomainKeys Identified Mail key management.
CREATE TABLE domain_signing_keys (
  id              BIGSERIAL   PRIMARY KEY,
  domain_id       BIGINT      NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  selector        TEXT        NOT NULL,        -- e.g. "default", "2024a"
  algorithm       TEXT        NOT NULL DEFAULT 'rsa-sha256'
                    CHECK (algorithm IN ('rsa-sha256','ed25519-sha256')),
  public_key_pem  TEXT        NOT NULL,        -- DNS TXT record content (base64 of pubkey)
  private_key_pem TEXT        NOT NULL,        -- encrypted with DB encryption key
  key_size        INT         NOT NULL DEFAULT 2048,
  active          BOOL        NOT NULL DEFAULT TRUE,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  rotated_at      TIMESTAMPTZ,
  UNIQUE (domain_id, selector)
);

CREATE INDEX dsk_domain_active_idx ON domain_signing_keys(domain_id, active);

-- DKIM verification results per message
ALTER TABLE messages ADD COLUMN IF NOT EXISTS dkim_result TEXT;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS dkim_selector TEXT;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS dkim_domain TEXT;
