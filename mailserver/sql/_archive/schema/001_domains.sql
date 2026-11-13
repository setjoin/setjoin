-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Domains: every email domain this server accepts or relays mail for.
CREATE TABLE domains (
  id                      BIGSERIAL PRIMARY KEY,
  name                    TEXT      NOT NULL UNIQUE,
  is_primary              BOOL      NOT NULL DEFAULT FALSE,
  is_local                BOOL      NOT NULL DEFAULT TRUE,   -- FALSE = relay domain
  catch_all_mailbox_id    BIGINT,                            -- FK added after mailboxes created
  dkim_selector           TEXT,
  dkim_private_key_enc    TEXT,                              -- AES-encrypted, key from system_config
  dkim_key_expires_at     TIMESTAMPTZ,
  spf_record              TEXT,
  dmarc_policy    TEXT        NOT NULL DEFAULT 'none'
                            CHECK (dmarc_policy IN ('none','quarantine','reject')),
  dmarc_rua       TEXT,                         -- aggregate report URI (mailto:...)
  dmarc_ruf       TEXT,                         -- forensic report URI (mailto:...)
  dmarc_pct       INT         NOT NULL DEFAULT 100,
  mta_sts_policy          TEXT      NOT NULL DEFAULT 'none'
                            CHECK (mta_sts_policy IN ('none','testing','enforce')),
  max_message_bytes       BIGINT    NOT NULL DEFAULT 52428800, -- 50 MB
  quota_bytes             BIGINT,                               -- NULL = unlimited domain storage cap
  created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX domains_name_idx ON domains(name);
CREATE INDEX domains_local_idx ON domains(is_local) WHERE is_local = TRUE;
-- At most one primary domain
CREATE UNIQUE INDEX domains_primary_uniq ON domains((TRUE)) WHERE is_primary;
