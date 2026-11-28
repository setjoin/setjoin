-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V051: Per-alias email signatures.

CREATE TABLE user_signatures (
    id              BIGSERIAL    PRIMARY KEY,
    user_id         BIGINT       NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    alias_email     TEXT         NOT NULL,   -- the alias (or primary email) this signature is for
    signature_html  TEXT         NOT NULL DEFAULT '',
    signature_text  TEXT         NOT NULL DEFAULT '',
    is_default      BOOL         NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- One signature per alias per user
CREATE UNIQUE INDEX idx_user_signatures_user_alias ON user_signatures(user_id, alias_email);
CREATE INDEX idx_user_signatures_user ON user_signatures(user_id);

COMMENT ON TABLE user_signatures IS
'Per-alias HTML/text signatures. One row per (user, alias_email) pair. Clients pick the signature matching the From address in compose.';
