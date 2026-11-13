-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V024: OIDC Provider (IdP) mode tables.
-- Registered OIDC relying party clients that our IdP serves.
CREATE TABLE IF NOT EXISTS oidc_clients (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    secret          TEXT NOT NULL,           -- bcrypt-hashed client secret
    redirect_uris   TEXT[] NOT NULL,
    grant_types     TEXT[] NOT NULL DEFAULT '{authorization_code,refresh_token}',
    scopes          TEXT[] NOT NULL DEFAULT '{openid,profile,email}',
    enabled         BOOL NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Ephemeral authorization requests (single-use, short-lived).
-- UNLOGGED for speed; lost on crash is acceptable since requests expire in 10 min.
CREATE UNLOGGED TABLE IF NOT EXISTS oidc_auth_requests (
    id              TEXT PRIMARY KEY,
    client_id       TEXT NOT NULL REFERENCES oidc_clients(id),
    redirect_uri    TEXT NOT NULL,
    state           TEXT NOT NULL,
    nonce           TEXT,
    code_challenge  TEXT,
    code_challenge_method TEXT,
    scopes          TEXT[] NOT NULL,
    user_id         BIGINT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL DEFAULT now() + INTERVAL '10 minutes'
);

-- Issued tokens for refresh, introspection, and revocation.
CREATE TABLE IF NOT EXISTS oidc_tokens (
    id              TEXT PRIMARY KEY,
    client_id       TEXT NOT NULL REFERENCES oidc_clients(id),
    user_id         BIGINT NOT NULL REFERENCES users(id),
    subject         TEXT NOT NULL,
    refresh_token_hash TEXT,
    scopes          TEXT[] NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS oidc_tokens_refresh_idx ON oidc_tokens(refresh_token_hash)
  WHERE refresh_token_hash IS NOT NULL;
