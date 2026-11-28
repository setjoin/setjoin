-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Schema 005: Unified OAuth / token table.
-- Tracks all token types — access, refresh, XOAUTH2, app passwords, authorization codes.
-- NOTIFY trigger fires on revocation for real-time IMAP session kill.
CREATE TABLE oauth_tokens (
    id                  BIGSERIAL   PRIMARY KEY,
    user_id             BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id           TEXT,
    token_hash          BYTEA       NOT NULL,            -- SHA-256 of the token
    token_type          TEXT        NOT NULL CHECK (token_type IN
                            ('access','refresh','xoauth2','app_password','authorization_code')),
    scope               TEXT[]      DEFAULT '{}',
    issued_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ,
    revoked_at          TIMESTAMPTZ,
    revoked_by          BIGINT      REFERENCES users(id),
    previous_token_hash BYTEA,                           -- links to replaced token (refresh chain theft detection)
    last_used_at        TIMESTAMPTZ,
    last_used_protocol  TEXT                              -- 'imap','smtp','jmap','caldav'
);
CREATE INDEX oauth_user_idx       ON oauth_tokens(user_id);
CREATE INDEX oauth_hash_idx       ON oauth_tokens(token_hash);
-- Partial index for active (non-revoked) tokens. The predicate cannot reference
-- now() — a partial-index predicate must be IMMUTABLE, and now() is STABLE, so
-- "expires_at > now()" raised "functions in index predicate must be marked
-- IMMUTABLE" and aborted the whole schema load. Expiry is filtered at query time;
-- indexing on revoked_at IS NULL is the IMMUTABLE, still-selective predicate.
CREATE INDEX oauth_user_active_idx ON oauth_tokens(user_id) WHERE revoked_at IS NULL;

-- Trigger: fires pg_notify on revocation for real-time session kill
CREATE OR REPLACE FUNCTION trg_oauth_revoke_notify() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.revoked_at IS NOT NULL AND (OLD.revoked_at IS NULL OR OLD.revoked_at IS DISTINCT FROM NEW.revoked_at) THEN
        PERFORM pg_notify('token_revoked:' || NEW.user_id, json_build_object(
            'token_type', NEW.token_type,
            'revoked_at', NEW.revoked_at
        )::text);
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_oauth_revoke_notify
    AFTER UPDATE ON oauth_tokens
    FOR EACH ROW EXECUTE FUNCTION trg_oauth_revoke_notify();
