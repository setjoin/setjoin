-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- App passwords: static credentials for IMAP/SMTP clients that cannot use JWT/OAuth.
-- Tokens are generated as 32-byte random hex with 'mail-ap-' prefix and SHA-256 hashed.
CREATE TABLE app_passwords (
    id              BIGSERIAL    PRIMARY KEY,
    user_id         BIGINT       NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name            TEXT         NOT NULL,
    label           TEXT,
    token_hash      TEXT         NOT NULL,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_used_at    TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ
);

CREATE INDEX app_passwords_user_idx ON app_passwords(user_id)
    WHERE revoked_at IS NULL;

-- Enforce max 10 active app passwords per user
CREATE OR REPLACE FUNCTION trg_app_password_limit() RETURNS TRIGGER AS $$
BEGIN
    IF (SELECT COUNT(*) FROM app_passwords
        WHERE user_id = NEW.user_id AND revoked_at IS NULL) >= 10 THEN
        RAISE EXCEPTION 'Maximum 10 app passwords per user'
            USING ERRCODE = 'BZ015',
            HINT = jsonb_build_object('type', 'app_password_limit', 'user_id', NEW.user_id)::TEXT;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER app_password_limit
    BEFORE INSERT ON app_passwords
    FOR EACH ROW EXECUTE FUNCTION trg_app_password_limit();

-- Auth event log: records every authentication event (app password, bcrypt, etc.)
CREATE TABLE auth_event_log (
    id          BIGSERIAL    PRIMARY KEY,
    user_id     BIGINT       REFERENCES users(id) ON DELETE SET NULL,
    event       TEXT         NOT NULL CHECK (event IN ('login', 'login_failed')),
    provider    TEXT         NOT NULL CHECK (provider IN ('bcrypt', 'app_password', 'kerberos', 'jwt', 'ldap', 'webauthn', 'basic')),
    email       TEXT,
    ip_address  INET,
    details     JSONB,
    occurred_at TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX auth_event_log_user_idx ON auth_event_log(user_id, occurred_at DESC);
CREATE INDEX auth_event_log_time_idx ON auth_event_log(occurred_at DESC);
