-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Unlogged tables: fast hot state that lives in shared_buffers.
-- These are TRUNCATED on crash — each is designed to tolerate that.

-- User sessions: truncated on crash → users re-authenticate (acceptable).
--
-- Revocation model:
--   Access tokens are short-lived JWTs (1h) and are NOT tracked per-session.
--   Refresh tokens ARE tracked: token_hash = sha256(refresh_token). Logout
--   deletes the row; /auth/refresh rejects any token whose hash is missing.
CREATE UNLOGGED TABLE sessions (
  id              TEXT        PRIMARY KEY DEFAULT gen_random_uuid()::text,
  user_id         BIGINT      NOT NULL,             -- no FK on unlogged table
  token_hash      BYTEA       UNIQUE,               -- sha256(refresh_token); NULL for non-refresh sessions
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at      TIMESTAMPTZ NOT NULL,
  last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  ip              INET,
  user_agent      TEXT,
  auth_method     TEXT        CHECK (auth_method IN
                    ('password','webauthn','kerberos','saml','oidc','totp')),
  -- AD grace period: allow session to survive AD being unreachable
  ad_grace_until  TIMESTAMPTZ
);

CREATE INDEX sessions_user_idx    ON sessions(user_id);
CREATE INDEX sessions_expires_idx ON sessions(expires_at);

-- WebSocket subscriptions: which JMAP push channels each connection listens on.
-- Rebuilt automatically when clients reconnect after crash.
CREATE UNLOGGED TABLE ws_subscriptions (
  connection_id   TEXT        PRIMARY KEY,
  session_id      TEXT        NOT NULL,
  user_id         BIGINT      NOT NULL,
  mailbox_ids     BIGINT[]    NOT NULL DEFAULT '{}',
  calendar_ids    BIGINT[]    NOT NULL DEFAULT '{}',
  subscribed_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_ping_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ws_subs_user_idx    ON ws_subscriptions(user_id);
CREATE INDEX ws_subs_session_idx ON ws_subscriptions(session_id);

-- Greylisting: truncated on crash → brief period of delivery delays on restart.
-- Legitimate senders retry within minutes; spambots usually do not.
CREATE UNLOGGED TABLE greylist (
  ip              INET        NOT NULL,
  sender          TEXT        NOT NULL,
  recipient       TEXT        NOT NULL,
  first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
  pass_count      INT         NOT NULL DEFAULT 0,
  whitelisted     BOOL        NOT NULL DEFAULT FALSE,  -- auto after first pass
  PRIMARY KEY (ip, sender, recipient)
);

CREATE INDEX greylist_whitelist_idx ON greylist(sender) WHERE whitelisted;

-- Rate limit counters: truncated on crash → brief permissive window on restart.
-- This is acceptable: a 3-second permissive window is not a security issue.
CREATE UNLOGGED TABLE rate_limit_counters (
  key             TEXT        PRIMARY KEY,  -- 'smtp:{ip}' | 'auth:{ip}' | 'send:{user_id}'
  count           INT         NOT NULL DEFAULT 0,
  window_start    TIMESTAMPTZ NOT NULL DEFAULT now(),
  blocked_until   TIMESTAMPTZ
);

-- Active SMTP sessions: truncated on crash → in-progress SMTP connections dropped.
-- Sending MTAs retry automatically per RFC 5321.
CREATE UNLOGGED TABLE smtp_sessions (
  id              TEXT        PRIMARY KEY,
  remote_ip       INET        NOT NULL,
  started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  state           TEXT        NOT NULL DEFAULT 'greeting'
                    CHECK (state IN ('greeting','ehlo','mail_from','rcpt_to','data','quit')),
  ehlo_hostname   TEXT,
  mail_from       TEXT,
  rcpt_to         TEXT[]      NOT NULL DEFAULT '{}',
  tls_enabled     BOOL        NOT NULL DEFAULT FALSE,
  tls_version     TEXT,
  authenticated   BOOL        NOT NULL DEFAULT FALSE,
  auth_user_id    BIGINT,
  spf_result      TEXT,
  bytes_received  BIGINT      NOT NULL DEFAULT 0
);

-- Clean up stale WebSocket subscriptions
-- [pg_cron→Go cron worker] SELECT cron.schedule('prune-ws-subscriptions', '* * * * *',
--   $$ DELETE FROM ws_subscriptions WHERE last_ping_at < now() - interval '5 minutes'; $$);
