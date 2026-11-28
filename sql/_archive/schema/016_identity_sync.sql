-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Identity sync: AD/LDAP sync tracking, conflicts, device sessions.
CREATE TABLE identity_sync_log (
  id              BIGSERIAL   PRIMARY KEY,
  sync_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  source          TEXT        NOT NULL CHECK (source IN ('ad','ldap','manual')),
  users_checked   INT         NOT NULL DEFAULT 0,
  users_updated   INT         NOT NULL DEFAULT 0,
  users_created   INT         NOT NULL DEFAULT 0,
  users_disabled  INT         NOT NULL DEFAULT 0,
  fields_skipped  INT         NOT NULL DEFAULT 0,  -- fields protected by local_overrides
  conflicts_found INT         NOT NULL DEFAULT 0,
  duration_ms     INT,
  error           TEXT,
  details         JSONB                            -- per-user change summary
);

-- Conflicts: AD changed a field that has a local override.
CREATE TABLE sync_conflicts (
  id              BIGSERIAL   PRIMARY KEY,
  user_id         BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  field           TEXT        NOT NULL,
  local_value     TEXT,
  remote_value    TEXT,
  source          TEXT        NOT NULL CHECK (source IN ('ad','ldap')),
  detected_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  resolved_at     TIMESTAMPTZ,
  resolved_by     BIGINT      REFERENCES users(id) ON DELETE SET NULL,
  resolution      TEXT        CHECK (resolution IN ('kept_local','accepted_remote','merged'))
);

CREATE INDEX sync_conflicts_user_idx       ON sync_conflicts(user_id);
CREATE INDEX sync_conflicts_unresolved_idx ON sync_conflicts(detected_at)
  WHERE resolved_at IS NULL;

-- Registered client devices (for push notifications and remote wipe).
CREATE TABLE user_devices (
  id              BIGSERIAL   PRIMARY KEY,
  user_id         BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_name     TEXT        NOT NULL,  -- "Cat's iPhone"
  platform        TEXT        NOT NULL CHECK (platform IN ('ios','android','web','desktop')),
  push_token_enc  TEXT,                  -- AES-encrypted APNs / FCM / WebPush token
  push_provider   TEXT        CHECK (push_provider IN ('apns','fcm','webpush')),
  last_seen_at    TIMESTAMPTZ,
  last_seen_ip    INET,
  wipe_requested  BOOL        NOT NULL DEFAULT FALSE,
  wipe_type       TEXT        CHECK (wipe_type IN ('selective','full')),
  wipe_at         TIMESTAMPTZ,
  registered_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX user_devices_user_idx ON user_devices(user_id);
