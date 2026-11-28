-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V059: User settings — notification preferences, login events
BEGIN;

-- Per-device notification preferences
CREATE TABLE IF NOT EXISTS user_notification_prefs (
    id              BIGSERIAL PRIMARY KEY,
    user_id         BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_fingerprint UUID,  -- NULL = global default for user
    push_enabled    BOOLEAN DEFAULT true,
    push_sound      TEXT DEFAULT 'default',
    stop_push_when_desktop_online BOOLEAN DEFAULT false,
    dnd_start       TIME,
    dnd_end         TIME,
    dnd_days        SMALLINT DEFAULT 127,  -- bitmask: Mon=1..Sun=64, 127=all
    mail_notifications TEXT DEFAULT 'all' CHECK (mail_notifications IN ('all','important','off')),
    calendar_reminders BOOLEAN DEFAULT true,
    task_reminders  BOOLEAN DEFAULT true,
    created_at      TIMESTAMPTZ DEFAULT now(),
    updated_at      TIMESTAMPTZ DEFAULT now(),
    UNIQUE(user_id, device_fingerprint)
);

-- Login event tracking for user-facing history
CREATE TABLE IF NOT EXISTS login_events (
    id              BIGSERIAL PRIMARY KEY,
    user_id         BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_fingerprint UUID,
    device_name     TEXT,
    platform        TEXT,  -- ios/android/macos/windows/linux/webmail
    source_ip       INET,
    location        TEXT,  -- GeoIP city, country
    success         BOOLEAN NOT NULL,
    fail_reason     TEXT,  -- NULL if success
    occurred_at     TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_login_events_user ON login_events(user_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_login_events_ip ON login_events(source_ip);
CREATE INDEX IF NOT EXISTS idx_notification_prefs_user ON user_notification_prefs(user_id);

COMMIT;
