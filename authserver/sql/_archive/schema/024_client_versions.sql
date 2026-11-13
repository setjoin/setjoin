-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Schema 024: Client version tracking and distribution table.
-- Stores client binary metadata for the self-hosted update distribution pattern.

CREATE TABLE IF NOT EXISTS client_versions (
    id              BIGSERIAL PRIMARY KEY,
    platform        TEXT NOT NULL,           -- ios, android
    app             TEXT NOT NULL,           -- mail, guard
    version         TEXT NOT NULL,           -- SemVer 1.2.3
    file_path       TEXT,                    -- relative path under client storage dir
    sha256          TEXT NOT NULL,           -- hex-encoded SHA-256
    signature       TEXT,                    -- detached signature (base64)
    release_notes   TEXT,
    release_date    TIMESTAMPTZ NOT NULL DEFAULT now(),
    min_os_version  TEXT,                    -- e.g. "18.0" for iOS
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (platform, app, version)
);

-- Policy: global default + per-app overrides
INSERT INTO system_config (key, value) VALUES
    ('client_version_policy', '{"default":"recommended","rules":[{"behind_major":"required"},{"behind_minor2":"required"}]}')
ON CONFLICT (key) DO NOTHING;
