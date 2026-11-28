-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- schema/051_user_app_entitlements.sql
-- Per-user application entitlements for effective-capabilities (B8, S7 + S11).
--
-- Default-allow semantics: an absent row means the user IS allowed to use the app.
-- A row with enabled=FALSE blocks access; with enabled=TRUE it is an explicit grant
-- (useful for future deny-unless-explicit modes).
--
-- The table name and schema are deliberately compatible with a future additive
-- user > group > global precedence chain (S11) — the current implementation only
-- has the user layer; group and global layers will be added as satellite tables
-- without requiring a rename here.
--
-- The app CHECK list gates only apps that have corresponding feature toggles and
-- independent UI surfaces.  Mail ('mail') is included to allow future mailbox-level
-- gating even though it ships always-on for now.

CREATE TABLE IF NOT EXISTS user_app_entitlements (
    user_id    BIGINT       NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    app        TEXT         NOT NULL CHECK (app IN ('mail', 'calendar', 'contacts', 'tasks')),
    enabled    BOOLEAN      NOT NULL DEFAULT TRUE,
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_by BIGINT       REFERENCES users(id) ON DELETE SET NULL,
    PRIMARY KEY (user_id, app)
);

COMMENT ON TABLE user_app_entitlements IS
    'Per-user app access overrides. Absent row = allowed (default-allow). '
    'enabled=FALSE blocks the user from the named app regardless of global toggle. '
    'Schema is compatible with additive group/global precedence layers (S11).';

-- Index: only blocked rows matter for admin "who is blocked?" listing.
-- Leading user_id is omitted here because blocked-row admin scans are global;
-- the PK already covers the per-user fast-path.
CREATE INDEX IF NOT EXISTS user_app_entitlements_app_idx
    ON user_app_entitlements (app)
    WHERE enabled = FALSE;
