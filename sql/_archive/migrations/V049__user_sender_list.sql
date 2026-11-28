-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V049: Per-user safe/blocked sender lists + view preferences storage.

CREATE TABLE user_sender_list (
    user_id   BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    sender    TEXT   NOT NULL,  -- email or *@domain wildcard
    list_type TEXT   NOT NULL CHECK (list_type IN ('safe', 'blocked')),
    added_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, sender, list_type)
);

CREATE INDEX idx_user_sender_list_user ON user_sender_list(user_id);

-- Extend users table with a view preferences JSONB blob.
-- NULL = use defaults; stored JSON is the user's explicit overrides.
ALTER TABLE users ADD COLUMN IF NOT EXISTS view_prefs JSONB;

COMMENT ON COLUMN users.view_prefs IS
'Per-user view preferences: {default_view, reading_pane, sender_images, ext_sender_warning, smart_mute}. NULL → use defaults on the client.';
