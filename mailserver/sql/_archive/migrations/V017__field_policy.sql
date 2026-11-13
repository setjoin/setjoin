-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V017: Per-field ownership policy for AD/LDAP identity sync.
-- Admins lock individual fields to prevent sync from overwriting local values.

CREATE TABLE field_policy (
    user_id   BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    field     TEXT   NOT NULL,
    policy    TEXT   NOT NULL CHECK (policy IN ('local_only', 'ad_managed')),
    set_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    set_by    BIGINT REFERENCES users(id),
    PRIMARY KEY (user_id, field)
);

CREATE INDEX field_policy_user_idx ON field_policy(user_id);
