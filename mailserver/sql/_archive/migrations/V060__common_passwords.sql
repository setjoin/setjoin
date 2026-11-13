-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V060: Common passwords table for weak-password detection.
-- Stores SHA-256 hashes of well-known compromised passwords.
-- Checked during password creation and change to reject easily-guessed passwords.

CREATE TABLE IF NOT EXISTS common_passwords (
    id            BIGSERIAL  PRIMARY KEY,
    password_hash BYTEA      NOT NULL UNIQUE
);
