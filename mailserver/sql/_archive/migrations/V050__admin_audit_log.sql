-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V050: Admin audit log — ensures the table exists for the report handler tests.
-- Schema originally defined in sql/schema/015_compliance.sql; this migration
-- creates it if it doesn't already exist (idempotent).

CREATE TABLE IF NOT EXISTS admin_audit_log (
  id              BIGSERIAL   PRIMARY KEY,
  occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  user_id         BIGINT      REFERENCES users(id) ON DELETE SET NULL,
  ip              INET,
  action          TEXT        NOT NULL,
  target_type     TEXT,
  target_id       BIGINT,
  before_state    JSONB,
  after_state     JSONB,
  notes           TEXT
);

CREATE INDEX IF NOT EXISTS admin_audit_user_idx    ON admin_audit_log(user_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS admin_audit_target_idx  ON admin_audit_log(target_type, target_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS admin_audit_time_idx    ON admin_audit_log(occurred_at DESC);
