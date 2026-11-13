-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- DLP (Data Loss Prevention) policies for outbound mail.
CREATE TABLE dlp_policies (
  id              BIGSERIAL   PRIMARY KEY,
  domain_id       BIGINT      REFERENCES domains(id) ON DELETE CASCADE,
  name            TEXT        NOT NULL,
  enabled         BOOL        NOT NULL DEFAULT TRUE,
  priority        INT         NOT NULL DEFAULT 0,
  action          TEXT        NOT NULL DEFAULT 'block'
                    CHECK (action IN ('block','warn','quarantine','notify_admin')),
  -- Match conditions
  regex_patterns  TEXT[]      NOT NULL DEFAULT '{}',   -- regexes to match against body/subject
  keywords        TEXT[]      NOT NULL DEFAULT '{}',   -- keywords (case-insensitive)
  min_confidence  REAL        NOT NULL DEFAULT 0.7
                    CHECK (min_confidence >= 0 AND min_confidence <= 1),
  blocked_file_types TEXT[]   NOT NULL DEFAULT '{}',   -- e.g. {'exe','bat','scr'}
  max_attachment_size BIGINT  NOT NULL DEFAULT 0,      -- 0 = unlimited
  -- Scope
  applies_to_all  BOOL        NOT NULL DEFAULT TRUE,   -- if FALSE, use dlp_policy_targets
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX dlp_policies_domain_idx ON dlp_policies(domain_id, enabled, priority);

-- Target mailboxes for per-mailbox DLP policies
CREATE TABLE dlp_policy_targets (
  policy_id       BIGINT      NOT NULL REFERENCES dlp_policies(id) ON DELETE CASCADE,
  mailbox_id      BIGINT      NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
  PRIMARY KEY (policy_id, mailbox_id)
);

-- DLP violation log
CREATE TABLE dlp_violations (
  id              BIGSERIAL   PRIMARY KEY,
  policy_id       BIGINT      NOT NULL REFERENCES dlp_policies(id),
  message_id      BIGINT,     -- intentionally no FK: messages is partitioned
  mailbox_id      BIGINT      NOT NULL REFERENCES mailboxes(id),
  violation_type  TEXT        NOT NULL,
  matched_text    TEXT,
  action_taken    TEXT        NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- dlp_check is defined in 047_dlp_consolidate.sql (consolidated version)
