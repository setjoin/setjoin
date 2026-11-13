-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Schema 010: IP allow/block rules — admin-managed CIDR entries.
-- Allow entries bypass ALL threat detection steps.
-- Block entries cause immediate reject with audit trail.
CREATE TABLE ip_rules (
    id          BIGSERIAL   PRIMARY KEY,
    cidr        INET        NOT NULL,
    action      TEXT        NOT NULL CHECK (action IN ('allow','block')),
    description TEXT        NOT NULL,
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by  BIGINT      REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX ip_rules_cidr_idx ON ip_rules USING gist (cidr inet_ops);
CREATE INDEX ip_rules_action_idx ON ip_rules (action);
