-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Schema 020: Conditional access policies — declarative JSONB policy engine.
-- Policies are evaluated in priority order after the 8-step threat pipeline.
-- First policy whose conditions ALL match determines the outcome.
-- No-match falls through to built-in default (allow, no step-up).

CREATE TABLE conditional_access_policies (
    id          BIGSERIAL   PRIMARY KEY,
    priority    INT         NOT NULL DEFAULT 0,
    name        TEXT        NOT NULL,
    description TEXT        NOT NULL DEFAULT '',
    enabled     BOOL        NOT NULL DEFAULT TRUE,
    scope_type  TEXT        NOT NULL DEFAULT 'global'
                            CHECK (scope_type IN ('global', 'user', 'group')),
    scope_target TEXT       NOT NULL DEFAULT '',
    conditions  JSONB       NOT NULL DEFAULT '{}',
    actions     JSONB       NOT NULL DEFAULT '{"action":"allow"}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT valid_conditions CHECK (jsonb_typeof(conditions) = 'object'),
    CONSTRAINT valid_actions CHECK (jsonb_typeof(actions) = 'object')
);

-- Ensure unique priority ordering among enabled policies
CREATE UNIQUE INDEX ca_policies_priority_unique_idx
    ON conditional_access_policies (priority) WHERE enabled;

CREATE INDEX ca_policies_priority_idx ON conditional_access_policies (priority ASC);
