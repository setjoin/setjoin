-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Webhook subscriptions and delivery log.

CREATE TABLE webhook_subscriptions (
    id              BIGSERIAL    PRIMARY KEY,
    user_id         BIGINT       REFERENCES users(id) ON DELETE CASCADE,
    url             TEXT         NOT NULL,
    secret          TEXT         NOT NULL,
    prev_secret     TEXT,
    event_types     JSONB        NOT NULL DEFAULT '[]',
    is_active       BOOL         NOT NULL DEFAULT TRUE,
    retry_enabled   BOOL         NOT NULL DEFAULT TRUE,
    max_retries     INT          NOT NULL DEFAULT 12,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE webhook_deliveries (
    id              BIGSERIAL    PRIMARY KEY,
    subscription_id BIGINT       NOT NULL REFERENCES webhook_subscriptions(id) ON DELETE CASCADE,
    event_id        TEXT         NOT NULL,
    event_type      TEXT         NOT NULL,
    request_body    JSONB        NOT NULL,
    response_code   INT,
    response_body   TEXT,
    latency_ms      INT,
    attempt         INT          NOT NULL DEFAULT 1,
    status          TEXT         NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','success','failed','exhausted')),
    error_message   TEXT,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ
);

CREATE UNIQUE INDEX webhook_deliveries_event_sub_idx
    ON webhook_deliveries(subscription_id, event_id);

CREATE INDEX webhook_subscriptions_active_idx
    ON webhook_subscriptions(id) WHERE is_active;
