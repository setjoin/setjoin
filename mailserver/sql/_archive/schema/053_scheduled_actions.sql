-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- 053_scheduled_actions.sql: Scheduled Actions — one deferred-action
-- infrastructure replacing the scattered per-kind "timer" reducers (snooze /
-- scheduled-send / undo-send) and the never-firing calendar-VALARM / task-reminder
-- scan. Canonical mirror of migrations/V080__scheduled_actions.sql.
-- See retired-docs:superpowers/specs/2026-06-16-scheduled-actions-design.md.
--
-- Security model (DATABASE_SECURITY.md): this repo enforces R4 via p_mailbox_id /
-- mailbox_id propagation through the reducers (sql/AGENTS.md), not native Postgres
-- RLS policies (there are zero FORCE'd tables in this schema). The dispatcher runs
-- on the cron worker's privileged connection (spec §3: NO SECURITY DEFINER /
-- BYPASSRLS); user-action reducers (enqueue/cancel, reminder_*) scope every
-- statement by mailbox_id. mailbox_id is the owner column for observability + the
-- ON DELETE CASCADE.

CREATE TABLE IF NOT EXISTS scheduled_actions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action_kind   TEXT        NOT NULL,                  -- 'send' | 'snooze' | 'remind' | ...
    fire_at       TIMESTAMPTZ NOT NULL,
    payload       JSONB       NOT NULL DEFAULT '{}',     -- handler-private; dispatcher never reads it
    status        TEXT        NOT NULL DEFAULT 'pending' -- pending | processing | done | failed
                              CHECK (status IN ('pending','processing','done','failed')),
    attempts      INT         NOT NULL DEFAULT 0,
    locked_until  TIMESTAMPTZ,
    locked_by     TEXT,
    last_error    TEXT,
    dedup_key     TEXT,                                  -- egress idempotency; NULL for pure-DB kinds
    mailbox_id    BIGINT      REFERENCES mailboxes(id) ON DELETE CASCADE,  -- owner (R4 propagation / observability)
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS scheduled_actions_due_idx
    ON scheduled_actions (fire_at) WHERE status = 'pending';
CREATE UNIQUE INDEX IF NOT EXISTS scheduled_actions_dedup_idx
    ON scheduled_actions (dedup_key) WHERE dedup_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS scheduled_actions_reclaim_idx
    ON scheduled_actions (locked_until) WHERE status = 'processing';
CREATE INDEX IF NOT EXISTS scheduled_actions_mailbox_idx
    ON scheduled_actions (mailbox_id) WHERE mailbox_id IS NOT NULL;

-- Append-only audit: "why didn't my scheduled mail send". Not FK-cascading — the
-- log survives the action row.
CREATE TABLE IF NOT EXISTS scheduled_action_log (
    id          BIGSERIAL   PRIMARY KEY,
    action_id   UUID        NOT NULL,
    at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    from_status TEXT,
    to_status   TEXT        NOT NULL,
    worker      TEXT,
    outcome     TEXT,                       -- 'claimed' | 'done' | 'failed' | 'expired' | 'retry'
    note        TEXT
);
CREATE INDEX IF NOT EXISTS scheduled_action_log_action_idx ON scheduled_action_log (action_id, at);

-- Reminders surface (the remind handler's sink). A small fire-once ledger keyed by
-- (mailbox_id, source_type, source_id, fire_at); jmap_reminder_state mirrors the
-- email/tag state pattern to drive JMAP push.
ALTER TABLE mailboxes ADD COLUMN IF NOT EXISTS jmap_reminder_state BIGINT NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS reminders (
    id            BIGSERIAL   PRIMARY KEY,
    mailbox_id    BIGINT      NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    source_type   TEXT        NOT NULL CHECK (source_type IN ('event','task','flag')),
    source_id     BIGINT      NOT NULL,
    fire_at       TIMESTAMPTZ NOT NULL,
    fired_at      TIMESTAMPTZ,
    dismissed_at  TIMESTAMPTZ,
    snoozed_until TIMESTAMPTZ,
    title         TEXT        NOT NULL,
    body          TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (mailbox_id, source_type, source_id, fire_at)   -- fire-once ledger
);
CREATE INDEX IF NOT EXISTS reminders_active_idx ON reminders(mailbox_id) WHERE dismissed_at IS NULL;

-- Egress idempotency for the send handler: a dedup_key on the outbound queue that
-- carries the scheduled_action id. A post-crash reclaim re-enqueues the same key
-- and conflicts on the UNIQUE, so the send is exactly-once. NULL for ordinary
-- (non-scheduled) sends; the default UNIQUE treats NULLs as distinct, so multiple
-- NULL rows coexist (spec §4 schema note).
ALTER TABLE outbound_queue     ADD COLUMN IF NOT EXISTS dedup_key TEXT;
ALTER TABLE outbound_queue_hot ADD COLUMN IF NOT EXISTS dedup_key TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS outbound_queue_hot_dedup_idx
    ON outbound_queue_hot (dedup_key) WHERE dedup_key IS NOT NULL;
