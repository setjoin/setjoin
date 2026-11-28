-- V113__booking_pages.sql — self-service booking pages (Calendly-style).
-- Public unauth surface: see docs/superpowers/plans/archive/2026-07-08-self-service-booking-pages.md
-- and docs/adr/DES-007-public-booking-surface.md (Task 10). FIRST deliberate
-- unauthenticated public app surface — default-OFF toggle, see below.

CREATE TABLE booking_pages (
    id               BIGSERIAL PRIMARY KEY,
    mailbox_id       BIGINT NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    slug             TEXT   NOT NULL UNIQUE
                     CHECK (slug ~ '^[a-z0-9][a-z0-9-]{2,63}$'),
    title            TEXT   NOT NULL,
    description      TEXT,
    duration_minutes INT    NOT NULL DEFAULT 30  CHECK (duration_minutes BETWEEN 5 AND 480),
    buffer_minutes   INT    NOT NULL DEFAULT 0   CHECK (buffer_minutes BETWEEN 0 AND 120),
    max_per_day      INT    NOT NULL DEFAULT 8   CHECK (max_per_day BETWEEN 1 AND 48),
    min_notice_minutes INT  NOT NULL DEFAULT 120 CHECK (min_notice_minutes BETWEEN 0 AND 20160),
    max_advance_days INT    NOT NULL DEFAULT 60  CHECK (max_advance_days BETWEEN 1 AND 365),
    -- weekly windows, page-local time: [{"dow":1,"start":"09:00","end":"17:00"}, ...] dow: 0=Sun
    availability     JSONB  NOT NULL DEFAULT
      '[{"dow":1,"start":"09:00","end":"17:00"},{"dow":2,"start":"09:00","end":"17:00"},{"dow":3,"start":"09:00","end":"17:00"},{"dow":4,"start":"09:00","end":"17:00"},{"dow":5,"start":"09:00","end":"17:00"}]',
    -- custom questions: [{"id":"q1","label":"...","required":true}]
    questions        JSONB  NOT NULL DEFAULT '[]',
    timezone         TEXT   NOT NULL DEFAULT 'UTC',
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX booking_pages_mailbox_idx ON booking_pages (mailbox_id);

-- Native-RLS backstop (per-mailbox), same shape as V080 saved_searches — INERT
-- for the superuser/owner test role until the prod DSN switches to setjoin_app
-- (docs/standards/DATABASE_SECURITY.md → Deploy gate). Primary enforcement is
-- the reducers' own `WHERE mailbox_id = p_mailbox_id` (R1/R3); this is defense
-- in depth for the eventual RLS flip.
ALTER TABLE booking_pages ENABLE ROW LEVEL SECURITY;
ALTER TABLE booking_pages FORCE  ROW LEVEL SECURITY;

CREATE POLICY booking_pages_tenant_isolation ON booking_pages
  FOR ALL
  TO public
  USING      (mailbox_id = (SELECT NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint))
  WITH CHECK (mailbox_id = (SELECT NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint));

CREATE TABLE booking_requests (
    id                BIGSERIAL PRIMARY KEY,
    page_id           BIGINT NOT NULL REFERENCES booking_pages(id) ON DELETE CASCADE,
    -- Denormalized owner mailbox (copied from booking_pages.mailbox_id at
    -- create time) so this table can carry the SAME per-mailbox RLS policy
    -- shape as booking_pages, instead of a correlated-subquery policy — R4
    -- requires FORCE RLS on every user-data table, and booker_email is PII.
    mailbox_id        BIGINT NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    event_id          BIGINT REFERENCES calendar_events(id) ON DELETE SET NULL,
    booker_email      TEXT   NOT NULL CHECK (booker_email ~ '^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$'),
    booker_name       TEXT   NOT NULL DEFAULT '',
    answers           JSONB  NOT NULL DEFAULT '{}',
    slot_start        TIMESTAMPTZ NOT NULL,
    slot_end          TIMESTAMPTZ NOT NULL,
    status            TEXT   NOT NULL DEFAULT 'pending'
                      CHECK (status IN ('pending','confirmed','cancelled','expired')),
    verify_token_hash TEXT   NOT NULL,          -- sha256 hex of the emailed token
    verify_expires_at TIMESTAMPTZ NOT NULL,
    cancel_token_hash TEXT,                     -- set on confirm
    created_ip        INET,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Double-booking backstop: one live request per page+start. The reducer ALSO
-- re-checks real free/busy under an advisory lock (Task 4); this index is the
-- race-proof floor.
CREATE UNIQUE INDEX booking_requests_live_slot_uq
    ON booking_requests (page_id, slot_start)
    WHERE status IN ('pending','confirmed');
CREATE INDEX booking_requests_page_day_idx ON booking_requests (page_id, slot_start);
CREATE INDEX booking_requests_mailbox_idx ON booking_requests (mailbox_id);
CREATE UNIQUE INDEX booking_requests_verify_uq ON booking_requests (verify_token_hash);
CREATE INDEX booking_requests_expiry_idx ON booking_requests (verify_expires_at)
    WHERE status = 'pending';

ALTER TABLE booking_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE booking_requests FORCE  ROW LEVEL SECURITY;

CREATE POLICY booking_requests_tenant_isolation ON booking_requests
  FOR ALL
  TO public
  USING      (mailbox_id = (SELECT NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint))
  WITH CHECK (mailbox_id = (SELECT NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint));

-- feature.booking_pages: DEFAULT OFF. Public endpoints return 404 (not 403)
-- when off — indistinguishable from "no such page" (enumeration parity).
INSERT INTO feature_toggles (key, enabled, description) VALUES
  ('feature.booking_pages', FALSE,
   'Self-service public booking pages (/book/<slug>). FIRST unauthenticated public app surface — leave OFF unless the deployment deliberately exposes it (see the ADR for the recommended reverse-proxy exposure model).')
ON CONFLICT (key) DO NOTHING;

INSERT INTO schema_migrations (version, applied_at) VALUES (113, now())
    ON CONFLICT (version) DO NOTHING;
