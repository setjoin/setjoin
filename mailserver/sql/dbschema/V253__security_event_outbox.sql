-- V253: security_event_outbox — the durable security-event delivery substrate
-- (L2-C4, MEDIUM XINCHUANG-DB-001/002; proposal packet
-- .glm-plan-review/nightly/packets/L2-C4-xinchuang-events-proposal).
--
-- Contract (load-bearing design decision): the outbox row IS the event. The
-- delivery worker's ticker is the durability floor; LISTEN/NOTIFY (channel
-- security_event_outbox) is only a latency optimization — a wakeup means
-- "drain due rows", never "here is the event" (same contract as
-- reducers/federation_enqueue.sql). Degrading to polling loses latency, not
-- events; dropped wakeups lose nothing because the next tick re-queries.
--
-- Reliability shape mirrors push_intents (mailserver/internal/pushjobs/
-- worker.go:511-516): pending→done | pending→failed only, attempts +
-- next_attempt_at lease (no 'processing' status — a crash mid-delivery is
-- recovered by lease expiry), capped exponential backoff, maxAttempts.
-- claim_generation is the per-claim fencing carrier: bumped on every claim,
-- every settlement (done/retry/fail) predicates on it so a worker whose lease
-- lapsed and whose row was reclaimed cannot overwrite the new claimant's state
-- (webhook_delivery_complete lease-fencing precedent). Rows are NEVER deleted
-- here: security events are audit-adjacent, retention defaults to retain (a
-- reap decision belongs to the owner — chat_push_intents reaps at 7 days and
-- that precedent does NOT carry over).
--
-- At-least-once delivery: a crash after sink acceptance but before settlement
-- yields a redelivery carrying the same stable event id (the immutable outbox
-- id — consumers dedupe on it). No exactly-once reading exists anywhere in
-- this contract.
--
-- Isolation posture: transport/infrastructure rows with no membership axis —
-- ENABLE + FORCE RLS with ZERO permissive policies (deny-all to every runtime
-- role, V246/V249 quarantine-ledger posture), ownership with setjoin_owner
-- (DB_OWNER_DSN partition/DDL owner). The app role reads/writes NOTHING here:
-- enqueue flows only through the worker-owned SECURITY DEFINER reducer
-- security_event_enqueue (function ACLs, NOT apply_worker_ownership — that
-- applicator grants setjoin_app EXECUTE by contract, V118:19-20), and delivery
-- drains on the BYPASSRLS worker pool, which FORCE RLS cannot see. NOT a
-- membership-scoped table: no entry in scripts/rls-coverage-allowlist.txt
-- classes (worker-owned substrate).
CREATE TABLE public.security_event_outbox (
    id               BIGSERIAL PRIMARY KEY,
    event_type       TEXT NOT NULL
        CHECK (event_type ~ '^[a-z][a-z0-9_.]{0,127}$'),
    payload          JSONB NOT NULL
        CHECK (jsonb_typeof(payload) = 'object'
               AND octet_length(payload::text) <= 16384),
    status           TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','done','failed')),
    attempts         INTEGER NOT NULL DEFAULT 0,
    next_attempt_at  TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    last_error       TEXT,
    -- Per-claim fencing carrier: bumped by every claim; settlements predicate
    -- on it (0 = settled/cleared — no live claim).
    claim_generation INTEGER NOT NULL DEFAULT 0
        CHECK (claim_generation >= 0),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    delivered_at     TIMESTAMPTZ,
    -- Terminal rows carry their completion time; pending rows must not.
    CONSTRAINT security_event_outbox_delivered_shape CHECK (
        (status = 'done') = (delivered_at IS NOT NULL)
    )
);

CREATE INDEX security_event_outbox_claim_idx
    ON public.security_event_outbox (status, next_attempt_at);

COMMENT ON TABLE public.security_event_outbox IS
  'Durable security-event outbox (V253, L2-C4): one row per security event; '
  'the row IS the event (LISTEN/NOTIFY is a latency optimization only). '
  'at-least-once delivery; consumers dedupe on the immutable id. Rows only '
  'move pending→done|failed and are never deleted here (retention decision '
  'flagged to the owner). Worker-only: FORCE RLS deny-all; enqueue via the '
  'worker-owned security_event_enqueue reducer, delivery on the BYPASSRLS '
  'worker pool.';

ALTER TABLE public.security_event_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.security_event_outbox FORCE ROW LEVEL SECURITY;
ALTER TABLE public.security_event_outbox OWNER TO setjoin_owner;

INSERT INTO public.schema_migrations (version, applied_at)
VALUES (253, now());
