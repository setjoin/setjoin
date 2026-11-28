-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Outbound mail queue: LOGGED so it survives a crash.
CREATE TABLE outbound_queue (
  id              BIGSERIAL   PRIMARY KEY,
  message_id      TEXT        NOT NULL,   -- RFC 5322 Message-ID
  from_addr       TEXT        NOT NULL,
  rcpt_addrs      TEXT[]      NOT NULL,
  raw_ref         TEXT        NOT NULL,   -- MinIO path to full RFC 5322 message
  dkim_signed     BOOL        NOT NULL DEFAULT FALSE,
  status          TEXT        NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','sending','delivered','bounced','deferred')),
  attempt_count   INT         NOT NULL DEFAULT 0,
  next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_error      TEXT,
  queued_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  delivered_at    TIMESTAMPTZ,
  mailbox_id      BIGINT      REFERENCES mailboxes(id) ON DELETE SET NULL
);

CREATE INDEX outbound_queue_pending_idx ON outbound_queue(next_attempt_at)
  WHERE status IN ('pending','deferred');

CREATE INDEX outbound_queue_status_queued_idx ON outbound_queue(status, queued_at);
CREATE INDEX outbound_queue_mailbox_idx ON outbound_queue(mailbox_id);

-- Prevent resurrecting terminal queue items (delivered/bounced → anything else).
CREATE OR REPLACE FUNCTION trg_outbound_queue_status_guard() RETURNS TRIGGER AS $$
BEGIN
  IF OLD.status IN ('delivered', 'bounced') AND NEW.status != OLD.status THEN
    RAISE EXCEPTION 'Cannot change status of % item from % to %', OLD.id, OLD.status, NEW.status
      USING ERRCODE = 'BZ012', HINT = jsonb_build_object('type', 'immutable_status', 'id', OLD.id, 'from_status', OLD.status, 'to_status', NEW.status)::TEXT;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER outbound_queue_status_guard
  BEFORE UPDATE ON outbound_queue
  FOR EACH ROW EXECUTE FUNCTION trg_outbound_queue_status_guard();

-- Delivery status notification (DSN): when a queue item transitions to 'bounced',
-- ENQUEUE a `dsn` scheduled_action and return. The MIME synthesis + sender
-- resolution + deliver() call now live in the `scheduled_action_dsn` handler
-- (reducers/scheduled_action_dsn.sql), run async + retried + idempotent by the A6
-- dispatcher. The trigger no longer calls deliver() inside the bounce writer's txn,
-- so a deliver() raise can never roll back the bounce-status UPDATE (which used to
-- requeue the dead message forever). The status write stays synchronous-in-txn (the
-- Go egress worker commits it); only the bounce EMAIL defers (≤1 min, @every-1m
-- dispatcher). dedup_key='dsn:'||id makes a post-crash reclaim a no-op.
CREATE OR REPLACE FUNCTION trg_outbound_queue_dsn() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.status = 'bounced' AND (OLD.status IS NULL OR OLD.status != 'bounced') THEN
        PERFORM enqueue_scheduled_action(
            'dsn',
            now(),
            jsonb_build_object('queue_id', NEW.id),
            NEW.mailbox_id,            -- owner (may be NULL; handler defer-resolves the sender)
            'dsn:' || NEW.id::TEXT     -- idempotency: a reclaim re-enqueue is a no-op
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER outbound_queue_dsn
  AFTER INSERT OR UPDATE ON outbound_queue
  FOR EACH ROW EXECUTE FUNCTION trg_outbound_queue_dsn();

-- Hot staging buffer: UNLOGGED for fast client submission writes.
-- pg_cron drains this into outbound_queue every 10 seconds.
-- On crash: truncated — worst case 10 seconds of queued mail is re-submitted by clients
-- (JMAP EmailSubmission tracks submission state; client retries if no ack received).
CREATE UNLOGGED TABLE outbound_queue_hot (LIKE outbound_queue INCLUDING DEFAULTS);
ALTER TABLE outbound_queue_hot ADD PRIMARY KEY (id);

-- Message trace log: one row per delivery event per message.
CREATE TABLE message_trace (
  id              BIGSERIAL   NOT NULL,
  message_id      TEXT        NOT NULL,
  event           TEXT        NOT NULL
                    CHECK (event IN (
                      'received','delivered','bounced','deferred',
                      'spam_filtered','rule_applied','quarantined',
                      'held','archived','expired'
                    )),
  from_addr       TEXT        NOT NULL,
  rcpt_addr       TEXT        NOT NULL,
  remote_host     TEXT,
  details         JSONB,
  occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (id, occurred_at)
) PARTITION BY RANGE (occurred_at);

-- Default partition catches events until month partitions are created by pg_cron
CREATE TABLE message_trace_default PARTITION OF message_trace DEFAULT;

CREATE INDEX trace_message_id_idx ON message_trace(message_id);
CREATE INDEX trace_from_idx       ON message_trace(from_addr, occurred_at DESC);
CREATE INDEX trace_rcpt_idx       ON message_trace(rcpt_addr, occurred_at DESC);
CREATE INDEX trace_occurred_idx   ON message_trace(occurred_at DESC);
